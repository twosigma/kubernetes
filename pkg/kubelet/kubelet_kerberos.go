/*
This file contains key routines used by kubelet to obtain Kerberos objects (i.e., keytabs,
tickets, and SSL certs). Kubelet invokes makeTSMounts() function from within its GenerateRunContainerOptions()
function (which is responsinble for creating all bindmounts included in the Pod by default).
*/

package kubelet

import (
	"path"
	"time"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	"k8s.io/kubernetes/pkg/kubelet/util/format"
	lock "k8s.io/kubernetes/pkg/util/lock"
)

// podKerberosManager() launches a goroutine to update Pod's Kerberos objects based on desired state.
// It takes the tasks from kl.podKerberosCh channel. The tasks are inserted into the channel by
// kubelet's Pod lifecycle event handlers (HandlePodCleanups() and HandlePodUpdates() in kubelet_pods.go
// and kubelet.go, respectively). The desired state includes both Pod level and service level KDC clusters.
// It is started from kubelet's main Run() loop.
// The manager keeps track of lifecycle operations being handled and prevents duplication of actions
// due to slower execution. It also parallelizes the lifecycle event handling by spanning goroutines and therefore
// avoids locking up kubelet main thread even if external Kerberos subsystem is slow.
//
// Parameters:
// - none
// Return:
// - none - does not return
func (kl *Kubelet) podKerberosManager() {
	// sets of refresh or deletion requests that are being handled to avoid queuing up
	// lifecycle operations for the same Pod
	inProgressDelete := sets.NewString()
	inProgressRefresh := sets.NewString()
	// result channels for the subroutines to report on
	resultChDelete := make(chan types.UID)
	resultChRefresh := make(chan types.UID)
	resultCh := make(chan types.UID)
	defer close(resultChDelete)
	defer close(resultChRefresh)
	for {
		select {
		case podUpdateMessage, ok := <-kl.podKerberosCh:
			if ok {
				apiPod := podUpdateMessage.APIPod
				// do not do anything with Pods with local Kerberos since no KDC registration has happened for them
				// and no refresh is required
				if krbLocal, ok := apiPod.ObjectMeta.Annotations[krbutils.TSKrbLocal]; ok && krbLocal == "true" {
					continue
				}
				// check what type of request it is and ignore if already in progress
				if apiPod.DeletionTimestamp != nil {
					if inProgressDelete.Has(string(apiPod.ObjectMeta.UID)) {
						break
					} else {
						inProgressDelete.Insert(string(apiPod.ObjectMeta.UID))
						resultCh = resultChDelete
					}
				} else {
					if inProgressRefresh.Has(string(apiPod.ObjectMeta.UID)) {
						break
					} else {
						inProgressRefresh.Insert(string(apiPod.ObjectMeta.UID))
						resultCh = resultChRefresh
					}
				}
				// fulfill the actual request
				go func(apiPod *v1.Pod, ch chan types.UID) {
					defer func() {
						ch <- apiPod.ObjectMeta.UID
					}()
					kl.podUpdateKerberos(apiPod)
				}(apiPod, resultCh)
			} else {
				glog.Errorf(krbutils.TSE + "error reading from podKerberosCh")
			}

		case podID, ok := <-resultChDelete:
			if ok {
				inProgressDelete.Delete(string(podID))
			} else {
				glog.Errorf(krbutils.TSE + "error reading from resultChDelete")
			}

		case podID, ok := <-resultChRefresh:
			if ok {
				inProgressRefresh.Delete(string(podID))
			} else {
				glog.Errorf(krbutils.TSE + "error reading from resultChRefresh")
			}
		}
	}
}

// podUpdateKerberos() refreshes Kerberos objects inside of the Pod based on current desired state.
// Specifically:
// - for a pod that is being deleted, it removes the node on which the Pod runs from all KDC clusters
//   that the pod belongs to. NOTE: it does not remove the clusters themselves from KDC since this is
//   an restricted operation that kubelet's ticket is not entitled to execute. The work with the SEC ENG
//   team has to be done to enable KDC cluster cleanup.
// - for a pod that is not being deleted, the method refreshes the Kerberos objects. It checks all of the
//   KDC clusters that the pod belongs to and verifies that the keytabs contained in the pod's keytab file
//   match the desired (requested) service keytabs for all KDC clusters that pod is a memebr of. Note that
//   if a new service starts selecting the pod then the Kerberos state for it is added to the Pod by this
//   method. As a result, user can add services to existing pods and get them auto-cnfigured. For SSL certs,
//   refresh function is invoked that checks if the cert is about to expire, and if it is, refreshes it.
// Morover, all operations against KDC invoked by this method are serialized using queue on etcd cluster.
// This is done to reduce load on the KDCs.
func (kl *Kubelet) podUpdateKerberos(pod *v1.Pod) {
	defer lock.ExecTime(time.Now(), "podUpdateKerberos", pod.Name)
	var err error
	var mutex *lock.Mutex = nil

	needKeytabs, needCerts, user, services := kl.checkIfPodUsesKerberos(pod)
	if !needCerts && !needKeytabs {
		// nothing to do for this Pod since it does not use Kerberos
		return
	}

	// get all of the Kerberos clusters the Pod is a member of
	podAllClusters, err := kl.GetAllPodKDCClusterNames(pod)
	if err != nil {
		glog.Errorf(krbutils.TSE+"error while getting service clusters for the POD %s during update, error: %v",
			pod.Name, err)
	}

	// check if it is delete or update
	if pod.DeletionTimestamp != nil {
		glog.V(5).Infof(krbutils.TSL+"deleting Kerberos objects for Pod %s", pod.Name)

		// get clusters for all other active Pods on this node
		nodeAllClusters, err := kl.getKDCClustersForAllPods(pod)
		if err != nil {
			glog.Errorf(krbutils.TSE+"error while getting service clusters for the PODs on the node during delete of Pod %s, error: %v",
				pod.Name, err)
		}

		// if locking is requested (runtime parameter of the kubelet) then obtain lock prior to KDC operations
		if kl.kubeletConfiguration.TSLockKerberos && !kl.kubeletConfiguration.TSLockKrb5KeytabOnly && mutex == nil {
			mutex, err = lock.NewMutex(
				kl.kubeletConfiguration.TSLockEtcdServerList,
				kl.kubeletConfiguration.TSLockEtcdCertFile,
				kl.kubeletConfiguration.TSLockEtcdKeyFile,
				kl.kubeletConfiguration.TSLockEtcdCAFile)
			if err != nil {
				glog.Errorf(krbutils.TSE + "Can not create Mutex")
			} else {
				defer lock.Close(mutex)
			}
		}

		// Remove the node from the KDC clusters of the Pod. No removal of actual singleton cluster
		// is done since the krb5_* software suite does not provide for that at the moment. The cleanup
		// aspect should be revisited since a large number of empty singleton clusters can build up in KDC.
		for podClusterName, _ := range podAllClusters {
			// Check if other existing Pods are members of this cluster.
			// We can not remove the node from such cluster.
			if nodeAllClusters[podClusterName] {
				continue
			}
			if err := kl.krbManager.RemoveHostFromClusterInKDC(podClusterName, kl.hostname, mutex); err != nil {
				glog.Errorf(krbutils.TSL+"Failed to remove host %s from KDC clusters %+v for pod %q during Pod update for delete, err: %v",
					kl.hostname, podAllClusters, format.Pod(pod), err)
			} else {
				glog.V(5).Infof(krbutils.TSL+"Removed host %s from KDC clusters %+v for pod %q during Pod update for delete",
					kl.hostname, podAllClusters, format.Pod(pod))
			}
		}
	} else {
		// if the Pod is not yet running we should not do steady-state management of its Kerberos state
		if pod.Status.Phase != v1.PodRunning {
			glog.V(5).Infof(krbutils.TSL+"pod %s of user %s is not running (state %v ) - not doing Kerberos management",
				pod.Name, user, pod.Status.Phase)
			return
		} else {
			glog.V(5).Infof(krbutils.TSL+"will update Kerberos keytabs and certs for Pod %s and user %s", pod.Name, user)
		}

		// do the Kerberos steady-state management (service level keytab management)

		// only manage KDC cluster if Pod requests either keytabs or certs. In addition to KDC cluster
		// management, createKeytab function will request actual keytab entries if services != "". In case
		// when services == "", only cluster membership is managed (for certs)
		if needKeytabs || needCerts {
			keytabFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.KeytabDirForPod)

			if err := kl.verifyAndFixKeytab(pod, services, kl.hostname, podAllClusters,
				keytabFilePath, user, false); err != nil {
				glog.Errorf(krbutils.TSE+"failed to verify keytab for Pod %s in podUpdate handler, error: %+v", pod.Name, err)

				// invoke actual keytab handling function to fix the keytab
				if err := kl.createKeytab(keytabFilePath, pod, services, podAllClusters, user, false); err != nil {
					glog.Errorf(krbutils.TSE+"error creating keytab (in refresh) for Pod %s clusters %+v services %+v, error: %v",
						pod.Name, podAllClusters, services, err)
				} else {
					glog.V(5).Infof(krbutils.TSL+"updated keytab file (during Pod refresh) for clusters %+v and services %+v for POD %q",
						podAllClusters, services, format.Pod(pod))
				}

			} else {
				// no need to proceed, all keytabs present
				glog.V(5).Infof(krbutils.TSL+"keytab creation skipped (during Pod refresh) for clusters %+v and services %+v for POD %q",
					podAllClusters, services, format.Pod(pod))
			}
		}
		// refresh certificates, if pod requests them
		if needCerts {
			// create certs
			certsFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.CertsDirForPod)
			if err := kl.createCerts(certsFilePath, pod, podAllClusters, user); err != nil {
				glog.Errorf(krbutils.TSE+"error creating certs (in update) for Pod %s clusters %+v, error: %v",
					pod.Name, podAllClusters, err)
			} else {
				glog.V(5).Infof(krbutils.TSL+"updated certs file (during Pod refresh) for clusters %+v for POD %q",
					podAllClusters, format.Pod(pod))
			}
		}
	}
}

// getKDCClustersForAllPods() computes the list of all KDC clusters of all Pods on this
// node except for Pod pod (passed as an argument). The purpose of this function is to
// allow for removal of the node from KDC clusters that pod is a member of only if there are
// no other pods on this node that are also members of one of those clusters.
//
// Paramaters:
// - pod - pod for which clusters should be excluded (only clusters that pods other than this one
//   that are co-hosted on the same node use
// Return:
// - map of DNS names of the KDC clusters that pods other than the argument pod on the same node use,
//   and error if failed
func (kl *Kubelet) getKDCClustersForAllPods(pod *v1.Pod) (map[string]bool, error) {
	defer lock.ExecTime(time.Now(), "getKDCClustersForAllPods", pod.Name)
	allClusters := make(map[string]bool)
	for _, p := range kl.GetActivePods() {
		if p.ObjectMeta.UID == pod.ObjectMeta.UID {
			// skip the Pod we are removing - no need to check for it
			continue
		}
		needKeytabs, needCerts, _, _ := kl.checkIfPodUsesKerberos(p)
		if !needKeytabs && !needCerts {
			// not a member of any Kerberos clusters, skip
			continue
		}
		if tmpClusters, err := kl.GetAllPodKDCClusterNames(p); err != nil {
			glog.Errorf(krbutils.TSE+"error while getting service clusters for the POD %s during update, error: %v",
				p.Name, err)
			return nil, err
		} else {
			for k, v := range tmpClusters {
				allClusters[k] = v
			}
		}
	}
	glog.V(4).Infof(krbutils.TSL+"all clusters of Pods on the node (except for %s) while verifying node removal are %v", pod.Name, allClusters)
	return allClusters, nil
}

// GetPodServiceClusters() builds a list of service-level clusters that the Pod is a member of. This is done
// by checking which services have selectors matching labels on the Pod.
//
// Parameter:
// - pod - pod object that the service clusters should be obtained for
// Return:
// - map of DNS names of KDC clusters related to services selecting the pod and error, if failed
func (kl *Kubelet) GetPodServiceClusters(pod *v1.Pod) (map[string]bool, error) {
	podLabels := pod.Labels
	if services, err := kl.serviceLister.List(labels.Everything()); err != nil {
		glog.Errorf(krbutils.TSE+"error listing Pod's services for keytab creation for Pod %s: %v", pod.Name, err)
		return nil, err
	} else {
		// services is of type api.ServiceList
		// filter for services selecting this POD
		// TODO: Check if there is a simpler way of finding services selecting a Pod.
		serviceClusters := make(map[string]bool)
		for i := range services {
			service := services[i]
			// HOT patch - need to fix the filter above
			if service.Namespace != pod.Namespace {
				continue
			}
			serviceCluster := service.Name + "." + service.Namespace + ".svc." + kl.clusterDomain
			isMember := false
			for selKey, selVal := range service.Spec.Selector {
				if labelVal := podLabels[selKey]; labelVal == selVal {
					isMember = true
					break
				}
			}

			// TODO: need to handle manually defined endpoints (for services with no selectors)
			// serviceEndpoints, err := xx?.GetServiceEndpoints(service)
			if isMember {
				serviceClusters[serviceCluster] = true
			}
		}
		glog.V(5).Infof(krbutils.TSL+"services selecting Pod %s are %v", pod.Name, serviceClusters)
		return serviceClusters, nil
	}
}

// GetAllPodKDCClusterNames() returns a map with DNS names of all KDC clusters that the pod is a memebr of.
// These include:
// - singleton cluster of the pod itself
// - clusters related to all services selecting the pod
// - external clusters defined using ts/externalclusters annotation
//
// Parameters:
// - pod - a pod to retrieve clusters for
// Return:
// - map of DNS names of all clusters and error, if failed
func (kl *Kubelet) GetAllPodKDCClusterNames(pod *v1.Pod) (map[string]bool, error) {
	defer lock.ExecTime(time.Now(), "GetAllPodKDCClusterNames", pod.Name)
	if allPodKDCClusters, err := krbutils.GetPodKDCClusterNames(pod, kl.clusterDomain); err != nil {
		glog.Errorf(krbutils.TSE+"error while getting Pod clusters for the POD %s during update, error: %v",
			pod.Name, err)
		return nil, err
	} else if podServiceClusters, err1 := kl.GetPodServiceClusters(pod); err1 != nil {
		glog.Errorf(krbutils.TSE+"error while getting service clusters for the POD %s during update, error: %v",
			pod.Name, err1)
		return nil, err1
	} else {
		for k, v := range podServiceClusters {
			allPodKDCClusters[k] = v
		}
		return allPodKDCClusters, nil
	}
}

// checkIfPodUsesKerberos() checks whether a given pod has annotations that request Kerberos keytabs or SSL certs.
// Pod has to have runasuser defined in order to be able to ask for any Kerberos objects.
//
// Paramaters:
// - pod - pod object to check
// Return:
// - quadruple of ( needKeytabs, needCerts, user, services ). The first two elements are booleans
//   indicating whether the pod requires keytabs and SLL certificates. The third is the user that
//   runs the pod (related to PID of the processes in the pod). Finally, the fourth element is
//   a comma separated list of services to include in keytab file (or empty string if none are requested).
//   The last comes directly from the user provided manifest annotation.
func (kl *Kubelet) checkIfPodUsesKerberos(pod *v1.Pod) (bool, bool, string, string) {
	needKeytabs := false
	needCerts := false

	// check if any Kerberos management is required
	user, ok := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]
	if !ok {
		// no ts/runasuser set, nothing to do
		return false, false, "", ""
	}

	services, ok := pod.ObjectMeta.Annotations[krbutils.TSServicesAnnotation]
	if ok && services != "" {
		needKeytabs = true
	} else {
		services = ""
	}

	doCerts, ok := pod.ObjectMeta.Annotations[krbutils.TSCertsAnnotation]
	if ok && doCerts == "true" {
		needCerts = true
	}
	return needKeytabs, needCerts, user, services
}
