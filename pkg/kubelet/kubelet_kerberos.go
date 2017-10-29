/*
This file contains key routines used by kubelet to obtain Kerberos objects (i.e., keytabs,
tickets, and SSL certs). Kubelet invokes makeTSMounts() function from within its GenerateRunContainerOptions()
function (which is responsinble for creating all bindmounts included in the Pod by default).
*/

package kubelet

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/util/format"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util/clock"
	lock "k8s.io/kubernetes/pkg/util/lock"
	"k8s.io/kubernetes/pkg/util/sets"
)

// makeTSMounts() obtaines and initializes Kerberos objects for the Pod.
//
// Parameters:
// - pod - Pod object for which the Kerberos objects are generated
// - podIP - IP address of the Pod
// - custeomResolvConf - flag indicating whether to also replace /etc/resolv.conf in the Pod with TS specific one
// Return:
// - an array of mount objects (one per file or directory containing Kerberos files) and error status
func (kl *Kubelet) makeTSMounts(pod *api.Pod, podIP string, customResolvConf bool) ([]kubecontainer.Mount, error) {
	// mount array to store all of the TS specific mounts that this method creates
	tsMounts := []kubecontainer.Mount{}

	// set up Kerberos ticket, if asked for and the user owning the container is known
	if tkt, ok := pod.ObjectMeta.Annotations[krbutils.TSTicketAnnotation]; ok {
		if user, ok := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]; ok {
			glog.V(5).Infof(krbutils.TSL+"delegated ticket found in pod spec for user %s: %s", user, tkt)
			tktMount, err := kl.makeTktMount(user, tkt, pod)
			if err != nil {
				glog.Errorf(krbutils.TSE+"unable to create ticket mount: %v", err)
				return nil, err
			} else {
				tsMounts = append(tsMounts, *tktMount)
			}
		}
	}

	// the function may be invoked multiple times for the same Pod (by the Kubelet)
	// ignore invocations where podIP is not yet set
	if len(podIP) == 0 {
		return tsMounts, nil
	}

	// Register in KDC under the DNS name as a singleton Pod cluster, create bind-mount for the keytab, and trigger the keytab fetch
	needKeytabs := false
	needCerts := false
	if user, ok := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]; ok {
		// check if Pod needs any keytabs (and for what services) and SSL certs
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

		// compute the list of all DNS names of KDC clusters that Pod requested to be a member of
		podKDCClusters, err := kl.GetAllPodKDCClusterNames(pod)
		if err != nil {
			glog.Errorf(krbutils.TSE+"error while getting KDC clusters for the POD %s, error: %v", pod.Name, err)
			return nil, err
		}

		// obtain keytabs, if asked for. Note that the makeKeytabMount function is still called even if only SSL certs are requested.
		// The reason is that it also performs cluster KDC registration (which is required for SSL certs even without keytabs).
		if needKeytabs || needCerts {
			glog.V(5).Infof(krbutils.TSL+"managing KDC clusters for keytabs/certs for the Pod %s user %s and services %+v",
				pod.Name, user, services)
			// create required KDC clusters and join the node to them. Also, if services != "" then request keytabs and
			// return mount object pointed at the keytab file.
			keytabMount, err := kl.makeKeytabMount(pod, services, podKDCClusters, user)
			if err != nil {
				glog.Errorf(krbutils.TSE+"unable to create keytab for Pod %s user %s and services %s: %+v",
					pod.Name, user, services, err)
				return nil, err
			} else {
				if keytabMount != nil {
					tsMounts = append(tsMounts, *keytabMount)
					glog.V(5).Infof(krbutils.TSL+"keytab for the Pod %s user %s and services %+v created",
						pod.Name, user, services)
				} else {
					glog.V(5).Infof(krbutils.TSL+"KDC clusters for the Pod %s user %s registered, but no keytab since services empty",
						pod.Name, user)
				}
			}
		}

		// obtain the SSL certificates, if required
		// Note that the KDC cluster registration has already been done in makeKeytabMount() function
		if needCerts {
			glog.V(5).Infof(krbutils.TSL+"creating SSL certs for the Pod %s and user %s", pod.Name, user)
			// obtain SSL certificates and return mount object pointing to the directory containing them
			certsMount, err := kl.makeCertMount(pod, podKDCClusters, user)
			if err != nil {
				glog.Errorf(krbutils.TSE+"unable to create SSL certs for Pod %s and user %s, error %+v", pod.Name, user, err)
				return nil, err
			} else {
				tsMounts = append(tsMounts, *certsMount)
				glog.V(5).Infof(krbutils.TSL+"created SSL certs for the Pod %s and user %s", pod.Name, user)
			}
		}
	}

	// check if Pod declares /etc/resolv.conf bindmount. If it does not, create the custom resolv.conf
	skipResolvConf := false
	for _, v := range pod.Spec.Volumes {
		if v.VolumeSource.HostPath != nil {
			if v.VolumeSource.HostPath.Path == "/etc/k8s-resolv.conf" {
				skipResolvConf = true
				glog.V(5).Infof(krbutils.TSL+"Pod declares resolv.conf, skipping the custom resolv.conf %s", pod.Name)
			}
		}
	}

	// create TS specific /etc/resolv.conf
	if customResolvConf && !skipResolvConf {
		glog.V(5).Infof(krbutils.TSL+"creating custom resolv.conf for Pod %s", pod.Name)
		resolveMount, err := kl.makeResolveMount(pod)
		if err != nil {
			glog.Errorf(krbutils.TSE+"unable to create resolve mount: %v", err)
			return nil, err
		} else {
			tsMounts = append(tsMounts, *resolveMount)
			glog.V(5).Infof(krbutils.TSL+"created custom resolv.conf for Pod %s", pod.Name)
		}
	} else {
		glog.V(5).Infof(krbutils.TSL+"not creating custom resolv.conf for Pod %s", pod.Name)
	}

	return tsMounts, nil
}

// checkFileExists() is a helper functions returning a boolean indicating if the given file exists
//
// Parameters:
// - path - path to the file to check
// Return:
// - true if exists, false otherwise, and error if can not be determined
func checkFileExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			glog.Errorf(krbutils.TSE+"checking if file %s exists failed %v", path, err)
			return false, err
		}
	} else {
		return true, nil
	}
}

// makeResolveMount() prepares a resolv.conf file based on TS networking configuration spec
//
// Parameters:
// - pod - Pod object for which the resolve file is generated
// Return:
// - a mount object pointing at the generated resolv.conf file and error status
func (kl *Kubelet) makeResolveMount(pod *api.Pod) (*kubecontainer.Mount, error) {
	resolveFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.ResolvePathForPod)
	// check if the file already exists (we need to do it only for the first container)
	exists, err := checkFileExists(resolveFilePath)
	if err != nil {
		glog.Errorf(krbutils.TSE+"checking if file exists failed %v", err)
		return nil, err
	}
	if !exists {
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_RESOLVE_MOUNT_START", "POD %s", pod.Name)
		if err := kl.createResolveFile(resolveFilePath, pod.Namespace); err != nil {
			kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_RESOLVE_MOUNT_FAILED", "POD %s , err %v", pod.Name, err)
			return nil, err
		}
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_RESOLVE_MOUNT_END", "POD %s", pod.Name)
	}
	return &kubecontainer.Mount{
		Name:          "resolv",
		ContainerPath: krbutils.ResolvePathInPod,
		HostPath:      resolveFilePath,
		ReadOnly:      false,
	}, nil
}

// createResolveFile() produces resolv.conf file according to TS network spec
//
// Parameters:
// - resolveFilePath - location on host file system to create the file at
// - podNamespace - namespace of the Pod (required to produce the DNS search path)
// Return:
// - error if failed, nil otheriwse
func (kl *Kubelet) createResolveFile(resolveFilePath, podNamespace string) error {
	var buffer bytes.Buffer
	var hostDNS []string
	var searchDomains []string
	// Get host DNS settings
	if kl.resolverConfig != "" {
		f, err := os.Open(kl.resolverConfig)
		if err != nil {
			return err
		}
		defer f.Close()

		hostDNS, searchDomains, err = kl.parseResolvConf(f)
		if err != nil {
			return err
		}

		buffer.WriteString("# Kubernetes-managed TS specific resolve.conf file.\n")
		buffer.WriteString(fmt.Sprintf("search %s.svc.%s svc.%s", podNamespace, kl.clusterDomain, kl.clusterDomain))
		for _, s := range searchDomains {
			buffer.WriteString(fmt.Sprintf(" %s", s))
		}
		buffer.WriteString(fmt.Sprintf("\n"))
		// TS mod, ignore link local dns resolvers to skip unbound
		hostDNS = krbutils.Filter(hostDNS, func(v string) bool {
			return !strings.HasPrefix(v, "127.")
		})
		for _, nameserverIP := range hostDNS {
			buffer.WriteString(fmt.Sprintf("nameserver %s\n", nameserverIP))
		}
		buffer.WriteString("options edns0 ndots:0\n")
		buffer.WriteString("options ndots:2\n")
		return ioutil.WriteFile(resolveFilePath, buffer.Bytes(), 0644)
	} else {
		glog.Errorf(krbutils.TSE + "error getting DNS servers")
		return errors.New("Could not get DNS server IPs from host resolv.conf ")
	}
}

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
				go func(apiPod *api.Pod, ch chan types.UID) {
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
func (kl *Kubelet) podUpdateKerberos(pod *api.Pod) {
	defer clock.ExecTime(time.Now(), "podUpdateKerberos", pod.Name)
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
		if pod.Status.Phase != api.PodRunning {
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
				// continue to the handler that will fix the keytabs
			} else {
				// no need to proceed, all keytabs present
				glog.V(5).Infof(krbutils.TSL+"keytab creation skipped (during Pod refresh) for clusters %+v and services %+v for POD %q",
					podAllClusters, services, format.Pod(pod))
				return
			}

			// invoke actual keytab handling function
			if err := kl.createKeytab(keytabFilePath, pod, services, podAllClusters, user, false); err != nil {
				glog.Errorf(krbutils.TSE+"error creating keytab (in refresh) for Pod %s clusters %+v services %+v, error: %v",
					pod.Name, podAllClusters, services, err)
			} else {
				glog.V(5).Infof(krbutils.TSL+"updated keytab file (during Pod refresh) for clusters %+v and services %+v for POD %q",
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
func (kl *Kubelet) getKDCClustersForAllPods(pod *api.Pod) (map[string]bool, error) {
	defer clock.ExecTime(time.Now(), "getKDCClustersForAllPods", pod.Name)
	allClusters := make(map[string]bool)
	for _, p := range kl.getActivePods() {
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
func (kl *Kubelet) GetPodServiceClusters(pod *api.Pod) (map[string]bool, error) {
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
func (kl *Kubelet) GetAllPodKDCClusterNames(pod *api.Pod) (map[string]bool, error) {
	defer clock.ExecTime(time.Now(), "GetAllPodKDCClusterNames", pod.Name)
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
func (kl *Kubelet) checkIfPodUsesKerberos(pod *api.Pod) (bool, bool, string, string) {
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
