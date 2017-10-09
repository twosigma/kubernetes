/*
This file contains routines used for managing Kerberos keytabs for pods. Keytabs are obtained
using krb5_keytab utility and then distributed to the pods. The work of getting the key material
is done on the host. Moreover, an option for generating local keytabs (for creating keytabs without
interaction with KDC) is implemented. That allows quick creation for use test cases.
The system also mainteins membership of nodes in appropriate KDC clusters to allow for getting the keytabs.

NOTE: these routines are used even if a pod does not request keytabs but requests SSL certificates. The
reason is that in such case the cluster management from here is used (without getting actual keytab material).
I.e., the required KDC clusters are created and also the membership (node joining and leaving) is maintained here
so "pwdb cert" can obtain the SSL certificates.
*/
package kubelet

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/util/clock"
	lock "k8s.io/kubernetes/pkg/util/lock"
)

// makeKeytabMount() creates keytab file on the host and obtains key material for all KDC clusters that the pod
// is a member of as well as for all services requested in the annotation.
//
// Parameters:
// - pod - pod to get keytabs for
// - services - comma separated list of services that keytabs should be obtained for
// - podKDCClusters - map containing DNS names of KDC clusters that pod is a member of
// - user - username that owns the processes in the pod
// Return:
// - mount pointing at the keytab file on the host and error, if failed
func (kl *Kubelet) makeKeytabMount(pod *api.Pod, services string, podKDCClusters map[string]bool, user string) (*kubecontainer.Mount, error) {
	if services == "" {
		return nil, nil
	}
	keytabFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.KeytabDirForPod)
	exists, err := checkFileExists(keytabFilePath)
	if err != nil {
		glog.Errorf(krbutils.TSE+"checking if file exists failed %v", err)
		return nil, err
	}
	if !exists {
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_KEYTABS_MOUNT_START", "POD %s", pod.Name)
		if err := kl.createKeytab(keytabFilePath, pod, services, podKDCClusters, user, true); err != nil {
			kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_KEYTABS_MOUNT_FAILED", "POD %s , err %v", pod.Name, err)
			return nil, err
		}
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_KEYTABS_MOUNT_END", "POD %s", pod.Name)
	}
	// return mount only if at least one service was requested. Empty services indicate user asked for certs but not for keytabs in which case
	// we manage KDC cluster membership but do not create actual keytabs and related bind mount
	return &kubecontainer.Mount{
		Name:          "ts-keytab",
		ContainerPath: krbutils.KeytabPathInPod,
		HostPath:      keytabFilePath,
		ReadOnly:      false,
	}, nil
}

// createKeytab() obtains keytabs for KDC clusters and services requested by the pod. It does that by registering the clusters in KDC,
// creating authorization files, and then obtaining the keytabs to a host file. The distribution of keytabs to pods is done in ./server/server.go
// based on a callback received form the Kerberos subsystem.
//
// Parameters:
// - dest - location to write the keytabs to
// - pod - pod for which the keytabs are being requested
// - services - comma separated list of services that keytabs are requested for
// - podKDCClusters - all KDC clusters that pod is a member of, e.g., singleton cluster related to the pod, service clusters for services
//                    selecting the pod, as well as external clusters defined using ts/externalclusters annotation
// - user - username that owns the processes running in the pod
// - force - force refresh of the keytab
//
// Return:
// - error, if failed
func (kl *Kubelet) createKeytab(dest string, pod *api.Pod, services string, podKDCClusters map[string]bool, user string, force bool) error {
	defer clock.ExecTime(time.Now(), "createKeytab", pod.Name)
	var err error
	var mutex *lock.Mutex = nil

	// special handling for pods requesting "local" keytabs - these are generated locally instead of
	// registering in KDC.
	if krbLocal, ok := pod.ObjectMeta.Annotations[krbutils.TSKrbLocal]; ok && krbLocal == "true" {
		// ts/krblocal set, doing local construction of keytab with "light" KDC interaction
		glog.V(5).Infof(krbutils.TSL+"pod %s has krblocal annotation, generating local keytab", pod.Name)
		clusterName := pod.Name + "." + pod.Namespace + "." + kl.clusterDomain
		for _, srv := range strings.Split(services, ",") {
			// request the local keytab (for domain not registered in KDC)
			// create keytab directory
			podKeytabFile := dest + "/" + user
			if err := os.MkdirAll(dest, 0755); err != nil {
				glog.Errorf("Error creating keytab directory %q for pod %s: %v", dest, err, pod.Name)
				return err
			}
			// create array of all Kerberos principals that are local to the pod (cluster keytabs can not be handled with
			// this approach. The files would have to be transfered to other systems hosting pods of the same cluster.
			podLocalPrincipals := []string{srv + "/" + clusterName}
			if tsuserprefixed, ok := pod.ObjectMeta.Annotations[krbutils.TSPrefixedHostnameAnnotation]; ok && tsuserprefixed == "true" {
				podLocalPrincipals = append(podLocalPrincipals, srv+"/"+user+"."+clusterName)
			}
			for _, principal := range podLocalPrincipals {
				if err = kl.krbManager.CreateLocalKey(podKeytabFile, principal); err != nil {
					glog.Errorf(krbutils.TSE+"error creating local keytab for principal %s during, error: %v",
						principal, err)
					return err
				} else {
					if err = kl.krbManager.ChangeFileOwnership(podKeytabFile, user, kl.krbManager.GetTicketUserGroup()); err != nil {
						return err
					}
					// add service ticket related to the keytab to the credentials cache of the Pod
					// since the keytabs created this way are not registered in KDC, we need to inject
					// service tickets for each keytab using kimpersonate. Specifically:
					tktFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.TicketDirForPod)
					if err = kl.krbManager.AddKimpersonateTicket(tktFilePath, user, kl.krbManager.GetKerberosRealm(),
						principal, podKeytabFile); err != nil {
						glog.Errorf(krbutils.TSE+"error creating ticket for local keytab for %s and %s@%s, error: %v",
							principal, user, kl.krbManager.GetKerberosRealm(), err)
						return err
					}
					glog.V(5).Infof(krbutils.TSL+"local keytabfile and ticket created for %s", principal)
				}
			}
		}
		glog.V(5).Infof(krbutils.TSL+"all local keytabs and tickets for Pod %s created", pod.Name)
		return nil
	}

	// it is a "regular" Pod - i.e., without krblocal annotation - will have full KDC registration

	// retrieve keys and versions from the host keytab file
	hostKeyVersions, _, _, err := kl.krbManager.GetKeyVersionsFromKeytab(kl.krbManager.GetHostKeytabFile())
	if err != nil {
		glog.Errorf(krbutils.TSE+"Retrieval of keytab key versions from host keytab file %s failed, error: %+v",
			kl.krbManager.GetHostKeytabFile(), err)
		return err
	}
	// retrieve keys and versions from the Pod keytab file
	podKeyVersions, _, _, err := kl.krbManager.GetKeyVersionsFromKeytab(path.Join(dest, user))
	if err != nil {
		glog.Errorf(krbutils.TSE+"Retrieval of keytab key versions from keytab file %s for Pod %s failed, error: %+v", dest, pod.Name, err)
		return err
	}

	// Refresh the actual keytab file on the node. The content relevant to this Pod will be extracted
	// and copied to the Pod directory (for bind-mount) based on krb5_keytab callback invoking
	// REST API of the kubelet at URL/refreshkeytabs.
	for clusterName, _ := range podKDCClusters {
		// optimize as not to attempt registration of service level cluster
		// many times (per each Pod selected by the service).
		// If the cluster already present in host keytab then node is already a member and no need to register.
		if inCluster, err := kl.krbManager.CheckIfHostInKDCCluster(clusterName, kl.hostname); err != nil || !inCluster {
			// was not able to get the status of KDC cluster or got it and hostName is not there - register
			if kl.kubeletConfiguration.TSLockKerberos && !kl.kubeletConfiguration.TSLockKrb5KeytabOnly && mutex == nil {
				mutex, err = lock.NewMutex(
					kl.kubeletConfiguration.TSLockEtcdServerList,
					kl.kubeletConfiguration.TSLockEtcdCertFile,
					kl.kubeletConfiguration.TSLockEtcdKeyFile,
					kl.kubeletConfiguration.TSLockEtcdCAFile)
				if err != nil {
					glog.Errorf(krbutils.TSE + "Can not create Mutex")
					return err
				}
				defer lock.Close(mutex)
			}
			//Register cluster in KDC
			if err = kl.krbManager.RegisterClusterInKDC(clusterName, kl.hostname, mutex); err != nil {
				glog.Errorf(krbutils.TSE+"error registering cluster %s in KDC, error: %+v", clusterName, err)
				return err
			}
			// Add node to the virtual cluster in KDC
			if err := kl.krbManager.AddHostToClusterInKDC(clusterName, kl.hostname, mutex); err != nil {
				glog.Errorf(krbutils.TSE+"error adding host %s to cluster %s in KDC, error: %v", kl.hostname, clusterName, err)
				return err
			}
		} else {
			glog.V(4).Infof(krbutils.TSL+"node already a member of the cluster %s, skipped registration in KDC", clusterName)
		}
		// we only request actual keytabs if the user asked for it. If no services requested then only
		// KDC cluster membership is managed for certs.
		if services != "" {
			// request refresh of the keytab
			glog.V(4).Infof(krbutils.TSL+"will refresh keytab for pod %s and cluster %s", pod.Name, clusterName)
			if err := kl.refreshKeytab(clusterName, services, hostKeyVersions, podKeyVersions, force); err != nil {
				glog.Errorf(krbutils.TSE+"error getting keytab file for cluster %s and services %+v, error: %v", clusterName, services, err)
				return err
			}
		}
	}
	// At this point, when the refresh returned sucessfully, the keytab callback has happened and the content
	// was extracted and placed into the Pod's folder. It is safe to proceed with provisioning.

	// turns out callback may fail to happen...
	// verify that the Pod got the service keytabs it asked for
	// it is additional robustness if the callback from krb5_keytab did not come
	if err := kl.verifyAndFixKeytab(pod, services, kl.hostname, podKDCClusters, dest, user, true); err != nil {
		glog.Errorf(krbutils.TSE+"failed to fix and verify keytab for Pod %s, error: %+v", pod.Name, err)
		return err
	} else {
		return nil
	}
}

// refreshKeytab() prepares authorization files and then requests keytab to be fetched to host's keytab file. The fetch
// generates callback that is handled by kubelet's server. The server distributes the keytab to pods as requested. Calls
// to krb5_keytab are serialized across the cluster using etcd based mutex.
//
// Parameters:
// - clusterName - DNS name of the cluster to get the keytab for
// - services - comma separated list of services to get keytabs for
// - hosteKeyVersions - keytab versions on the host (to avoid fetching is already present)
// - podKeyVersions - keytab versions in the pod (to avoid fetching is already present)
// - force - whether to force refresh even if the host and pod versions match
//
// Return:
// - error, if failed
func (kl *Kubelet) refreshKeytab(clusterName, services string, hostKeyVersions, podKeyVersions map[string]int, force bool) error {
	defer clock.ExecTime(time.Now(), "refreshKeytab", clusterName)
	// Pull the actual keytab for requested services to the node.
	// Services is a comma-separated list of services to include in the ticket. It is passed from
	// the manifest annotation.
	var lastOut []byte
	var retry int
	var mutex *lock.Mutex = nil
	var out []byte
	var err error

	for _, srv := range strings.Split(services, ",") {
		// check if we already have this key - and continue if we do
		principal := srv + "/" + clusterName + "@" + kl.krbManager.GetKerberosRealm()
		if _, ok := podKeyVersions[principal]; ok {
			if !force {
				glog.V(5).Infof(krbutils.TSL+"Keytab for principal %s already present, continuing", principal)
				continue
			}
		}
		// for each principal we need to create an ACL file in order to be able to request it as another user
		if err := kl.krbManager.SetupKrbACLFile(srv, clusterName); err != nil {
			glog.Errorf(krbutils.TSE+"can not create ACL file for service %s in cluster %s, error: %v", srv, clusterName, err)
			return err
		} else {
			glog.V(5).Infof(krbutils.TSL+"ACL file for service %s in cluster %s has been created", srv, clusterName)
		}
		// request the keytab refresh and retry if needed

		if kl.kubeletConfiguration.TSLockKerberos && mutex == nil {
			mutex, err = lock.NewMutex(
				kl.kubeletConfiguration.TSLockEtcdServerList,
				kl.kubeletConfiguration.TSLockEtcdCertFile,
				kl.kubeletConfiguration.TSLockEtcdKeyFile,
				kl.kubeletConfiguration.TSLockEtcdCAFile)
			if err != nil {
				glog.Errorf(krbutils.TSE + "Can not create Mutex")
				return err
			}
			defer lock.Close(mutex)
		}

		if err := kl.krbManager.RequestKey(srv, clusterName, mutex, kl.hostname); err != nil {
			glog.Errorf(krbutils.TSE+"error creating service key for service %s in cluster %s after retries, "+
				"giving up, error: %v, output: %v", srv, clusterName, err, string(lastOut))
			return err
		} else {
			glog.V(5).Infof(krbutils.TSL+"keytabfile content has been fetched for principal %s/%s "+
				"after %d retries, returned output %s with no error", srv, clusterName, retry, string(out))
		}
	}
	return nil
}

// invokePodKeytabRefresh() calls handler to refresh keytabs inside of Pods
//
// Parameters:
// - pod - pod to refresh
// - trimKeytab - boolean indicating wether to trim the keytab (remove entries not used by any pods)
//
// Return:
// - error, if failed
func (kl *Kubelet) invokePodKeytabRefresh(pod *api.Pod, trimKeytab bool) error {
	data := url.Values{}
	data.Set("keytabpath", kl.krbManager.GetHostKeytabFile())
	data.Set("trimkeytab", "false")
	if resp, err := http.Post(krbutils.KubeletRESTServiceURL, "text/plain", bytes.NewBufferString(data.Encode())); err != nil {
		glog.Errorf(krbutils.TSE+"invokePodKeytabRefresh for Pod %s failed, err: %+v", pod.Name, err)
		return err
	} else {
		if resp.StatusCode != 200 {
			glog.Errorf(krbutils.TSE+"invokePodKeytabRefresh for Pod %s failed, http server returned code %d with message %s",
				pod.Name, resp.StatusCode, resp.Status)
			return errors.New("invokePodKeytabRefresh for Pod " + pod.Name + "failed with error message from httpserver " + resp.Status)
		} else {
			glog.V(5).Infof(krbutils.TSL+"invokePodKeytabRefresh succeeded for Pod %s", pod.Name)
			return nil
		}
	}
}

// verifyAndFixKeytab() is additonal fail-safe. It will check if Pod got all of the Kerberos keytab principals it needs and will
// invoke callback REST API if it did not. The reason for this is that sometimes the security subsystem (krb5_keytab tool)
// fails to trigger callback.
//
// Parameters:
// - pod - pod to verify keytabs for
// - services - comma separated list of services to get keytabs for
// - hostname - hostname of the underlying host
// - podAllClusters - map with all DNS names of the KDC clusters that the pod is a member of
// - podDir - folder of the pod on the host
// - userName - username of teh owner of the processes in the pod
// - withFix - whether to fix or only verify
//
// Return:
// - error, if failed
func (kl *Kubelet) verifyAndFixKeytab(pod *api.Pod, services, hostname string, podAllClusters map[string]bool, podDir, userName string, withFix bool) error {
	defer clock.ExecTime(time.Now(), "verifyAndFixKeytab", pod.Name)

	if services == "" {
		glog.V(4).Infof(krbutils.TSL+"skipping verifyAndFixKeytab for pod %s since no service keytabs requested in the manifest", pod.Name)
		return nil
	}

	glog.V(4).Infof(krbutils.TSL+"starting verifyAndFixKeytab for pod %s", pod.Name)
	podKeytabPath := path.Join(podDir, userName)

	//generate cartesian product of services and cluster names that represents all Kerberos principals this Pod needs
	principals := map[string]bool{}
	for clusterName, _ := range podAllClusters {
		for _, srv := range strings.Split(services, ",") {
			principals[srv+"/"+clusterName+"@"+kl.krbManager.GetKerberosRealm()] = true
		}
	}
	glog.V(4).Infof(krbutils.TSL+"veryfing keytab for POD %s with podDir %s and principals %+v",
		pod.Name, podDir, principals)
	podKeyVersions, _, podKeyCount, err := kl.krbManager.GetKeyVersionsFromKeytab(podKeytabPath)
	if err != nil {
		glog.Errorf(krbutils.TSE+"Retrieval of keytab key versions from keytab file %s for Pod %s failed, error: %+v",
			podKeytabPath, pod.Name, err)
		return err
	}
	hostKeyVersions, _, hostKeyCount, err := kl.krbManager.GetKeyVersionsFromKeytab(kl.krbManager.GetHostKeytabFile())
	if err != nil {
		glog.Errorf(krbutils.TSE+"Retrieval of keytab key versions from host keytab file %s failed, error: %+v", podKeytabPath, err)
		return err
	}
	// check if all expected principals are in the Pod's keytab and also if the key versions in the Pod keytab match the newest
	// versions in the keytab file on the host
	missingPrincipals := map[string]bool{}
	oldKey := false
	for expectedPrincipal, _ := range principals {
		if podKeyVersion, ok := podKeyVersions[expectedPrincipal]; !ok {
			glog.Errorf(krbutils.TSE+"detected missing principal %s for pod %s", expectedPrincipal, pod.Name)
			missingPrincipals[expectedPrincipal] = true
		} else {
			if hostKeyVersion, ok := hostKeyVersions[expectedPrincipal]; !ok {
				glog.Errorf(krbutils.TSE+"detected key in Pod keytab not present in host keytab, principal %s", expectedPrincipal)

			} else if hostKeyVersion != podKeyVersion {
				glog.Errorf(krbutils.TSE+"expected principal %s for pod %s has version %d in Pod and version %d in host file, need to fix",
					expectedPrincipal, pod.Name, podKeyVersion, hostKeyVersion)
				oldKey = true
			} else if podKeyCount[expectedPrincipal] != hostKeyCount[expectedPrincipal] {
				glog.Errorf(krbutils.TSE+"expected principal %s for pod %s has %d versions in Pod and %d versions in host file, need to fix",
					expectedPrincipal, pod.Name, podKeyCount[expectedPrincipal], hostKeyCount[expectedPrincipal])
				oldKey = true
			} else {
				glog.V(5).Infof(krbutils.TSL+"expected principal %s for pod %s was found with key version %d", expectedPrincipal, pod.Name, podKeyVersion)
			}
		}
	}

	// if any requested principals are missing or key version in Pod is older than in host keytab file,
	// trigger the fix by invoking kubelet keytab distribution
	if len(missingPrincipals) > 0 || oldKey {
		glog.V(2).Infof(krbutils.TSL+"attempting to fix missing or expired (older key version) principals or trim on deletion for Pod %s", pod.Name)
		// repair by calling our callback function in the kubelet server.go thread
		// this assumes that the reason for failure is lack of callback from the security subsystem
		if withFix {
			if err := kl.invokePodKeytabRefresh(pod, false); err != nil {
				glog.Errorf(krbutils.TSE+"fixing keytab for Pod %s failed, err: %+v", pod.Name, err)
				return err
			} else {
				glog.V(5).Infof(krbutils.TSL+"fixing keytab for Pod %s succeeded", pod.Name)
			}
		} else {
			// return error indicating lack of keytabs for one of the requested services
			return errors.New("no expected keytab")
		}
	} else {
		glog.V(5).Infof(krbutils.TSL+"all required principals for Pod %s were found - no need to fix, or fixing not requested", pod.Name)
	}
	return nil
}
