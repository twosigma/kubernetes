/*
This file contains routines used by kubelet to obtain Kerberos tickets. makeTktMount() function
is invoked from makeTSMounts() and is responsible for creating a Kerberos ticket bindmount
inside of the pod. Moreover, the ticket refresh (accomplished via getting periodic pod manifest updates
from the apiserver) is also implemented here. In both cases the ticket is encrypted on the master node
and then decrypted on the worker node (using host key). Additionally, the handling for generation of tickets
for "local/fake" keytabs during ticket refresh is also here.
*/

package kubelet

import (
	"errors"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
)

// makeTktMount() gets the ticket (from the manifest of the pod), decrypts it using host's key, and
// deposits the decrypted ticket in pod's filesystem. It also creates mount object.
//
// Paramaters:
// - userName - username of the owner of the pod's processes
// - tkt - encrypted ticket
// - pod - pod object that the ticket is for
//
// Return:
// - mount pointing at the location of the decrypted ticket on host filesystem and error, if failed
func (kl *Kubelet) makeTktMount(userName, tkt string, pod *api.Pod) (*kubecontainer.Mount, error) {
	tktFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.TicketDirForPod)
	// skip tkt decoding if the file already exists, which means the pod is restarted rather than created
	// if the ticket is attempted to be decoded again, the decoding can fail since the ticket can be
	// encoded only within specific (configurable) time - this is configured at Kerberos layer on the hosts
	if _, err := os.Stat(tktFilePath); os.IsNotExist(err) {
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_TICKET_MOUNT_START", "POD %s", pod.Name)
		if err := kl.krbManager.DecryptTicket(tktFilePath, tkt, userName, kl.krbManager.GetTicketUserGroup(), pod); err != nil {
			kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_TICKET_MOUNT_FAILED", "POD %s , error %s", pod.Name, err.Error())
			return nil, err
		}
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_TICKET_MOUNT_END", "POD %s", pod.Name)
	} else if err != nil {
		glog.Errorf(krbutils.TSE+"checking if ticket file exists failed, err %v", err)
		return nil, err
	}
	return &kubecontainer.Mount{
		Name:          "ts-tkt",
		ContainerPath: path.Join(krbutils.TicketDirInPod, userName),
		HostPath:      tktFilePath,
		ReadOnly:      false,
	}, nil
}

// refreshTSTkt() refreshes the TS Kerberos ticket by decoding it using host's key
// and updating the content of the ticket file mounted into the container.
// We decode the ticket into a tempfile (instead of directly to the mounted file)
// to preserve the inode (so the container does not need to be restarted).
// Moreover, for Pods with local keytabs we also need to refresh the kimpersonator
// generated ticket (which is in the same credentials cache as the main tgt ticket)
//
// Parameters:
// - pod - pod object that the ticket is for
// - user - username of the owner of the pod's processes (and the ticket file)
// - tkt - encrypted ticket to decode
//
// Return:
// - none - ticket refresh, if failed, will be logged and is monitored for, but
//          will *not* invalidate the pod. It is desired behavior since in case of
//          failure of the refresh the ticket can still be repaired and the pod preserved
func (kl *Kubelet) refreshTSTkt(pod *api.Pod, user, tkt string) error {
	tktFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.TicketDirForPod)
	if _, err := os.Stat(tktFilePath); err == nil {
		file, err := ioutil.TempFile(os.TempDir(), "k8s-token")
		if err != nil {
			glog.Errorf(krbutils.TSE+"failed to create temp file: %v", err)
			return err
		} else {
			tmpFile := file.Name()
			defer os.Remove(tmpFile)
			// decode the ticket into a temporary file
			if err := kl.krbManager.DecryptTicket(tmpFile, tkt, user, kl.krbManager.GetTicketUserGroup(), pod); err != nil {
				glog.Errorf(krbutils.TSE+"unable to decode the ticket for pod %s/%s, err %v", pod.Namespace, pod.Name, err)
				return err
			} else {
				// for Pods with local keytabs we also need to refresh the kimpersonator generated ticket
				// (which is in the same credentials cache as the main tgt ticket)
				// Note that local keytabs (and therefore related tickets that are generated here) are
				// only available for the KDC singleton clusters local to the pod (not distributed).
				// Future extension option: The support for the cluster keytabs can be added by copying
				// the keytab file (not sensitive) to other nodes.
				if krbLocal, ok := pod.ObjectMeta.Annotations[krbutils.TSKrbLocal]; ok && krbLocal == "true" {
					// ts/krblocal set, doing local construction of keytab with no KDC interaction
					glog.V(5).Infof(krbutils.TSL+"pod %s/%s has krblocal annotation, refreshing tickets for local keytabs",
						pod.Namespace, pod.Name)
					podKeytabFile := path.Join(kl.getPodDir(pod.UID), krbutils.KeytabDirForPod) + "/" + user
					if services, ok := pod.ObjectMeta.Annotations[krbutils.TSServicesAnnotation]; ok && services != "" {
						for _, srv := range strings.Split(services, ",") {
							clusterName := pod.Name + "." + pod.Namespace + "." + kl.clusterDomain
							podLocalPrincipals := []string{srv + "/" + clusterName}
							if tsuserprefixed, ok := pod.ObjectMeta.Annotations[krbutils.TSPrefixedHostnameAnnotation]; ok &&
								tsuserprefixed == "true" {
								podLocalPrincipals = append(podLocalPrincipals, srv+"/"+user+"."+clusterName)
							}
							for _, principal := range podLocalPrincipals {
								if err := kl.krbManager.AddKimpersonateTicket(tmpFile, user,
									kl.krbManager.GetKerberosRealm(), principal, podKeytabFile); err != nil {
									glog.Errorf(krbutils.TSE+
										"error refreshing ticket for local keytab %s and %s@%s, error: %v",
										principal, user, kl.krbManager.GetKerberosRealm(), err)
									return err
								}
							}
						}
					}
					glog.V(5).Infof(krbutils.TSL+"all local tickets refreshed for pod %s/%s", pod.Namespace, pod.Name)
				}
				// copy the refreshed ticket to the pod's directory
				// this operation preserves the inode therefore the pod bindmount is not broken
				if err := krbutils.CopyFile(tmpFile, tktFilePath); err != nil {
					glog.Errorf(krbutils.TSE+"unable to copy the refreshed ticket for %s/%s at %s, error %v",
						pod.Namespace, pod.Name, tktFilePath, err)
					return err
				} else {
					glog.V(2).Infof(krbutils.TSL+"ticket has been refreshed for %s/%s at %s", pod.Namespace, pod.Name, tktFilePath)
				}
			}
		}
	} else if os.IsNotExist(err) {
		glog.Errorf(krbutils.TSE+"ticket file does not exist at %s", tktFilePath)
		return errors.New(krbutils.TSE + "ticket file does not exist at " + tktFilePath)
	} else {
		glog.Errorf(krbutils.TSE+"unable to check if the TS ticket file exists: %v", err)
		return err
	}
	return nil
}
