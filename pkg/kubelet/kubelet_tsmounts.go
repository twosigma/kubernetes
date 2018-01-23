/*
This file contains routine used by kubelet to create TS custom bindmounts in pods
*/

package kubelet

import (
	"os"

	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
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
