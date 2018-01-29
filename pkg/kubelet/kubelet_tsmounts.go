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

	// the function may be invoked multiple times for the same Pod (by the Kubelet)
	// ignore invocations where podIP is not yet set
	if len(podIP) == 0 {
		return tsMounts, nil
	}

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
