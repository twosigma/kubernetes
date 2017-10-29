/*
This file contains routines related to SSL certificate management. SSL certificates
are obtained for all KDC clusters that the Pod uses (if requested using ts/certs annotation).
The system uses "pwdb cert" command to get the certificates and also to refresh them as they
are about to expire. Additionally, the handling for generation of SSL certificates for "local/fake"
mode (using local self-signed certificates) is also done here.

NOTE: this assumes that the node is already a memeber of required KDC clusters. This is done
by the keytab creation routines (even if actual keytabs are not needed, the registration is
performed there if certificates are needed).
*/
package kubelet

import (
	"path"
	"path/filepath"
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/util/clock"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
)

// makeCertMount() creates SSL certificates on teh host filesystem and returns bindmount pointing at
// the directory containing them.
//
// Parameters:
// - pod - pod that the SSL certs are for
// - podKDCClusters - map containing DNS names of all KDC clusters that the pod is a member of
// - user - username of the pod's processes owner
// Return:
// - mount pointing to the directory on the host containing the SSL certs for the pod, error if failed
func (kl *Kubelet) makeCertMount(pod *api.Pod, podKDCClusters map[string]bool, user string) (*kubecontainer.Mount, error) {
	var areCertsValid bool
	var errValidate error
	certsFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.CertsDirForPod)
	exists, err := checkFileExists(certsFilePath)
	if err != nil {
		glog.Errorf(krbutils.TSE+"checking if file exists failed %v", err)
		return nil, err
	}
	// check if all 3 cert files exist
	if exists {
		if areCertsValid, errValidate = kl.validateCerts(certsFilePath, podKDCClusters); errValidate != nil {
			glog.Errorf(krbutils.TSE+"validation of SSL certs failed %v", err)
			return nil, err
		}
	} else {
		areCertsValid = false
	}
	if !areCertsValid {
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_CERTS_MOUNT_START", "POD %s", pod.Name)
		if err := kl.createCerts(certsFilePath, pod, podKDCClusters, user); err != nil {
			kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_CERTS_MOUNT_FAILED", "POD %s , err %v", pod.Name, err)
			return nil, err
		}
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_CERTS_MOUNT_END", "POD %s", pod.Name)
	}
	return &kubecontainer.Mount{
		Name:          "ts-certs",
		ContainerPath: krbutils.CertsPathInPod + "/" + user,
		HostPath:      certsFilePath,
		ReadOnly:      false,
	}, nil
}

// validateCerts() checks if all 3 SSL cert files (no extension, .key, and .p12) exist
//
// Parameters:
// - certsFilePath - path to the directory containing the certs
// - podKDCClusters - map with DNS names of the expected KDC clusters that should have certs
//
// Return:
// - true, if all files exist and false is some missing and error, if check could not be done
func (kl *Kubelet) validateCerts(certsFilePath string, podKDCClusters map[string]bool) (bool, error) {
	for cluster, _ := range podKDCClusters {
		// check no extension file
		certPath := certsFilePath + "/" + cluster
		exists, err := checkFileExists(certPath)
		if err != nil {
			return false, err
		} else if !exists {
			glog.Errorf(krbutils.TSE+"validation of SSL certs failed - %s missing", certPath)
			return false, nil
		}

		// check .key extension file
		certPath = certsFilePath + "/" + cluster + ".key"
		exists, err = checkFileExists(certPath)
		if err != nil {
			return false, err
		} else if !exists {
			glog.Errorf(krbutils.TSE+"validation of SSL certs failed - %s missing", certPath)
			return false, nil
		}

		// check .p12 extension file
		certPath = certsFilePath + "/" + cluster + ".p12"
		exists, err = checkFileExists(certPath)
		if err != nil {
			return false, err
		} else if !exists {
			glog.Errorf(krbutils.TSE+"validation of SSL certs failed - %s missing", certPath)
			return false, nil
		}
	}
	return true, nil
}

// createCerts() requests SSL certificates using "pwdb cert" command and places them in the directory dest/user
// on the host.
//
// Parameters:
// - dest - directory on the host to deposit the SSL certificate files in (deposited in dest/user)
// - pod - pod for which the certificates are requested
// - podKDCClusters - map containing DNS names of all KDC clusters that the pod is a member of
// - user - username of the pod's processes owner
// Return:
// - error, if failed
func (kl *Kubelet) createCerts(dest string, pod *api.Pod, podKDCClusters map[string]bool, user string) error {
	defer clock.ExecTime(time.Now(), "createCerts", pod.Name)

	// for the local kerberos option, the SSL certificates are generated locally without cluster registration in KDC
	// This is accomplished using openssl generator (via calling krb script on the host)
	if krbLocal, ok := pod.ObjectMeta.Annotations[krbutils.TSKrbLocal]; ok && krbLocal == "true" {
		// ts/krblocal set, doing local construction of certs (self-signed)
		glog.V(5).Infof(krbutils.TSL+"pod %s has krblocal annotation, generating local certs", pod.Name)
		clusterName := pod.Name + "." + pod.Namespace + "." + kl.clusterDomain
		// request the local certs (for domain not registered in KDC)
		podLocalClusters := []string{clusterName}
		if tsuserprefixed, ok := pod.ObjectMeta.Annotations[krbutils.TSPrefixedHostnameAnnotation]; ok && tsuserprefixed == "true" {
			podLocalClusters = append(podLocalClusters, user+"."+clusterName)
		}
		for _, localCluster := range podLocalClusters {
			if err := kl.krbManager.GetSelfSignedSSLCert(localCluster); err != nil {
				glog.Errorf(krbutils.TSE+"error creating local certs for cluster %s, error: %v, output: %v",
					localCluster, err)
				return err
			} else {
				// copy certs to the Pod's directory
				if err := kl.copyCertsToPod(krbutils.HostSelfSignedCertsFile, dest, localCluster, user, false, pod); err != nil {
					glog.Errorf(krbutils.TSE+"unable to copy certs in directory %s to %s: %s %v",
						krbutils.HostSelfSignedCertsFile, dest, err)
					return err
				} else {
					glog.V(5).Infof(krbutils.TSL+"cert for cluster %s in Pod %s created", localCluster, pod.Name)
				}
			}
		}
		glog.V(5).Infof(krbutils.TSL+"all local certs for Pod %s created", pod.Name)
		return nil
	}

	// for standard pwdb cert certificates invoke regular certificate refresh function
	// refresh the actual certs file on the node
	for clusterName, _ := range podKDCClusters {
		// request creation of the certificate
		if err := kl.refreshCerts(clusterName, dest, user, pod); err != nil {
			glog.Errorf(krbutils.TSE+"error getting certs files for cluster %s, error: %v", clusterName, err)
			return err
		} else {
			glog.V(5).Infof(krbutils.TSL+"certificate refreshed for pod %s and cluster %s", pod.Name, clusterName)
		}
	}
	return nil
}

// refreshCerts() pulls the actual certs for requested cluster to the node and deposits in the certsDir directory
// which is bind-mounted to Pods
//
// Parameters:
// - clusterName - name of the cluster that the pod belongs to that cert is needed for
// - certsDir - host directory where the cert files should be deposited
// - user - username of the pod's processes owner
// Return:
// - error, if failed
func (kl *Kubelet) refreshCerts(clusterName, certsDir, user string, pod *api.Pod) error {
	defer clock.ExecTime(time.Now(), "refreshCerts", clusterName)

	// check if the certs are already present and fresh (on the node)
	// we can not retry here since exit status of 1 is a normal condition
	// indicating expired certificate
	if err := kl.krbManager.GetPwdbSSLCert(clusterName); err != nil {
		return err
	}
	// copy certs to the Pod's directory
	if err := kl.copyCertsToPod(kl.krbManager.GetHostCertsFile(), certsDir, clusterName, user, false, pod); err != nil {
		glog.Errorf(krbutils.TSE+"unable to copy certs in directory %s to %s: %s %v", kl.krbManager.GetHostCertsFile(), certsDir, err)
		return err
	} else {
		glog.V(5).Infof(krbutils.TSL+"all cert files have been copied to Pod's directory %s for cluster %s", certsDir, clusterName)
		return nil
	}
}

// removeOriginalCerts() removes certificate files from teh host directory
//
// Parameters:
// - hostDir - folder with the certificate files
// - clusterName - name of the cluster to remove
// Return:
// - none since we only log on failure (do not fail the pod)
func removeOriginalCerts(hostDir, clusterName string) {
	// create the Pod directory
	exe := utilexec.New()
	cmd := exe.Command(
		"rm",
		"-f",
		hostDir+"/"+clusterName+"*")
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Errorf(krbutils.TSE+"unable to remove certs in directory %s: %s %v", hostDir, out, err)
	}
}

// copyCertsToPod() copies the SSL certificates from the host to pod's directory
//
// Parameters:
// - hostDir - directory on the host to copy from
// - clusterName - name of the KDC cluster to copy files for
// - removeOriginal - boolean indicating whether the original files should be removed
// Return:
// - error, if failed
func (kl *Kubelet) copyCertsToPod(hostDir, certsDir, clusterName, user string, removeOriginal bool, pod *api.Pod) error {
	if removeOriginal {
		defer removeOriginalCerts(hostDir, clusterName)
	}

	// create the Pod directory
	exe := utilexec.New()
	cmd := exe.Command(
		"mkdir",
		"-p",
		certsDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Errorf(krbutils.TSE+"unable to create Pod certs directory: %s %v", out, err)
	}

	// copy the files to the Pod certs directory
	if certFiles, err := filepath.Glob(hostDir + "/" + clusterName + "*"); err != nil {
		glog.Errorf(krbutils.TSE+"error listing cert files for cluster %s, error: %v", clusterName, err)
		return err
	} else {
		for _, certFile := range certFiles {
			glog.V(5).Infof(krbutils.TSL+"copying cert file %s to Pod's directory %s for cluster %s", certFile, certsDir, clusterName)
			if out, err := krbutils.RunCommand("/bin/cp", "-f", certFile, certsDir); err != nil {
				glog.Errorf(krbutils.TSE+"error copying cert file %s to Pod's directory %s for cluster %s, error: %v, output: %s",
					certFile, clusterName, certsDir, err, string(out))
				return err
			} else {
				glog.V(5).Infof(krbutils.TSL+"cert file %s have been copied to Pod's directory %s for cluster %s", certFile,
					certsDir, clusterName)
			}
			certFileInPod := certsDir + "/" + filepath.Base(certFile)

			// update file access rights and owner
			if err1 := kl.krbManager.ChangeFileOwnership(certFileInPod, user, kl.krbManager.GetTicketUserGroup()); err1 != nil {
				return err1
			}
		}
		return nil
	}
}
