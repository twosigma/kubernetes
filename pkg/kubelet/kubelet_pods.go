/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubelet

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	utilpod "k8s.io/kubernetes/pkg/api/pod"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/api/validation"
	"k8s.io/kubernetes/pkg/fieldpath"
	"k8s.io/kubernetes/pkg/kubelet/cm"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/envvars"
	"k8s.io/kubernetes/pkg/kubelet/images"
	"k8s.io/kubernetes/pkg/kubelet/server/remotecommand"
	"k8s.io/kubernetes/pkg/kubelet/status"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
	"k8s.io/kubernetes/pkg/kubelet/util/format"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util/clock"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
	krbutils "k8s.io/kubernetes/pkg/util/kerberos"
	lock "k8s.io/kubernetes/pkg/util/lock"
	"k8s.io/kubernetes/pkg/util/sets"
	"k8s.io/kubernetes/pkg/util/term"
	utilvalidation "k8s.io/kubernetes/pkg/util/validation"
	"k8s.io/kubernetes/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util/volumehelper"
	"k8s.io/kubernetes/third_party/forked/golang/expansion"
)

// Get a list of pods that have data directories.
func (kl *Kubelet) listPodsFromDisk() ([]types.UID, error) {
	podInfos, err := ioutil.ReadDir(kl.getPodsDir())
	if err != nil {
		return nil, err
	}
	pods := []types.UID{}
	for i := range podInfos {
		if podInfos[i].IsDir() {
			pods = append(pods, types.UID(podInfos[i].Name()))
		}
	}
	return pods, nil
}

// getActivePods returns non-terminal pods
func (kl *Kubelet) getActivePods() []*api.Pod {
	allPods := kl.podManager.GetPods()
	activePods := kl.filterOutTerminatedPods(allPods)
	return activePods
}

// makeDevices determines the devices for the given container.
// Experimental. For now, we hardcode /dev/nvidia0 no matter what the user asks for
// (we only support one device per node).
// TODO: add support for more than 1 GPU after #28216.
func makeDevices(container *api.Container) []kubecontainer.DeviceInfo {
	nvidiaGPULimit := container.Resources.Limits.NvidiaGPU()
	if nvidiaGPULimit.Value() != 0 {
		return []kubecontainer.DeviceInfo{
			{PathOnHost: "/dev/nvidia0", PathInContainer: "/dev/nvidia0", Permissions: "mrw"},
			{PathOnHost: "/dev/nvidiactl", PathInContainer: "/dev/nvidiactl", Permissions: "mrw"},
			{PathOnHost: "/dev/nvidia-uvm", PathInContainer: "/dev/nvidia-uvm", Permissions: "mrw"},
		}
	}

	return nil
}

// makeMounts determines the mount points for the given container.
func makeMounts(pod *api.Pod, podDir string, container *api.Container, hostName, hostDomain, podIP string, podVolumes kubecontainer.VolumeMap) ([]kubecontainer.Mount, error) {
	// Kubernetes only mounts on /etc/hosts if :
	// - container does not use hostNetwork and
	// - container is not an infrastructure(pause) container
	// - container is not already mounting on /etc/hosts
	// When the pause container is being created, its IP is still unknown. Hence, PodIP will not have been set.
	// OS is not Windows
	mountEtcHostsFile := (pod.Spec.SecurityContext == nil || !pod.Spec.SecurityContext.HostNetwork) && len(podIP) > 0 && runtime.GOOS != "windows"
	glog.V(3).Infof("container: %v/%v/%v podIP: %q creating hosts mount: %v", pod.Namespace, pod.Name, container.Name, podIP, mountEtcHostsFile)
	mounts := []kubecontainer.Mount{}
	for _, mount := range container.VolumeMounts {
		mountEtcHostsFile = mountEtcHostsFile && (mount.MountPath != etcHostsPath)
		vol, ok := podVolumes[mount.Name]
		if !ok {
			glog.Warningf("Mount cannot be satisfied for container %q, because the volume is missing: %q", container.Name, mount)
			continue
		}

		relabelVolume := false
		// If the volume supports SELinux and it has not been
		// relabeled already and it is not a read-only volume,
		// relabel it and mark it as labeled
		if vol.Mounter.GetAttributes().Managed && vol.Mounter.GetAttributes().SupportsSELinux && !vol.SELinuxLabeled {
			vol.SELinuxLabeled = true
			relabelVolume = true
		}
		hostPath, err := volume.GetPath(vol.Mounter)
		if err != nil {
			return nil, err
		}
		if mount.SubPath != "" {
			hostPath = filepath.Join(hostPath, mount.SubPath)
		}

		// Docker Volume Mounts fail on Windows if it is not of the form C:/
		containerPath := mount.MountPath
		if runtime.GOOS == "windows" {
			if strings.HasPrefix(hostPath, "/") && !strings.Contains(hostPath, ":") {
				hostPath = "c:" + hostPath
			}
			if strings.HasPrefix(containerPath, "/") && !strings.Contains(containerPath, ":") {
				containerPath = "c:" + containerPath
			}
		}

		mounts = append(mounts, kubecontainer.Mount{
			Name:           mount.Name,
			ContainerPath:  containerPath,
			HostPath:       hostPath,
			ReadOnly:       mount.ReadOnly,
			SELinuxRelabel: relabelVolume,
		})
	}
	if mountEtcHostsFile {
		// check if pod has prefixed hostname annotation
		prefix := ""
		if tsuserprefixedhostname, ok := pod.ObjectMeta.Annotations[krbutils.TSPrefixedHostnameAnnotation]; ok && tsuserprefixedhostname == "true" {
			if runAsUsername, ok1 := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]; ok1 {
				prefix = runAsUsername
			}
		}
		hostsMount, err := makeHostsMount(podDir, podIP, hostName, hostDomain, prefix)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, *hostsMount)
	}

	return mounts, nil
}

func (kl *Kubelet) makeTSMounts(pod *api.Pod, podDir string, podIP string, clusterDomain, nodeHostname string, customResolvConf bool) ([]kubecontainer.Mount, error) {
	tsMounts := []kubecontainer.Mount{}

	// Set up Kerberos ticket
	if tkt, ok := pod.ObjectMeta.Annotations[krbutils.TSTicketAnnotation]; ok {
		if user, ok := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]; ok {
			glog.V(5).Infof(krbutils.TSL+"delegated ticket found in pod spec for user %s: %s", user, tkt)
			tktMount, err := kl.makeTktMount(podDir, user, tkt, pod)
			if err != nil {
				glog.Errorf(krbutils.TSE+"unable to create ticket mount: %v", err)
				return nil, err
			} else {
				tsMounts = append(tsMounts, *tktMount)
			}
		}
	}

	if len(podIP) == 0 {
		return tsMounts, nil
	}

	// Register in KDC under the DNS name as a singleton Pod cluster, create bind-mount for the keytab, and trigger the keytab fetch
	realm := krbutils.KerberosRealm
	needKeytabs := false
	needCerts := false
	if user, ok := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]; ok {
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

		podKDCClusters, err := kl.GetAllPodKDCClusterNames(pod)
		if err != nil {
			glog.Errorf(krbutils.TSE+"error while getting KDC clusters for the POD %s, error: %v", pod.Name, err)
			return nil, err
		}

		if needKeytabs || needCerts {
			// create required KDC clusters and join the node to them. Also, if services != "" then request keytabs and
			// create bind mount for keytab file.
			glog.V(5).Infof(krbutils.TSL+"managing KDC clusters for keytabs/certs for the Pod %s user %s and services %+v", pod.Name, user, services)
			tktMount, err := kl.makeKeytabMount(podDir, clusterDomain, pod, services, nodeHostname, realm, podKDCClusters, user)
			if err != nil {
				glog.Errorf(krbutils.TSE+"unable to create keytab for Pod %s user %s and services %s: %+v", pod.Name, user, services, err)
				return nil, err
			} else {
				if tktMount != nil {
					tsMounts = append(tsMounts, *tktMount)
					glog.V(5).Infof(krbutils.TSL+"keytab for the Pod %s user %s and services %+v created", pod.Name, user, services)
				} else {
					glog.V(5).Infof(krbutils.TSL+"KDC clusters for the Pod %s user %s created, but no keytab since services empty", pod.Name, user)
				}
			}
		}

		if needCerts {
			// create certificates
			glog.V(5).Infof(krbutils.TSL+"creating certs for the Pod %s and user %s", pod.Name, user)
			certsMount, err := kl.makeCertMount(podDir, clusterDomain, pod, nodeHostname, realm,
				podKDCClusters, user)
			if err != nil {
				glog.Errorf(krbutils.TSE+"unable to create certs for Pod %s and user %s, error %+v", pod.Name, user, err)
				return nil, err
			} else {
				tsMounts = append(tsMounts, *certsMount)
				glog.V(5).Infof(krbutils.TSL+"created certs for the Pod %s and user %s", pod.Name, user)
			}
		}
	}

	// check if Pod declares /etc/resolv.conf bindmount. If it does not, create the custom resolv.conf
	// TODO: this should be removed after all manifests are corrected (/etc/resolv.conf mounts removed)
	skipResolvConf := false
	for _, v := range pod.Spec.Volumes {
		if v.VolumeSource.HostPath != nil {
			if v.VolumeSource.HostPath.Path == "/etc/k8s-resolv.conf" {
				skipResolvConf = true
				glog.V(5).Infof(krbutils.TSL+"Pod declares resolv.conf, skipping the custom resolv.conf %s", pod.Name)
			}
		}
	}

	if customResolvConf && !skipResolvConf {
		// create custom TS resolve conf
		glog.V(5).Infof(krbutils.TSL+"creating custom resolv.conf for Pod %s", pod.Name)
		resolveMount, err := kl.makeResolveMount(podDir, pod.Namespace, clusterDomain, pod)
		if err != nil {
			glog.Errorf(krbutils.TSE+"unable to create resolve mount: %v", err)
			return nil, err
		} else {
			tsMounts = append(tsMounts, *resolveMount)
		}
	} else {
		glog.V(5).Infof(krbutils.TSL+"not creating custom resolv.conf for Pod %s", pod.Name)
	}

	return tsMounts, nil
}

func checkFileExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}

func (kl *Kubelet) makeResolveMount(podDir, podNamespace, clusterDomain string, pod *api.Pod) (*kubecontainer.Mount, error) {
	resolveFilePath := path.Join(podDir, krbutils.ResolvePathForPod)
	// check if the file already exists (we need to do it only for the first container)
	exists, err := checkFileExists(resolveFilePath)
	if err != nil {
		glog.Errorf(krbutils.TSE+"checking if file exists failed %v", err)
		return nil, err
	}
	if !exists {
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_RESOLVE_MOUNT_START", "POD %s", pod.Name)
		if err := kl.createResolveFile(resolveFilePath, podNamespace, clusterDomain); err != nil {
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

func (kl *Kubelet) createResolveFile(resolveFilePath, podNamespace, clusterDomain string) error {
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
		buffer.WriteString(fmt.Sprintf("search %s.svc.%s svc.%s", podNamespace, clusterDomain, clusterDomain))
		for _, s := range searchDomains {
			buffer.WriteString(fmt.Sprintf(" %s", s))
		}
		buffer.WriteString(fmt.Sprintf("\n"))
		// TS mod, ignore link local dns resolvers to skip unbound
		hostDNS = Filter(hostDNS, func(v string) bool {
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

func (kl *Kubelet) makeCertMount(podDir, clusterDomain string, pod *api.Pod, hostName, realm string, podKDCClusters map[string]bool, user string) (*kubecontainer.Mount, error) {
	certsFilePath := path.Join(podDir, krbutils.CertsDirForPod)
	exists, err := checkFileExists(certsFilePath)
	if err != nil {
		glog.Errorf(krbutils.TSE+"checking if file exists failed %v", err)
		return nil, err
	}
	if !exists {
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_CERTS_MOUNT_START", "POD %s", pod.Name)
		if err := createCerts(certsFilePath, clusterDomain, pod, hostName, realm, podKDCClusters, user); err != nil {
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

func createCerts(dest, clusterDomain string, pod *api.Pod, hostName, realm string, podKDCClusters map[string]bool, user string) error {
	defer clock.ExecTime(time.Now(), "createCerts", pod.Name)

	if krbLocal, ok := pod.ObjectMeta.Annotations[krbutils.TSKrbLocal]; ok && krbLocal == "true" {
		// ts/krblocal set, doing local construction of certs (self-signed)
		glog.V(5).Infof(krbutils.TSL+"pod %s has krblocal annotation, generating local certs", pod.Name)
		clusterName := pod.Name + "." + pod.Namespace + "." + clusterDomain
		// request the local certs (for domain not registered in KDC)
		out, err := krbutils.RunCommand(krbutils.LocalCertGeneratorPath, clusterName, krbutils.HostSelfSignedCertsFile)
		if err != nil {
			glog.Errorf(krbutils.TSE+"error creating local certs for cluster %s, error: %v, output: %v", clusterName, err, string(out))
			return err
		} else {
			// copy certs to the Pod's directory
			if err := copyCertsToPod(krbutils.HostSelfSignedCertsFile, dest, clusterName, user, false); err != nil {
				glog.Errorf(krbutils.TSE+"unable to copy certs in directory %s to %s: %s %v", krbutils.HostSelfSignedCertsFile,
					dest, err)
			} else {
				glog.V(5).Infof(krbutils.TSL+"all local certs for Pod %s created", pod.Name)
				return nil
			}
		}
	}

	// refresh the actual certs file on the node
	for clusterName, _ := range podKDCClusters {
		// request creation of the certificate
		if err := refreshCerts(clusterName, dest, user); err != nil {
			glog.Errorf(krbutils.TSE+"error getting certs files for cluster %s, error: %v", clusterName, err)
			return err
		} else {
			glog.V(5).Infof(krbutils.TSL+"certificate refreshed for pod %s and cluster %s", pod.Name, clusterName)
		}
	}
	return nil
}

// Pull the actual certs for requested cluster to the node.
func refreshCerts(clusterName, certsDir, user string) error {
	defer clock.ExecTime(time.Now(), "refreshCerts", clusterName)

	var lastErr error
	var lastOut []byte
	var retry int

	// check if the certs are already present and fresh (on the node)
	// we can not retry here since exit status of 1 is a normal condition
	// indicating expired certificate
	// TODO: check if we can change pwdb output to differentiate between expired cert and other error
	if out, err := krbutils.RunCommand(krbutils.PwdbPath, "cert", "-e", "-h", clusterName); err != nil {
		glog.V(1).Infof(krbutils.TSL+"certificate files for cluster %s is expired (or other error happened), error: %v, output: %v",
			clusterName, err, string(out))
		// request the certs file refresh and retry if needed
		for retry = 0; retry < krbutils.MaxKrb5RetryCount; retry++ {
			if out, err := krbutils.RunCommand(krbutils.PwdbPath, "cert", "-h", clusterName); err != nil {
				lastErr = err
				lastOut = out
				glog.V(2).Infof(krbutils.TSL+"TSRETRY error creating certificate files for cluster %s during %d retry, error: %v, output: %v",
					clusterName, retry, err, string(out))
				time.Sleep(krbutils.Krb5RetrySleepSec)
			} else {
				glog.V(5).Infof(krbutils.TSL+"certs have been fetched for cluster %s after %d retries, returned output %s with no error",
					clusterName, retry, string(out))
				break
			}
			if retry >= krbutils.MaxKrb5RetryCount {
				glog.Errorf(krbutils.TSE+"error creating certificate files for cluster %s after %d retries, giving up, error: %v, output: %v",
					clusterName, retry, lastErr, string(lastOut))
				return lastErr
			}
		}
		// TODO: mark the Pod indicating that certs were refreshed
		// this can be used to restart the Pod or notify the user
	} else {
		glog.V(5).Infof(krbutils.TSL+"certificate files for cluster %s are fresh, no need to refresh, returned output %s with no error",
			clusterName, string(out))
	}

	// copy certs to the Pod's directory
	if err := copyCertsToPod(krbutils.HostCertsFile, certsDir, clusterName, user, false); err != nil {
		glog.Errorf(krbutils.TSE+"unable to copy certs in directory %s to %s: %s %v", krbutils.HostCertsFile, certsDir, err)
		return err
	} else {
		glog.V(5).Infof(krbutils.TSL+"all cert files have been copied to Pod's directory %s for cluster %s", certsDir, clusterName)
		return nil
	}
}

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

func copyCertsToPod(hostDir, certsDir, clusterName, user string, removeOriginal bool) error {
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
			err1 := os.Chmod(certFileInPod, 0600)
			if err1 != nil {
				glog.Errorf(krbutils.TSE+"error changing cert file %s permission to 0600, error: %v", certFileInPod, err1)
				return err1
			}
			owner := user + ":" + krbutils.TicketUserGroup
			cmd = exe.Command(krbutils.ChownPath, owner, certFileInPod)
			_, err1 = cmd.CombinedOutput()
			if err1 != nil {
				glog.Errorf(krbutils.TSE+"error changing owner of cert file %s to %s, error: %v", certFileInPod, owner, err1)
				return err1
			}
		}
		return nil
	}
}

func (kl *Kubelet) makeKeytabMount(podDir, clusterDomain string, pod *api.Pod, services string, hostName, realm string, podKDCClusters map[string]bool, user string) (*kubecontainer.Mount, error) {
	if services == "" {
		return nil, nil
	}
	keytabFilePath := path.Join(podDir, krbutils.KeytabDirForPod)
	exists, err := checkFileExists(keytabFilePath)
	if err != nil {
		glog.Errorf(krbutils.TSE+"checking if file exists failed %v", err)
		return nil, err
	}
	if !exists {
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_KEYTABS_MOUNT_START", "POD %s", pod.Name)
		if err := kl.createKeytab(keytabFilePath, clusterDomain, pod, services, hostName, realm, podKDCClusters, user, true); err != nil {
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

func changeFileOwnership(podKeytabFile, user string, pod *api.Pod) error {
	err := os.Chmod(podKeytabFile, 0600)
	if err != nil {
		glog.Errorf(krbutils.TSE+"error changing keytab file %s permission to 0600 for pod %s, error: %v", podKeytabFile, pod.Name, err)
		return err
	}
	owner := user + ":" + krbutils.TicketUserGroup
	exe := utilexec.New()
	cmd := exe.Command(krbutils.ChownPath, owner, podKeytabFile)
	if _, err = cmd.CombinedOutput(); err != nil {
		glog.Errorf(krbutils.TSE+"error changing owner to %v, error: %v", owner, err)
		return err
	}
	return nil
}

func (kl *Kubelet) createKeytab(dest, clusterDomain string, pod *api.Pod, services string, hostName, realm string, podKDCClusters map[string]bool, user string, force bool) error {
	defer clock.ExecTime(time.Now(), "createKeytab", pod.Name)
	var err error
	var out []byte
	var mutex *lock.Mutex = nil

	if krbLocal, ok := pod.ObjectMeta.Annotations[krbutils.TSKrbLocal]; ok && krbLocal == "true" {
		// ts/krblocal set, doing local construction of keytab with "light" KDC interaction
		glog.V(5).Infof(krbutils.TSL+"pod %s has krblocal annotation, generating local keytab", pod.Name)
		clusterName := pod.Name + "." + pod.Namespace + "." + clusterDomain
		for _, srv := range strings.Split(services, ",") {
			// request the local keytab (for domain not registered
			// create keytab directory
			podKeytabFile := dest + "/" + user
			if err := os.MkdirAll(dest, 0755); err != nil {
				glog.Errorf("Error creating keytab directory %q for pod %s: %v", dest, err, pod.Name)
				return err
			}
			out, err = krbutils.RunCommand(krbutils.HeimdalKtutilPath, "-k", podKeytabFile, "add", "-re",
				"aes128-cts", "-V", "2", "-p", srv+"/"+clusterName)
			if err != nil {
				glog.Errorf(krbutils.TSE+"error creating local keytab for service %s in cluster %s during, error: %v, output: %v",
					srv, clusterName, err, string(out))
				return err
			} else {
				if err = changeFileOwnership(podKeytabFile, user, pod); err != nil {
					return err
				}
				// add service ticket related to the keytab to the credentials cache of the Pod
				tktFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.TicketDirForPod)
				out, err = krbutils.RunCommandWithEnv([]string{"KRB5_CCNAME=" + tktFilePath}, krbutils.KImpersonatePath, "-A", "-c",
					user+"@"+realm, "-s", srv+"/"+clusterName+"@", "-t", "aes128-stc", "-k", dest)
				if err != nil {
					glog.Errorf(krbutils.TSE+"error creating ticket for local keytab for %s/%s and %s@%s, error: %v, output: %v",
						srv, clusterName, user, realm, err, string(out))
					return err
				}
				glog.V(5).Infof(krbutils.TSL+"local keytabfile and ticket created for %s/%s, returned output %s with no error",
					srv, clusterName, string(out))
			}
		}
		glog.V(5).Infof(krbutils.TSL+"all local keytabs and tickets for  Pod %s created", pod.Name)
		return nil
	}

	// it is a "regular" Pod - i.e., without krblocal annotation - will have full KDC registration

	// retrieve keys and versions from the host keytab file
	hostKeyVersions, _, _, err := getKeyVersionsFromKeytab(krbutils.HostKeytabFile)
	if err != nil {
		glog.Errorf(krbutils.TSE+"Retrieval of keytab key versions from host keytab file %s failed, error: %+v", krbutils.HostKeytabFile, err)
		return err
	}
	// retrieve keys and versions from the Pod keytab file
	podKeyVersions, _, _, err := getKeyVersionsFromKeytab(path.Join(dest, user))
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
		if inCluster, err := krbutils.CheckIfHostInInKDCCluster(clusterName, hostName); err != nil || !inCluster {
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
			if err = krbutils.RegisterClusterInKDC(clusterName, hostName, mutex); err != nil {
				glog.Errorf(krbutils.TSE+"error registering cluster %s in KDC, error: %+v", clusterName, err)
				return err
			}
			// Add node to the virtual cluster in KDC
			if err := krbutils.AddHostToClusterInKDC(clusterName, hostName, mutex); err != nil {
				glog.Errorf(krbutils.TSE+"error adding host %s to cluster %s in KDC, error: %v", hostName, clusterName, err)
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
			if err := kl.refreshKeytab(clusterName, services, realm, hostKeyVersions, podKeyVersions, force); err != nil {
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
	if err := verifyAndFixKeytab(pod, services, hostName, realm, podKDCClusters, dest, user, true); err != nil {
		glog.Errorf(krbutils.TSE+"failed to fix and verify keytab for Pod %s, error: %+v", pod.Name, err)
		return err
	} else {
		return nil
	}
}

// retrieve Kerberos key versions present in the keytab file
func getKeyVersionsFromKeytab(keytabFilePath string) (map[string]int, map[string]bool, map[string]int, error) {
	keyVersions := map[string]int{}
	clusterNames := map[string]bool{}
	keyCount := map[string]int{}
	// check if the file exists and, if it does not, return an empty map
	if _, err := os.Stat(keytabFilePath); err != nil {
		if os.IsNotExist(err) {
			return keyVersions, clusterNames, keyCount, nil
		} else {
			return nil, nil, nil, err
		}
	}
	// list all entries in the keytab file
	outb, errb, err := krbutils.ExecWithPipe("printf", krbutils.KtutilPath, []string{"rkt " + keytabFilePath + "\nlist\nq\n"}, []string{})
	if err != nil {
		glog.Errorf(krbutils.TSE+"exec with pipe failed, error %v", err)
		return nil, nil, nil, err
	}
	if errb.Len() > 0 {
		glog.Errorf(krbutils.TSE+"unable to list keys in keytab file %s, output %s, error %s", keytabFilePath, outb.String(), errb.String())
		return nil, nil, nil, errors.New(outb.String() + " " + errb.String())
	}
	re := regexp.MustCompile("  +")
	keyArray := strings.Split(string(re.ReplaceAll(bytes.TrimSpace(outb.Bytes()), []byte(" "))), "\n")

	for c := len(keyArray) - 1; c >= 0; c-- {
		key := strings.Trim(keyArray[c], " ")
		// skip header outputed by the ktutil
		if c < 4 {
			continue
		}
		items := strings.Split(key, " ")
		// skip irrelevant parts of the klist output
		if len(items) != 3 {
			continue
		}
		if keyVersion, err := strconv.Atoi(items[1]); err != nil {
			glog.Errorf(krbutils.TSE+"could not convert key version %s to integer, error: %+v", items[1], err)
		} else {
			if existingKeyVersion, ok := keyVersions[items[2]]; ok {
				if keyVersion > existingKeyVersion {
					keyVersions[items[2]] = keyVersion
				}
			} else {
				keyVersions[items[2]] = keyVersion
			}
			if existingKeyCount, ok := keyCount[items[2]]; ok {
				keyCount[items[2]] = existingKeyCount + 1
			} else {
				keyCount[items[2]] = 1
			}

			// extract cluster name
			clusterName := strings.Split(strings.Split(items[2], "/")[1], "@")[0]
			clusterNames[clusterName] = true
		}
	}
	return keyVersions, clusterNames, keyCount, nil
}

func (kl *Kubelet) refreshKeytab(clusterName, services, realm string, hostKeyVersions, podKeyVersions map[string]int, force bool) error {
	defer clock.ExecTime(time.Now(), "refreshKeytab", clusterName)
	// Pull the actual keytab for requested services to the node.
	// Services is a comma-separated list of services to include in the ticket. It is passed from
	// the manifest annotation.
	var lastErr error
	var lastOut []byte
	var retry int
	var mutex *lock.Mutex = nil
	var err error
	var l *lock.Lock
	var out []byte

	for _, srv := range strings.Split(services, ",") {
		// check if we already have this key - and continue if we do
		principal := srv + "/" + clusterName + "@" + realm
		if _, ok := podKeyVersions[principal]; ok {
			if !force {
				glog.V(5).Infof(krbutils.TSL+"Keytab for principal %s already present, continuing", principal)
				continue
			}
		}
		// for each principal we need to create an ACL file in order to be able to request it as another user
		data := []byte(krbutils.KeytabOwner + " " + realm + " " + srv + " " + clusterName)
		if err := ioutil.WriteFile(krbutils.Krb5keytabAclDir+srv+"-"+clusterName, data, 0664); err != nil {
			glog.Errorf(krbutils.TSE+"can not create ACL file for service %s in cluster %s, error: %v", srv, clusterName, err)
			return err
		} else {
			glog.V(5).Infof(krbutils.TSL+"ACL file for service %s in cluster %s has been created", srv, clusterName)
		}
		// request the keytab refresh and retry if needed
		for retry = 0; retry < krbutils.MaxKrb5RetryCount; retry++ {

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

			if kl.kubeletConfiguration.TSLockKerberos {
				l, err = mutex.Acquire(krbutils.EtcdGlobalFolder, "krb5_keytab "+kl.hostname+" "+principal, krbutils.EtcdTTL)
				if err != nil {
					glog.Errorf(krbutils.TSE+"error obtaining lock while getting key for service %s in cluster %s during %d retry, error: %v",
						srv, clusterName, retry, err)
					if l != nil {
						l.Release()
					}
					return err
				}
			}
			out, err = krbutils.RunCommand(krbutils.Krb5keytabPath, "-p", krbutils.KeytabOwner, srv+"/"+clusterName)
			if kl.kubeletConfiguration.TSLockKerberos {
				if l != nil {
					l.Release()
				}
			}
			if err != nil {
				lastErr = err
				lastOut = out
				glog.V(2).Infof(krbutils.TSL+"TSRETRY error creating service key for service %s in cluster %s during %d retry, error: %v, output: %v",
					srv, clusterName, retry, err, string(out))
				time.Sleep(krbutils.Krb5RetrySleepSec)
			} else {
				glog.V(5).Infof(krbutils.TSL+"keytabfile content has been fetched for principal %s/%s after %d retries, returned output %s with no error",
					srv, clusterName, retry, string(out))
				break
			}
		}
		if retry >= krbutils.MaxKrb5RetryCount {
			glog.Errorf(krbutils.TSE+"error creating service key for service %s in cluster %s after %d retries, giving up, error: %v, output: %v",
				srv, clusterName, retry, lastErr, string(lastOut))
			return lastErr
		}
	}
	return nil
}

// call handler to refresh keytabs inside of Pods
func invokePodKeytabRefresh(pod *api.Pod, trimKeytab bool) error {
	data := url.Values{}
	data.Set("keytabpath", krbutils.HostKeytabFile)
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

// This function is additonal fail-safe. It will check if Pod got all of the Kerberos keytab principals it needs and will
// invoke callback REST API if it did not. The reason for this is that sometimes the security subsystem (krb5_keytab tool)
// fails to trigger callback.
func verifyAndFixKeytab(pod *api.Pod, services, hostname, realm string, podAllClusters map[string]bool, podDir, userName string, withFix bool) error {
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
			principals[srv+"/"+clusterName+"@"+realm] = true
		}
	}
	glog.V(4).Infof(krbutils.TSL+"veryfing keytab for POD %s with podDir %s and principals %+v",
		pod.Name, podDir, principals)
	podKeyVersions, _, podKeyCount, err := getKeyVersionsFromKeytab(podKeytabPath)
	if err != nil {
		glog.Errorf(krbutils.TSE+"Retrieval of keytab key versions from keytab file %s for Pod %s failed, error: %+v", podKeytabPath, pod.Name, err)
		return err
	}
	hostKeyVersions, _, hostKeyCount, err := getKeyVersionsFromKeytab(krbutils.HostKeytabFile)
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
			if err := invokePodKeytabRefresh(pod, false); err != nil {
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

func (kl *Kubelet) makeTktMount(podDir, userName, tkt string, pod *api.Pod) (*kubecontainer.Mount, error) {
	tktFilePath := path.Join(podDir, krbutils.TicketDirForPod)
	// skip tkt decode if the file already exists, which means the pod is restarted rather than created
	if _, err := os.Stat(tktFilePath); os.IsNotExist(err) {
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_TICKET_MOUNT_START", "POD %s", pod.Name)
		if err := decodeTicket(tktFilePath, tkt, userName, krbutils.TicketUserGroup); err != nil {
			kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_TICKET_MOUNT_FAILED", "POD %s , err %v", pod.Name, err)
			return nil, err
		}
		kl.recorder.Eventf(pod, api.EventTypeNormal, "MAKE_TICKET_MOUNT_END", "POD %s", pod.Name)
	} else if err != nil {
		// something else went wrong
		return nil, err
	}
	return &kubecontainer.Mount{
		Name:          "ts-tkt",
		ContainerPath: path.Join(krbutils.TicketDirInPod, userName),
		HostPath:      tktFilePath,
		ReadOnly:      false,
	}, nil
}

func decodeTicket(dest, data, user, group string) error {
	exe := utilexec.New()
	cmd := exe.Command(krbutils.GsstokenPath, "-r", "-C", dest)
	env := "KRB5_KTNAME=" + krbutils.HostKeytabFile
	env1 := "KRB5_CONFIG=" + krbutils.KRB5ConfFile
	cmd.SetEnv([]string{env, env1})
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	io.Copy(stdin, bytes.NewBufferString(data))
	stdin.Close()
	out, err1 := cmd.CombinedOutput()
	if err1 != nil {
		glog.Errorf(krbutils.TSE+"error decoding ticket, error: %v, output: %v", err1, string(out))
		return err1
	}
	err1 = os.Chmod(dest, 0600)
	if err1 != nil {
		glog.Errorf(krbutils.TSE+"error changing tkt file permission to 0600, error: %v", err1)
		return err1
	}
	owner := user + ":" + group
	cmd = exe.Command(krbutils.ChownPath, owner, dest)
	_, err1 = cmd.CombinedOutput()
	if err1 != nil {
		glog.Errorf(krbutils.TSE+"error changing owner to %v, error: %v", owner, err1)
		return err1
	}
	return nil
}

// makeHostsMount makes the mountpoint for the hosts file that the containers
// in a pod are injected with.
func makeHostsMount(podDir, podIP, hostName, hostDomainName, prefix string) (*kubecontainer.Mount, error) {
	hostsFilePath := path.Join(podDir, "etc-hosts")
	if err := ensureHostsFile(hostsFilePath, podIP, hostName, hostDomainName, prefix); err != nil {
		return nil, err
	}
	return &kubecontainer.Mount{
		Name:           "k8s-managed-etc-hosts",
		ContainerPath:  etcHostsPath,
		HostPath:       hostsFilePath,
		ReadOnly:       false,
		SELinuxRelabel: true,
	}, nil
}

// ensureHostsFile ensures that the given host file has an up-to-date ip, host
// name, and domain name.
func ensureHostsFile(fileName, hostIP, hostName, hostDomainName, prefix string) error {
	if _, err := os.Stat(fileName); os.IsExist(err) {
		glog.V(4).Infof("kubernetes-managed etc-hosts file exits. Will not be recreated: %q", fileName)
		return nil
	}
	var buffer bytes.Buffer
	buffer.WriteString("# Kubernetes-managed hosts file.\n")
	buffer.WriteString("127.0.0.1\tlocalhost\n")                      // ipv4 localhost
	buffer.WriteString("::1\tlocalhost ip6-localhost ip6-loopback\n") // ipv6 localhost
	buffer.WriteString("fe00::0\tip6-localnet\n")
	buffer.WriteString("fe00::0\tip6-mcastprefix\n")
	buffer.WriteString("fe00::1\tip6-allnodes\n")
	buffer.WriteString("fe00::2\tip6-allrouters\n")
	if len(hostDomainName) > 0 {
		if prefix == "" {
			buffer.WriteString(fmt.Sprintf("%s\t%s.%s\t%s\n", hostIP, hostName, hostDomainName, hostName))
		} else {
			buffer.WriteString(fmt.Sprintf("%s\t%s.%s.%s\t%s.%s\t%s\n",
				hostIP, prefix, hostName, hostDomainName, hostName, hostDomainName, hostName))
		}
	} else {
		buffer.WriteString(fmt.Sprintf("%s\t%s\n", hostIP, hostName))
	}
	return ioutil.WriteFile(fileName, buffer.Bytes(), 0644)
}

func makePortMappings(container *api.Container) (ports []kubecontainer.PortMapping) {
	names := make(map[string]struct{})
	for _, p := range container.Ports {
		pm := kubecontainer.PortMapping{
			HostPort:      int(p.HostPort),
			ContainerPort: int(p.ContainerPort),
			Protocol:      p.Protocol,
			HostIP:        p.HostIP,
		}

		// We need to create some default port name if it's not specified, since
		// this is necessary for rkt.
		// http://issue.k8s.io/7710
		if p.Name == "" {
			pm.Name = fmt.Sprintf("%s-%s:%d", container.Name, p.Protocol, p.ContainerPort)
		} else {
			pm.Name = fmt.Sprintf("%s-%s", container.Name, p.Name)
		}

		// Protect against exposing the same protocol-port more than once in a container.
		if _, ok := names[pm.Name]; ok {
			glog.Warningf("Port name conflicted, %q is defined more than once", pm.Name)
			continue
		}
		ports = append(ports, pm)
		names[pm.Name] = struct{}{}
	}
	return
}

// truncatePodHostnameIfNeeded truncates the pod hostname if it's longer than 63 chars.
func truncatePodHostnameIfNeeded(podName, hostname string) (string, error) {
	// Cap hostname at 63 chars (specification is 64bytes which is 63 chars and the null terminating char).
	const hostnameMaxLen = 63
	if len(hostname) <= hostnameMaxLen {
		return hostname, nil
	}
	truncated := hostname[:hostnameMaxLen]
	glog.Errorf("hostname for pod:%q was longer than %d. Truncated hostname to :%q", podName, hostnameMaxLen, truncated)
	// hostname should not end with '-' or '.'
	truncated = strings.TrimRight(truncated, "-.")
	if len(truncated) == 0 {
		// This should never happen.
		return "", fmt.Errorf("hostname for pod %q was invalid: %q", podName, hostname)
	}
	return truncated, nil
}

const hostnameMaxLen = 63

// GeneratePodHostNameAndDomain creates a hostname and domain name for a pod,
// given that pod's spec and annotations or returns an error.
func (kl *Kubelet) GeneratePodHostNameAndDomain(pod *api.Pod) (string, string, error) {
	// TODO(vmarmol): Handle better.
	clusterDomain := kl.clusterDomain
	podAnnotations := pod.Annotations
	if podAnnotations == nil {
		podAnnotations = make(map[string]string)
	}
	hostname := pod.Name
	if len(pod.Spec.Hostname) > 0 {
		if msgs := utilvalidation.IsDNS1123Label(pod.Spec.Hostname); len(msgs) != 0 {
			return "", "", fmt.Errorf("Pod Hostname %q is not a valid DNS label: %s", pod.Spec.Hostname, strings.Join(msgs, ";"))
		}
		hostname = pod.Spec.Hostname
	} else {
		hostnameCandidate := podAnnotations[utilpod.PodHostnameAnnotation]
		if len(utilvalidation.IsDNS1123Label(hostnameCandidate)) == 0 {
			// use hostname annotation, if specified.
			hostname = hostnameCandidate
		}
	}
	hostname, err := truncatePodHostnameIfNeeded(pod.Name, hostname)
	if err != nil {
		return "", "", err
	}

	hostDomain := ""
	if len(pod.Spec.Subdomain) > 0 {
		if msgs := utilvalidation.IsDNS1123Label(pod.Spec.Subdomain); len(msgs) != 0 {
			return "", "", fmt.Errorf("Pod Subdomain %q is not a valid DNS label: %s", pod.Spec.Subdomain, strings.Join(msgs, ";"))
		}
		hostDomain = fmt.Sprintf("%s.%s.svc.%s", pod.Spec.Subdomain, pod.Namespace, clusterDomain)
	} else {
		subdomainCandidate := pod.Annotations[utilpod.PodSubdomainAnnotation]
		if len(utilvalidation.IsDNS1123Label(subdomainCandidate)) == 0 {
			hostDomain = fmt.Sprintf("%s.%s.svc.%s", subdomainCandidate, pod.Namespace, clusterDomain)
		}
	}
	// override the hostDomain of the Pod to match the name <pod.Name>.<namespace>.pods.<cluster>
	hostDomain = krbutils.GetPodDomainName(pod, clusterDomain)
	return hostname, hostDomain, nil
}

// GenerateRunContainerOptions generates the RunContainerOptions, which can be used by
// the container runtime to set parameters for launching a container.
func (kl *Kubelet) GenerateRunContainerOptions(pod *api.Pod, container *api.Container, podIP string) (*kubecontainer.RunContainerOptions, error) {
	var err error
	pcm := kl.containerManager.NewPodContainerManager()
	_, podContainerName := pcm.GetPodContainerName(pod)
	opts := &kubecontainer.RunContainerOptions{CgroupParent: podContainerName}
	hostname, hostDomainName, err := kl.GeneratePodHostNameAndDomain(pod)
	if err != nil {
		return nil, err
	}
	if kl.kubeletConfiguration.TSHostnameFqdn {
		opts.Hostname = hostname + "." + hostDomainName
	} else {
		opts.Hostname = hostname
	}
	if len(opts.Hostname) > hostnameMaxLen && !podUsesHostNetwork(pod) {
		return nil, errors.New("Container hostname " + opts.Hostname + " is too long (63 characters limit).")
	}
	podName := volumehelper.GetUniquePodName(pod)
	volumes := kl.volumeManager.GetMountedVolumesForPod(podName)

	opts.PortMappings = makePortMappings(container)
	opts.Devices = makeDevices(container)

	opts.Mounts, err = makeMounts(pod, kl.getPodDir(pod.UID), container, hostname, hostDomainName, podIP, volumes)
	if err != nil {
		return nil, err
	}

	// create all required TS mounts (for Kerberos ticket, keytabs, certs, and custom resolve.conf)
	if tsMounts, err := kl.makeTSMounts(pod, kl.getPodDir(pod.UID), podIP, kl.clusterDomain, kl.hostname,
		kl.kubeletConfiguration.TSCustomResolvConf); err != nil {
		glog.Errorf(krbutils.TSE+"unable to create TS mounts for Pod %s, error: %v", pod.Name, err)
		return nil, err
	} else {
		if len(tsMounts) > 0 {
			opts.Mounts = append(opts.Mounts, tsMounts...)
		}
	}

	opts.Envs, err = kl.makeEnvironmentVariables(pod, container, podIP)
	if err != nil {
		return nil, err
	}

	// Disabling adding TerminationMessagePath on Windows as these files would be mounted as docker volume and
	// Docker for Windows has a bug where only directories can be mounted
	if len(container.TerminationMessagePath) != 0 && runtime.GOOS != "windows" {
		p := kl.getPodContainerDir(pod.UID, container.Name)
		if err := os.MkdirAll(p, 0750); err != nil {
			glog.Errorf("Error on creating %q: %v", p, err)
		} else {
			opts.PodContainerDir = p
		}
	}

	opts.DNS, opts.DNSSearch, err = kl.GetClusterDNS(pod)
	if err != nil {
		return nil, err
	}

	// only do this check if the experimental behavior is enabled, otherwise allow it to default to false
	if kl.experimentalHostUserNamespaceDefaulting {
		opts.EnableHostUserNamespace = kl.enableHostUserNamespace(pod)
	}

	return opts, nil
}

var masterServices = sets.NewString("kubernetes")

// getServiceEnvVarMap makes a map[string]string of env vars for services a
// pod in namespace ns should see.
func (kl *Kubelet) getServiceEnvVarMap(ns string) (map[string]string, error) {
	var (
		serviceMap = make(map[string]*api.Service)
		m          = make(map[string]string)
	)

	// Get all service resources from the master (via a cache),
	// and populate them into service environment variables.
	if kl.serviceLister == nil {
		// Kubelets without masters (e.g. plain GCE ContainerVM) don't set env vars.
		return m, nil
	}
	services, err := kl.serviceLister.List(labels.Everything())
	if err != nil {
		return m, fmt.Errorf("failed to list services when setting up env vars.")
	}

	// project the services in namespace ns onto the master services
	for i := range services {
		service := services[i]
		// ignore services where ClusterIP is "None" or empty
		if !api.IsServiceIPSet(service) {
			continue
		}
		serviceName := service.Name

		switch service.Namespace {
		// for the case whether the master service namespace is the namespace the pod
		// is in, the pod should receive all the services in the namespace.
		//
		// ordering of the case clauses below enforces this
		case ns:
			serviceMap[serviceName] = service
		case kl.masterServiceNamespace:
			if masterServices.Has(serviceName) {
				if _, exists := serviceMap[serviceName]; !exists {
					serviceMap[serviceName] = service
				}
			}
		}
	}

	mappedServices := []*api.Service{}
	for key := range serviceMap {
		mappedServices = append(mappedServices, serviceMap[key])
	}

	for _, e := range envvars.FromServices(mappedServices) {
		m[e.Name] = e.Value
	}
	return m, nil
}

// Make the environment variables for a pod in the given namespace.
func (kl *Kubelet) makeEnvironmentVariables(pod *api.Pod, container *api.Container, podIP string) ([]kubecontainer.EnvVar, error) {
	var result []kubecontainer.EnvVar
	// Note:  These are added to the docker Config, but are not included in the checksum computed
	// by dockertools.BuildDockerName(...).  That way, we can still determine whether an
	// api.Container is already running by its hash. (We don't want to restart a container just
	// because some service changed.)
	//
	// Note that there is a race between Kubelet seeing the pod and kubelet seeing the service.
	// To avoid this users can: (1) wait between starting a service and starting; or (2) detect
	// missing service env var and exit and be restarted; or (3) use DNS instead of env vars
	// and keep trying to resolve the DNS name of the service (recommended).
	serviceEnv, err := kl.getServiceEnvVarMap(pod.Namespace)
	if err != nil {
		return result, err
	}

	// Determine the final values of variables:
	//
	// 1.  Determine the final value of each variable:
	//     a.  If the variable's Value is set, expand the `$(var)` references to other
	//         variables in the .Value field; the sources of variables are the declared
	//         variables of the container and the service environment variables
	//     b.  If a source is defined for an environment variable, resolve the source
	// 2.  Create the container's environment in the order variables are declared
	// 3.  Add remaining service environment vars
	var (
		tmpEnv      = make(map[string]string)
		configMaps  = make(map[string]*api.ConfigMap)
		secrets     = make(map[string]*api.Secret)
		mappingFunc = expansion.MappingFuncFor(tmpEnv, serviceEnv)
	)
	for _, envVar := range container.Env {
		// Accesses apiserver+Pods.
		// So, the master may set service env vars, or kubelet may.  In case both are doing
		// it, we delete the key from the kubelet-generated ones so we don't have duplicate
		// env vars.
		// TODO: remove this net line once all platforms use apiserver+Pods.
		delete(serviceEnv, envVar.Name)

		runtimeVal := envVar.Value
		if runtimeVal != "" {
			// Step 1a: expand variable references
			runtimeVal = expansion.Expand(runtimeVal, mappingFunc)
		} else if envVar.ValueFrom != nil {
			// Step 1b: resolve alternate env var sources
			switch {
			case envVar.ValueFrom.FieldRef != nil:
				runtimeVal, err = kl.podFieldSelectorRuntimeValue(envVar.ValueFrom.FieldRef, pod, podIP)
				if err != nil {
					return result, err
				}
			case envVar.ValueFrom.ResourceFieldRef != nil:
				defaultedPod, defaultedContainer, err := kl.defaultPodLimitsForDownwardApi(pod, container)
				if err != nil {
					return result, err
				}
				runtimeVal, err = containerResourceRuntimeValue(envVar.ValueFrom.ResourceFieldRef, defaultedPod, defaultedContainer)
				if err != nil {
					return result, err
				}
			case envVar.ValueFrom.ConfigMapKeyRef != nil:
				name := envVar.ValueFrom.ConfigMapKeyRef.Name
				key := envVar.ValueFrom.ConfigMapKeyRef.Key
				configMap, ok := configMaps[name]
				if !ok {
					if kl.kubeClient == nil {
						return result, fmt.Errorf("Couldn't get configMap %v/%v, no kubeClient defined", pod.Namespace, name)
					}
					configMap, err = kl.kubeClient.Core().ConfigMaps(pod.Namespace).Get(name)
					if err != nil {
						return result, err
					}
					configMaps[name] = configMap
				}
				runtimeVal, ok = configMap.Data[key]
				if !ok {
					return result, fmt.Errorf("Couldn't find key %v in ConfigMap %v/%v", key, pod.Namespace, name)
				}
			case envVar.ValueFrom.SecretKeyRef != nil:
				name := envVar.ValueFrom.SecretKeyRef.Name
				key := envVar.ValueFrom.SecretKeyRef.Key
				secret, ok := secrets[name]
				if !ok {
					if kl.kubeClient == nil {
						return result, fmt.Errorf("Couldn't get secret %v/%v, no kubeClient defined", pod.Namespace, name)
					}
					secret, err = kl.kubeClient.Core().Secrets(pod.Namespace).Get(name)
					if err != nil {
						return result, err
					}
					secrets[name] = secret
				}
				runtimeValBytes, ok := secret.Data[key]
				if !ok {
					return result, fmt.Errorf("Couldn't find key %v in Secret %v/%v", key, pod.Namespace, name)
				}
				runtimeVal = string(runtimeValBytes)
			}
		}

		tmpEnv[envVar.Name] = runtimeVal
		result = append(result, kubecontainer.EnvVar{Name: envVar.Name, Value: tmpEnv[envVar.Name]})
	}

	// Append remaining service env vars.
	for k, v := range serviceEnv {
		result = append(result, kubecontainer.EnvVar{Name: k, Value: v})
	}
	return result, nil
}

// podFieldSelectorRuntimeValue returns the runtime value of the given
// selector for a pod.
func (kl *Kubelet) podFieldSelectorRuntimeValue(fs *api.ObjectFieldSelector, pod *api.Pod, podIP string) (string, error) {
	internalFieldPath, _, err := api.Scheme.ConvertFieldLabel(fs.APIVersion, "Pod", fs.FieldPath, "")
	if err != nil {
		return "", err
	}
	switch internalFieldPath {
	case "spec.nodeName":
		return pod.Spec.NodeName, nil
	case "spec.serviceAccountName":
		return pod.Spec.ServiceAccountName, nil
	case "status.podIP":
		return podIP, nil
	}
	return fieldpath.ExtractFieldPathAsString(pod, internalFieldPath)
}

// containerResourceRuntimeValue returns the value of the provided container resource
func containerResourceRuntimeValue(fs *api.ResourceFieldSelector, pod *api.Pod, container *api.Container) (string, error) {
	containerName := fs.ContainerName
	if len(containerName) == 0 {
		return fieldpath.ExtractContainerResourceValue(fs, container)
	} else {
		return fieldpath.ExtractResourceValueByContainerName(fs, pod, containerName)
	}
}

// One of the following arguments must be non-nil: runningPod, status.
// TODO: Modify containerRuntime.KillPod() to accept the right arguments.
func (kl *Kubelet) killPod(pod *api.Pod, runningPod *kubecontainer.Pod, status *kubecontainer.PodStatus, gracePeriodOverride *int64) error {
	var p kubecontainer.Pod
	if runningPod != nil {
		p = *runningPod
	} else if status != nil {
		p = kubecontainer.ConvertPodStatusToRunningPod(kl.GetRuntime().Type(), status)
	}

	// cache the pod cgroup Name for reducing the cpu resource limits of the pod cgroup once the pod is killed
	pcm := kl.containerManager.NewPodContainerManager()
	var podCgroup cm.CgroupName
	reduceCpuLimts := true
	if pod != nil {
		podCgroup, _ = pcm.GetPodContainerName(pod)
	} else {
		// If the pod is nil then cgroup limit must have already
		// been decreased earlier
		reduceCpuLimts = false
	}

	// Call the container runtime KillPod method which stops all running containers of the pod
	if err := kl.containerRuntime.KillPod(pod, p, gracePeriodOverride); err != nil {
		return err
	}
	// At this point the pod might not completely free up cpu and memory resources.
	// In such a case deleting the pod's cgroup might cause the pod's charges to be transferred
	// to the parent cgroup. There might be various kinds of pod charges at this point.
	// For example, any volume used by the pod that was backed by memory will have its
	// pages charged to the pod cgroup until those volumes are removed by the kubelet.
	// Hence we only reduce the cpu resource limits of the pod's cgroup
	// and defer the responsibilty of destroying the pod's cgroup to the
	// cleanup method and the housekeeping loop.
	if reduceCpuLimts {
		pcm.ReduceCPULimits(podCgroup)
	}
	return nil
}

// makePodDataDirs creates the dirs for the pod datas.
func (kl *Kubelet) makePodDataDirs(pod *api.Pod) error {
	uid := pod.UID
	if err := os.MkdirAll(kl.getPodDir(uid), 0750); err != nil && !os.IsExist(err) {
		return err
	}
	if err := os.MkdirAll(kl.getPodVolumesDir(uid), 0750); err != nil && !os.IsExist(err) {
		return err
	}
	if err := os.MkdirAll(kl.getPodPluginsDir(uid), 0750); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

// returns whether the pod uses the host network namespace.
func podUsesHostNetwork(pod *api.Pod) bool {
	return pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.HostNetwork
}

// getPullSecretsForPod inspects the Pod and retrieves the referenced pull
// secrets.
// TODO: duplicate secrets are being retrieved multiple times and there
// is no cache.  Creating and using a secret manager interface will make this
// easier to address.
func (kl *Kubelet) getPullSecretsForPod(pod *api.Pod) ([]api.Secret, error) {
	pullSecrets := []api.Secret{}

	for _, secretRef := range pod.Spec.ImagePullSecrets {
		secret, err := kl.kubeClient.Core().Secrets(pod.Namespace).Get(secretRef.Name)
		if err != nil {
			glog.Warningf("Unable to retrieve pull secret %s/%s for %s/%s due to %v.  The image pull may not succeed.", pod.Namespace, secretRef.Name, pod.Namespace, pod.Name, err)
			continue
		}

		pullSecrets = append(pullSecrets, *secret)
	}

	return pullSecrets, nil
}

// Returns true if pod is in the terminated state ("Failed" or "Succeeded").
func (kl *Kubelet) podIsTerminated(pod *api.Pod) bool {
	var status api.PodStatus
	// Check the cached pod status which was set after the last sync.
	status, ok := kl.statusManager.GetPodStatus(pod.UID)
	if !ok {
		// If there is no cached status, use the status from the
		// apiserver. This is useful if kubelet has recently been
		// restarted.
		status = pod.Status
	}
	if status.Phase == api.PodFailed || status.Phase == api.PodSucceeded {
		return true
	}

	return false
}

// filterOutTerminatedPods returns the given pods which the status manager
// does not consider failed or succeeded.
func (kl *Kubelet) filterOutTerminatedPods(pods []*api.Pod) []*api.Pod {
	var filteredPods []*api.Pod
	for _, p := range pods {
		if kl.podIsTerminated(p) {
			continue
		}
		filteredPods = append(filteredPods, p)
	}
	return filteredPods
}

// removeOrphanedPodStatuses removes obsolete entries in podStatus where
// the pod is no longer considered bound to this node.
func (kl *Kubelet) removeOrphanedPodStatuses(pods []*api.Pod, mirrorPods []*api.Pod) {
	podUIDs := make(map[types.UID]bool)
	for _, pod := range pods {
		podUIDs[pod.UID] = true
	}
	for _, pod := range mirrorPods {
		podUIDs[pod.UID] = true
	}
	kl.statusManager.RemoveOrphanedStatuses(podUIDs)
}

// HandlePodCleanups performs a series of cleanup work, including terminating
// pod workers, killing unwanted pods, and removing orphaned volumes/pod
// directories.
// NOTE: This function is executed by the main sync loop, so it
// should not contain any blocking calls.
func (kl *Kubelet) HandlePodCleanups() error {
	// The kubelet lacks checkpointing, so we need to introspect the set of pods
	// in the cgroup tree prior to inspecting the set of pods in our pod manager.
	// this ensures our view of the cgroup tree does not mistakenly observe pods
	// that are added after the fact...
	var (
		cgroupPods map[types.UID]cm.CgroupName
		err        error
	)
	if kl.cgroupsPerQOS {
		pcm := kl.containerManager.NewPodContainerManager()
		cgroupPods, err = pcm.GetAllPodsFromCgroups()
		if err != nil {
			return fmt.Errorf("failed to get list of pods that still exist on cgroup mounts: %v", err)
		}
	}

	allPods, mirrorPods := kl.podManager.GetPodsAndMirrorPods()
	// Pod phase progresses monotonically. Once a pod has reached a final state,
	// it should never leave regardless of the restart policy. The statuses
	// of such pods should not be changed, and there is no need to sync them.
	// TODO: the logic here does not handle two cases:
	//   1. If the containers were removed immediately after they died, kubelet
	//      may fail to generate correct statuses, let alone filtering correctly.
	//   2. If kubelet restarted before writing the terminated status for a pod
	//      to the apiserver, it could still restart the terminated pod (even
	//      though the pod was not considered terminated by the apiserver).
	// These two conditions could be alleviated by checkpointing kubelet.
	activePods := kl.filterOutTerminatedPods(allPods)

	desiredPods := make(map[types.UID]empty)
	for _, pod := range activePods {
		desiredPods[pod.UID] = empty{}
	}
	// Stop the workers for no-longer existing pods.
	// TODO: is here the best place to forget pod workers?
	kl.podWorkers.ForgetNonExistingPodWorkers(desiredPods)
	kl.probeManager.CleanupPods(activePods)

	runningPods, err := kl.runtimeCache.GetPods()
	if err != nil {
		glog.Errorf("Error listing containers: %#v", err)
		return err
	}
	for _, pod := range runningPods {
		if _, found := desiredPods[pod.ID]; !found {
			kl.podKillingCh <- &kubecontainer.PodPair{APIPod: nil, RunningPod: pod}
		}
	}

	// manage Kerberos for the active Pods
	for _, pod := range kl.getActivePods() {
		needKeytabs, needCerts, _, _ := kl.checkIfPodUsesKerberos(pod)
		if needCerts || needKeytabs {
			glog.V(5).Infof(krbutils.TSL+"managing Kerberos objects for Pod %s in HandlePodCleanups()", pod.Name)
			kl.podKerberosCh <- &PodUpdateKerberosMessage{APIPod: pod}
		}
	}

	kl.removeOrphanedPodStatuses(allPods, mirrorPods)
	// Note that we just killed the unwanted pods. This may not have reflected
	// in the cache. We need to bypass the cache to get the latest set of
	// running pods to clean up the volumes.
	// TODO: Evaluate the performance impact of bypassing the runtime cache.
	runningPods, err = kl.containerRuntime.GetPods(false)
	if err != nil {
		glog.Errorf("Error listing containers: %#v", err)
		return err
	}

	// Remove any orphaned volumes.
	// Note that we pass all pods (including terminated pods) to the function,
	// so that we don't remove volumes associated with terminated but not yet
	// deleted pods.
	err = kl.cleanupOrphanedPodDirs(allPods, runningPods)
	if err != nil {
		// We want all cleanup tasks to be run even if one of them failed. So
		// we just log an error here and continue other cleanup tasks.
		// This also applies to the other clean up tasks.
		glog.Errorf("Failed cleaning up orphaned pod directories: %v", err)
	}

	// Remove any orphaned mirror pods.
	kl.podManager.DeleteOrphanedMirrorPods()

	// Clear out any old bandwidth rules
	err = kl.cleanupBandwidthLimits(allPods)
	if err != nil {
		glog.Errorf("Failed cleaning up bandwidth limits: %v", err)
	}

	// Remove any cgroups in the hierarchy for pods that should no longer exist
	if kl.cgroupsPerQOS {
		kl.cleanupOrphanedPodCgroups(cgroupPods, allPods, runningPods)
	}

	kl.backOff.GC()
	return nil
}

// podKiller launches a goroutine to kill a pod received from the channel if
// another goroutine isn't already in action.
func (kl *Kubelet) podKiller() {
	killing := sets.NewString()
	resultCh := make(chan types.UID)
	defer close(resultCh)
	for {
		select {
		case podPair, ok := <-kl.podKillingCh:
			if !ok {
				return
			}

			runningPod := podPair.RunningPod
			apiPod := podPair.APIPod

			if killing.Has(string(runningPod.ID)) {
				// The pod is already being killed.
				break
			}
			killing.Insert(string(runningPod.ID))
			go func(apiPod *api.Pod, runningPod *kubecontainer.Pod, ch chan types.UID) {
				defer func() {
					ch <- runningPod.ID
				}()
				glog.V(2).Infof("Killing unwanted pod %q", runningPod.Name)
				err := kl.killPod(apiPod, runningPod, nil, nil)
				if err != nil {
					glog.Errorf("Failed killing the pod %q: %v", runningPod.Name, err)
				}
			}(apiPod, runningPod, resultCh)

		case podID := <-resultCh:
			killing.Delete(string(podID))
		}
	}
}

// podKerberosManager launches a goroutine to update Pod's Kerberos objects based on desired state.
// The desired state includes both Pod level and service level KDC clusters.
func (kl *Kubelet) podKerberosManager() {
	inProgressDelete := sets.NewString()
	inProgressRefresh := sets.NewString()
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
				// do not do anything with Pods with cached Kerberos
				if krbLocal, ok := apiPod.ObjectMeta.Annotations[krbutils.TSKrbLocal]; ok && krbLocal == "true" {
					continue
				}
				// check what type of request it is and ignore if already on-going
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

func (kl *Kubelet) podUpdateKerberos(pod *api.Pod) {
	defer clock.ExecTime(time.Now(), "podUpdateKerberos", pod.Name)
	var err error
	var mutex *lock.Mutex = nil

	needKeytabs := false
	needCerts := false
	realm := krbutils.KerberosRealm

	needKeytabs, needCerts, user, services := kl.checkIfPodUsesKerberos(pod)
	if !needCerts && !needKeytabs {
		// nothing to do for this Pod
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
			if err := krbutils.RemoveHostFromClusterInKDC(podClusterName, kl.hostname, mutex); err != nil {
				glog.V(2).Infof(krbutils.TSL+"Failed to remove host %s from KDC clusters %+v for pod %q during Pod update for delete, err: %v",
					kl.hostname, podAllClusters, format.Pod(pod), err)
			} else {
				glog.V(5).Infof(krbutils.TSL+"Removed host %s from KDC clusters %+v for pod %q during Pod update for delete",
					kl.hostname, podAllClusters, format.Pod(pod))
			}
		}
		/*
			// trigger host keytab trimming
			if err := invokePodKeytabRefresh(pod); err != nil {
				glog.Errorf(krbutils.TSE+"trimming keytab post deletion for Pod %s failed, err: %+v", pod.Name, err)
			} else {
				glog.V(5).Infof(krbutils.TSL+"trimming keytab post deletion for Pod %s succeeded", pod.Name)
			}
		*/
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

			if err := verifyAndFixKeytab(pod, services, kl.hostname, realm, podAllClusters, keytabFilePath, user, false); err != nil {
				glog.Errorf(krbutils.TSE+"failed to verify keytab for Pod %s in podUpdate handler, error: %+v", pod.Name, err)
				// continue to the handler
			} else {
				// no need to proceed, all keytabs present
				glog.V(5).Infof(krbutils.TSL+"keytab creation skipped (during Pod refresh) for clusters %+v and services %+v for POD %q",
					podAllClusters, services, format.Pod(pod))
				return
			}

			if err := kl.createKeytab(keytabFilePath, kl.clusterDomain, pod, services,
				kl.hostname, realm, podAllClusters, user, false); err != nil {
				glog.Errorf(krbutils.TSE+"error creating keytab (in refresh) for Pod %s clusters %+v services %+v, error: %v",
					pod.Name, podAllClusters, services, err)
			} else {
				glog.V(5).Infof(krbutils.TSL+"updated keytab file (during Pod refresh) for clusters %+v and services %+v for POD %q",
					podAllClusters, services, format.Pod(pod))
			}
		}
		if needCerts {
			// create certs
			certsFilePath := path.Join(kl.getPodDir(pod.UID), krbutils.CertsDirForPod)
			if err := createCerts(certsFilePath, kl.clusterDomain, pod,
				kl.hostname, realm, podAllClusters, user); err != nil {
				glog.Errorf(krbutils.TSE+"error creating certs (in update) for Pod %s clusters %+v, error: %v",
					pod.Name, podAllClusters, err)
			} else {
				glog.V(5).Infof(krbutils.TSL+"updated certs file (during Pod refresh) for clusters %+v for POD %q",
					podAllClusters, format.Pod(pod))
			}
		}
	}
}

// compute the list of all KDC clusters of all Pods on this node except for Pod pod (which is being removed)
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

// checkHostPortConflicts detects pods with conflicted host ports.
func hasHostPortConflicts(pods []*api.Pod) bool {
	ports := sets.String{}
	for _, pod := range pods {
		if errs := validation.AccumulateUniqueHostPorts(pod.Spec.Containers, &ports, field.NewPath("spec", "containers")); len(errs) > 0 {
			glog.Errorf("Pod %q: HostPort is already allocated, ignoring: %v", format.Pod(pod), errs)
			return true
		}
		if errs := validation.AccumulateUniqueHostPorts(pod.Spec.InitContainers, &ports, field.NewPath("spec", "initContainers")); len(errs) > 0 {
			glog.Errorf("Pod %q: HostPort is already allocated, ignoring: %v", format.Pod(pod), errs)
			return true
		}
	}
	return false
}

// validateContainerLogStatus returns the container ID for the desired container to retrieve logs for, based on the state
// of the container. The previous flag will only return the logs for the last terminated container, otherwise, the current
// running container is preferred over a previous termination. If info about the container is not available then a specific
// error is returned to the end user.
func (kl *Kubelet) validateContainerLogStatus(podName string, podStatus *api.PodStatus, containerName string, previous bool) (containerID kubecontainer.ContainerID, err error) {
	var cID string

	cStatus, found := api.GetContainerStatus(podStatus.ContainerStatuses, containerName)
	// if not found, check the init containers
	if !found {
		cStatus, found = api.GetContainerStatus(podStatus.InitContainerStatuses, containerName)
	}
	if !found {
		return kubecontainer.ContainerID{}, fmt.Errorf("container %q in pod %q is not available", containerName, podName)
	}
	lastState := cStatus.LastTerminationState
	waiting, running, terminated := cStatus.State.Waiting, cStatus.State.Running, cStatus.State.Terminated

	switch {
	case previous:
		if lastState.Terminated == nil {
			return kubecontainer.ContainerID{}, fmt.Errorf("previous terminated container %q in pod %q not found", containerName, podName)
		}
		cID = lastState.Terminated.ContainerID

	case running != nil:
		cID = cStatus.ContainerID

	case terminated != nil:
		cID = terminated.ContainerID

	case lastState.Terminated != nil:
		cID = lastState.Terminated.ContainerID

	case waiting != nil:
		// output some info for the most common pending failures
		switch reason := waiting.Reason; reason {
		case images.ErrImagePull.Error():
			return kubecontainer.ContainerID{}, fmt.Errorf("container %q in pod %q is waiting to start: image can't be pulled", containerName, podName)
		case images.ErrImagePullBackOff.Error():
			return kubecontainer.ContainerID{}, fmt.Errorf("container %q in pod %q is waiting to start: trying and failing to pull image", containerName, podName)
		default:
			return kubecontainer.ContainerID{}, fmt.Errorf("container %q in pod %q is waiting to start: %v", containerName, podName, reason)
		}
	default:
		// unrecognized state
		return kubecontainer.ContainerID{}, fmt.Errorf("container %q in pod %q is waiting to start - no logs yet", containerName, podName)
	}

	return kubecontainer.ParseContainerID(cID), nil
}

// GetKubeletContainerLogs returns logs from the container
// TODO: this method is returning logs of random container attempts, when it should be returning the most recent attempt
// or all of them.
func (kl *Kubelet) GetKubeletContainerLogs(podFullName, containerName string, logOptions *api.PodLogOptions, stdout, stderr io.Writer) error {
	// Pod workers periodically write status to statusManager. If status is not
	// cached there, something is wrong (or kubelet just restarted and hasn't
	// caught up yet). Just assume the pod is not ready yet.
	name, namespace, err := kubecontainer.ParsePodFullName(podFullName)
	if err != nil {
		return fmt.Errorf("unable to parse pod full name %q: %v", podFullName, err)
	}

	pod, ok := kl.GetPodByName(namespace, name)
	if !ok {
		return fmt.Errorf("pod %q cannot be found - no logs available", name)
	}

	podUID := pod.UID
	if mirrorPod, ok := kl.podManager.GetMirrorPodByPod(pod); ok {
		podUID = mirrorPod.UID
	}
	podStatus, found := kl.statusManager.GetPodStatus(podUID)
	if !found {
		// If there is no cached status, use the status from the
		// apiserver. This is useful if kubelet has recently been
		// restarted.
		podStatus = pod.Status
	}

	// TODO: Consolidate the logic here with kuberuntime.GetContainerLogs, here we convert container name to containerID,
	// but inside kuberuntime we convert container id back to container name and restart count.
	// TODO: After separate container log lifecycle management, we should get log based on the existing log files
	// instead of container status.
	containerID, err := kl.validateContainerLogStatus(pod.Name, &podStatus, containerName, logOptions.Previous)
	if err != nil {
		return err
	}

	// Do a zero-byte write to stdout before handing off to the container runtime.
	// This ensures at least one Write call is made to the writer when copying starts,
	// even if we then block waiting for log output from the container.
	if _, err := stdout.Write([]byte{}); err != nil {
		return err
	}

	return kl.containerRuntime.GetContainerLogs(pod, containerID, logOptions, stdout, stderr)
}

// GetPhase returns the phase of a pod given its container info.
// This func is exported to simplify integration with 3rd party kubelet
// integrations like kubernetes-mesos.
func GetPhase(spec *api.PodSpec, info []api.ContainerStatus) api.PodPhase {
	initialized := 0
	pendingInitialization := 0
	failedInitialization := 0
	for _, container := range spec.InitContainers {
		containerStatus, ok := api.GetContainerStatus(info, container.Name)
		if !ok {
			pendingInitialization++
			continue
		}

		switch {
		case containerStatus.State.Running != nil:
			pendingInitialization++
		case containerStatus.State.Terminated != nil:
			if containerStatus.State.Terminated.ExitCode == 0 {
				initialized++
			} else {
				failedInitialization++
			}
		case containerStatus.State.Waiting != nil:
			if containerStatus.LastTerminationState.Terminated != nil {
				if containerStatus.LastTerminationState.Terminated.ExitCode == 0 {
					initialized++
				} else {
					failedInitialization++
				}
			} else {
				pendingInitialization++
			}
		default:
			pendingInitialization++
		}
	}

	unknown := 0
	running := 0
	waiting := 0
	stopped := 0
	failed := 0
	succeeded := 0
	for _, container := range spec.Containers {
		containerStatus, ok := api.GetContainerStatus(info, container.Name)
		if !ok {
			unknown++
			continue
		}

		switch {
		case containerStatus.State.Running != nil:
			running++
		case containerStatus.State.Terminated != nil:
			stopped++
			if containerStatus.State.Terminated.ExitCode == 0 {
				succeeded++
			} else {
				failed++
			}
		case containerStatus.State.Waiting != nil:
			if containerStatus.LastTerminationState.Terminated != nil {
				stopped++
			} else {
				waiting++
			}
		default:
			unknown++
		}
	}

	if failedInitialization > 0 && spec.RestartPolicy == api.RestartPolicyNever {
		return api.PodFailed
	}

	switch {
	case pendingInitialization > 0:
		fallthrough
	case waiting > 0:
		glog.V(5).Infof("pod waiting > 0, pending")
		// One or more containers has not been started
		return api.PodPending
	case running > 0 && unknown == 0:
		// All containers have been started, and at least
		// one container is running
		return api.PodRunning
	case running == 0 && stopped > 0 && unknown == 0:
		// All containers are terminated
		if spec.RestartPolicy == api.RestartPolicyAlways {
			// All containers are in the process of restarting
			return api.PodRunning
		}
		if stopped == succeeded {
			// RestartPolicy is not Always, and all
			// containers are terminated in success
			return api.PodSucceeded
		}
		if spec.RestartPolicy == api.RestartPolicyNever {
			// RestartPolicy is Never, and all containers are
			// terminated with at least one in failure
			return api.PodFailed
		}
		// RestartPolicy is OnFailure, and at least one in failure
		// and in the process of restarting
		return api.PodRunning
	default:
		glog.V(5).Infof("pod default case, pending")
		return api.PodPending
	}
}

// generateAPIPodStatus creates the final API pod status for a pod, given the
// internal pod status.
func (kl *Kubelet) generateAPIPodStatus(pod *api.Pod, podStatus *kubecontainer.PodStatus) api.PodStatus {
	glog.V(3).Infof("Generating status for %q", format.Pod(pod))

	// check if an internal module has requested the pod is evicted.
	for _, podSyncHandler := range kl.PodSyncHandlers {
		if result := podSyncHandler.ShouldEvict(pod); result.Evict {
			return api.PodStatus{
				Phase:   api.PodFailed,
				Reason:  result.Reason,
				Message: result.Message,
			}
		}
	}

	s := kl.convertStatusToAPIStatus(pod, podStatus)

	// Assume info is ready to process
	spec := &pod.Spec
	allStatus := append(append([]api.ContainerStatus{}, s.ContainerStatuses...), s.InitContainerStatuses...)
	s.Phase = GetPhase(spec, allStatus)
	kl.probeManager.UpdatePodStatus(pod.UID, s)
	s.Conditions = append(s.Conditions, status.GeneratePodInitializedCondition(spec, s.InitContainerStatuses, s.Phase))
	s.Conditions = append(s.Conditions, status.GeneratePodReadyCondition(spec, s.ContainerStatuses, s.Phase))
	// s (the PodStatus we are creating) will not have a PodScheduled condition yet, because converStatusToAPIStatus()
	// does not create one. If the existing PodStatus has a PodScheduled condition, then copy it into s and make sure
	// it is set to true. If the existing PodStatus does not have a PodScheduled condition, then create one that is set to true.
	if _, oldPodScheduled := api.GetPodCondition(&pod.Status, api.PodScheduled); oldPodScheduled != nil {
		s.Conditions = append(s.Conditions, *oldPodScheduled)
	}
	api.UpdatePodCondition(&pod.Status, &api.PodCondition{
		Type:   api.PodScheduled,
		Status: api.ConditionTrue,
	})

	if !kl.standaloneMode {
		hostIP, err := kl.getHostIPAnyWay()
		if err != nil {
			glog.V(4).Infof("Cannot get host IP: %v", err)
		} else {
			s.HostIP = hostIP.String()
			if podUsesHostNetwork(pod) && s.PodIP == "" {
				s.PodIP = hostIP.String()
			}
		}
	}

	return *s
}

// convertStatusToAPIStatus creates an api PodStatus for the given pod from
// the given internal pod status.  It is purely transformative and does not
// alter the kubelet state at all.
func (kl *Kubelet) convertStatusToAPIStatus(pod *api.Pod, podStatus *kubecontainer.PodStatus) *api.PodStatus {
	var apiPodStatus api.PodStatus
	apiPodStatus.PodIP = podStatus.IP

	apiPodStatus.ContainerStatuses = kl.convertToAPIContainerStatuses(
		pod, podStatus,
		pod.Status.ContainerStatuses,
		pod.Spec.Containers,
		len(pod.Spec.InitContainers) > 0,
		false,
	)
	apiPodStatus.InitContainerStatuses = kl.convertToAPIContainerStatuses(
		pod, podStatus,
		pod.Status.InitContainerStatuses,
		pod.Spec.InitContainers,
		len(pod.Spec.InitContainers) > 0,
		true,
	)

	return &apiPodStatus
}

// convertToAPIContainerStatuses converts the given internal container
// statuses into API container statuses.
func (kl *Kubelet) convertToAPIContainerStatuses(pod *api.Pod, podStatus *kubecontainer.PodStatus, previousStatus []api.ContainerStatus, containers []api.Container, hasInitContainers, isInitContainer bool) []api.ContainerStatus {
	convertContainerStatus := func(cs *kubecontainer.ContainerStatus) *api.ContainerStatus {
		cid := cs.ID.String()
		status := &api.ContainerStatus{
			Name:         cs.Name,
			RestartCount: int32(cs.RestartCount),
			Image:        cs.Image,
			ImageID:      cs.ImageID,
			ContainerID:  cid,
		}
		switch cs.State {
		case kubecontainer.ContainerStateRunning:
			status.State.Running = &api.ContainerStateRunning{StartedAt: unversioned.NewTime(cs.StartedAt)}
		case kubecontainer.ContainerStateExited:
			status.State.Terminated = &api.ContainerStateTerminated{
				ExitCode:    int32(cs.ExitCode),
				Reason:      cs.Reason,
				Message:     cs.Message,
				StartedAt:   unversioned.NewTime(cs.StartedAt),
				FinishedAt:  unversioned.NewTime(cs.FinishedAt),
				ContainerID: cid,
			}
		default:
			status.State.Waiting = &api.ContainerStateWaiting{}
		}
		return status
	}

	// Fetch old containers statuses from old pod status.
	oldStatuses := make(map[string]api.ContainerStatus, len(containers))
	for _, status := range previousStatus {
		oldStatuses[status.Name] = status
	}

	// Set all container statuses to default waiting state
	statuses := make(map[string]*api.ContainerStatus, len(containers))
	defaultWaitingState := api.ContainerState{Waiting: &api.ContainerStateWaiting{Reason: "ContainerCreating"}}
	if hasInitContainers {
		defaultWaitingState = api.ContainerState{Waiting: &api.ContainerStateWaiting{Reason: "PodInitializing"}}
	}

	for _, container := range containers {
		status := &api.ContainerStatus{
			Name:  container.Name,
			Image: container.Image,
			State: defaultWaitingState,
		}
		// Apply some values from the old statuses as the default values.
		if oldStatus, found := oldStatuses[container.Name]; found {
			status.RestartCount = oldStatus.RestartCount
			status.LastTerminationState = oldStatus.LastTerminationState
		}
		statuses[container.Name] = status
	}

	// Make the latest container status comes first.
	sort.Sort(sort.Reverse(kubecontainer.SortContainerStatusesByCreationTime(podStatus.ContainerStatuses)))
	// Set container statuses according to the statuses seen in pod status
	containerSeen := map[string]int{}
	for _, cStatus := range podStatus.ContainerStatuses {
		cName := cStatus.Name
		if _, ok := statuses[cName]; !ok {
			// This would also ignore the infra container.
			continue
		}
		if containerSeen[cName] >= 2 {
			continue
		}
		status := convertContainerStatus(cStatus)
		if containerSeen[cName] == 0 {
			statuses[cName] = status
		} else {
			statuses[cName].LastTerminationState = status.State
		}
		containerSeen[cName] = containerSeen[cName] + 1
	}

	// Handle the containers failed to be started, which should be in Waiting state.
	for _, container := range containers {
		if isInitContainer {
			// If the init container is terminated with exit code 0, it won't be restarted.
			// TODO(random-liu): Handle this in a cleaner way.
			s := podStatus.FindContainerStatusByName(container.Name)
			if s != nil && s.State == kubecontainer.ContainerStateExited && s.ExitCode == 0 {
				continue
			}
		}
		// If a container should be restarted in next syncpod, it is *Waiting*.
		if !kubecontainer.ShouldContainerBeRestarted(&container, pod, podStatus) {
			continue
		}
		status := statuses[container.Name]
		reason, message, ok := kl.reasonCache.Get(pod.UID, container.Name)
		if !ok {
			// In fact, we could also apply Waiting state here, but it is less informative,
			// and the container will be restarted soon, so we prefer the original state here.
			// Note that with the current implementation of ShouldContainerBeRestarted the original state here
			// could be:
			//   * Waiting: There is no associated historical container and start failure reason record.
			//   * Terminated: The container is terminated.
			continue
		}
		if status.State.Terminated != nil {
			status.LastTerminationState = status.State
		}
		status.State = api.ContainerState{
			Waiting: &api.ContainerStateWaiting{
				Reason:  reason.Error(),
				Message: message,
			},
		}
		statuses[container.Name] = status
	}

	var containerStatuses []api.ContainerStatus
	for _, status := range statuses {
		containerStatuses = append(containerStatuses, *status)
	}

	// Sort the container statuses since clients of this interface expect the list
	// of containers in a pod has a deterministic order.
	if isInitContainer {
		kubetypes.SortInitContainerStatuses(pod, containerStatuses)
	} else {
		sort.Sort(kubetypes.SortedContainerStatuses(containerStatuses))
	}
	return containerStatuses
}

// Returns logs of current machine.
func (kl *Kubelet) ServeLogs(w http.ResponseWriter, req *http.Request) {
	// TODO: whitelist logs we are willing to serve
	kl.logServer.ServeHTTP(w, req)
}

// findContainer finds and returns the container with the given pod ID, full name, and container name.
// It returns nil if not found.
func (kl *Kubelet) findContainer(podFullName string, podUID types.UID, containerName string) (*kubecontainer.Container, error) {
	pods, err := kl.containerRuntime.GetPods(false)
	if err != nil {
		return nil, err
	}
	podUID = kl.podManager.TranslatePodUID(podUID)
	pod := kubecontainer.Pods(pods).FindPod(podFullName, podUID)
	return pod.FindContainerByName(containerName), nil
}

// Run a command in a container, returns the combined stdout, stderr as an array of bytes
func (kl *Kubelet) RunInContainer(podFullName string, podUID types.UID, containerName string, cmd []string) ([]byte, error) {
	container, err := kl.findContainer(podFullName, podUID, containerName)
	if err != nil {
		return nil, err
	}
	if container == nil {
		return nil, fmt.Errorf("container not found (%q)", containerName)
	}
	// TODO(timstclair): Pass a proper timeout value.
	return kl.runner.RunInContainer(container.ID, cmd, 0)
}

// ExecInContainer executes a command in a container, connecting the supplied
// stdin/stdout/stderr to the command's IO streams.
func (kl *Kubelet) ExecInContainer(podFullName string, podUID types.UID, containerName string, cmd []string, stdin io.Reader, stdout, stderr io.WriteCloser, tty bool, resize <-chan term.Size, timeout time.Duration) error {
	streamingRuntime, ok := kl.containerRuntime.(kubecontainer.DirectStreamingRuntime)
	if !ok {
		return fmt.Errorf("streaming methods not supported by runtime")
	}

	container, err := kl.findContainer(podFullName, podUID, containerName)
	if err != nil {
		return err
	}
	if container == nil {
		return fmt.Errorf("container not found (%q)", containerName)
	}
	return streamingRuntime.ExecInContainer(container.ID, cmd, stdin, stdout, stderr, tty, resize, timeout)
}

// AttachContainer uses the container runtime to attach the given streams to
// the given container.
func (kl *Kubelet) AttachContainer(podFullName string, podUID types.UID, containerName string, stdin io.Reader, stdout, stderr io.WriteCloser, tty bool, resize <-chan term.Size) error {
	streamingRuntime, ok := kl.containerRuntime.(kubecontainer.DirectStreamingRuntime)
	if !ok {
		return fmt.Errorf("streaming methods not supported by runtime")
	}

	container, err := kl.findContainer(podFullName, podUID, containerName)
	if err != nil {
		return err
	}
	if container == nil {
		return fmt.Errorf("container not found (%q)", containerName)
	}
	return streamingRuntime.AttachContainer(container.ID, stdin, stdout, stderr, tty, resize)
}

// PortForward connects to the pod's port and copies data between the port
// and the stream.
func (kl *Kubelet) PortForward(podFullName string, podUID types.UID, port uint16, stream io.ReadWriteCloser) error {
	streamingRuntime, ok := kl.containerRuntime.(kubecontainer.DirectStreamingRuntime)
	if !ok {
		return fmt.Errorf("streaming methods not supported by runtime")
	}

	pods, err := kl.containerRuntime.GetPods(false)
	if err != nil {
		return err
	}
	podUID = kl.podManager.TranslatePodUID(podUID)
	pod := kubecontainer.Pods(pods).FindPod(podFullName, podUID)
	if pod.IsEmpty() {
		return fmt.Errorf("pod not found (%q)", podFullName)
	}
	return streamingRuntime.PortForward(&pod, port, stream)
}

// GetExec gets the URL the exec will be served from, or nil if the Kubelet will serve it.
func (kl *Kubelet) GetExec(podFullName string, podUID types.UID, containerName string, cmd []string, streamOpts remotecommand.Options) (*url.URL, error) {
	switch streamingRuntime := kl.containerRuntime.(type) {
	case kubecontainer.DirectStreamingRuntime:
		// Kubelet will serve the exec directly.
		return nil, nil
	case kubecontainer.IndirectStreamingRuntime:
		container, err := kl.findContainer(podFullName, podUID, containerName)
		if err != nil {
			return nil, err
		}
		if container == nil {
			return nil, fmt.Errorf("container not found (%q)", containerName)
		}
		return streamingRuntime.GetExec(container.ID, cmd, streamOpts.Stdin, streamOpts.Stdout, streamOpts.Stderr, streamOpts.TTY)
	default:
		return nil, fmt.Errorf("container runtime does not support exec")
	}
}

// GetAttach gets the URL the attach will be served from, or nil if the Kubelet will serve it.
func (kl *Kubelet) GetAttach(podFullName string, podUID types.UID, containerName string, streamOpts remotecommand.Options) (*url.URL, error) {
	switch streamingRuntime := kl.containerRuntime.(type) {
	case kubecontainer.DirectStreamingRuntime:
		// Kubelet will serve the attach directly.
		return nil, nil
	case kubecontainer.IndirectStreamingRuntime:
		container, err := kl.findContainer(podFullName, podUID, containerName)
		if err != nil {
			return nil, err
		}
		if container == nil {
			return nil, fmt.Errorf("container not found (%q)", containerName)
		}

		return streamingRuntime.GetAttach(container.ID, streamOpts.Stdin, streamOpts.Stdout, streamOpts.Stderr)
	default:
		return nil, fmt.Errorf("container runtime does not support attach")
	}
}

// GetPortForward gets the URL the port-forward will be served from, or nil if the Kubelet will serve it.
func (kl *Kubelet) GetPortForward(podName, podNamespace string, podUID types.UID) (*url.URL, error) {
	switch streamingRuntime := kl.containerRuntime.(type) {
	case kubecontainer.DirectStreamingRuntime:
		// Kubelet will serve the attach directly.
		return nil, nil
	case kubecontainer.IndirectStreamingRuntime:
		pods, err := kl.containerRuntime.GetPods(false)
		if err != nil {
			return nil, err
		}
		podUID = kl.podManager.TranslatePodUID(podUID)
		podFullName := kubecontainer.BuildPodFullName(podName, podNamespace)
		pod := kubecontainer.Pods(pods).FindPod(podFullName, podUID)
		if pod.IsEmpty() {
			return nil, fmt.Errorf("pod not found (%q)", podFullName)
		}

		return streamingRuntime.GetPortForward(podName, podNamespace, podUID)
	default:
		return nil, fmt.Errorf("container runtime does not support port-forward")
	}
}

// cleanupOrphanedPodCgroups removes the Cgroups of pods that should not be
// running and whose volumes have been cleaned up.
func (kl *Kubelet) cleanupOrphanedPodCgroups(
	cgroupPods map[types.UID]cm.CgroupName,
	pods []*api.Pod, runningPods []*kubecontainer.Pod) error {
	// Add all running and existing terminated pods to a set allPods
	allPods := sets.NewString()
	for _, pod := range pods {
		allPods.Insert(string(pod.UID))
	}
	for _, pod := range runningPods {
		allPods.Insert(string(pod.ID))
	}

	pcm := kl.containerManager.NewPodContainerManager()

	// Iterate over all the found pods to verify if they should be running
	for uid, val := range cgroupPods {
		if allPods.Has(string(uid)) {
			continue
		}

		// If volumes have not been unmounted/detached, do not delete the cgroup in case so the charge does not go to the parent.
		if podVolumesExist := kl.podVolumesExist(uid); podVolumesExist {
			glog.V(3).Infof("Orphaned pod %q found, but volumes are not cleaned up, Skipping cgroups deletion: %v", uid)
			continue
		}
		glog.V(3).Infof("Orphaned pod %q found, removing pod cgroups", uid)
		// Destroy all cgroups of pod that should not be running,
		// by first killing all the attached processes to these cgroups.
		// We ignore errors thrown by the method, as the housekeeping loop would
		// again try to delete these unwanted pod cgroups
		go pcm.Destroy(val)
	}
	return nil
}

// enableHostUserNamespace determines if the host user namespace should be used by the container runtime.
// Returns true if the pod is using a host pid, pic, or network namespace, the pod is using a non-namespaced
// capability, the pod contains a privileged container, or the pod has a host path volume.
//
// NOTE: when if a container shares any namespace with another container it must also share the user namespace
// or it will not have the correct capabilities in the namespace.  This means that host user namespace
// is enabled per pod, not per container.
func (kl *Kubelet) enableHostUserNamespace(pod *api.Pod) bool {
	if hasPrivilegedContainer(pod) || hasHostNamespace(pod) ||
		hasHostVolume(pod) || hasNonNamespacedCapability(pod) || kl.hasHostMountPVC(pod) {
		return true
	}
	return false
}

// hasPrivilegedContainer returns true if any of the containers in the pod are privileged.
func hasPrivilegedContainer(pod *api.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil &&
			c.SecurityContext.Privileged != nil &&
			*c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

// hasNonNamespacedCapability returns true if MKNOD, SYS_TIME, or SYS_MODULE is requested for any container.
func hasNonNamespacedCapability(pod *api.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
			for _, cap := range c.SecurityContext.Capabilities.Add {
				if cap == "MKNOD" || cap == "SYS_TIME" || cap == "SYS_MODULE" {
					return true
				}
			}
		}
	}

	return false
}

// hasHostVolume returns true if the pod spec has a HostPath volume.
func hasHostVolume(pod *api.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}

// hasHostNamespace returns true if hostIPC, hostNetwork, or hostPID are set to true.
func hasHostNamespace(pod *api.Pod) bool {
	if pod.Spec.SecurityContext == nil {
		return false
	}
	return pod.Spec.SecurityContext.HostIPC || pod.Spec.SecurityContext.HostNetwork || pod.Spec.SecurityContext.HostPID
}

// hasHostMountPVC returns true if a PVC is referencing a HostPath volume.
func (kl *Kubelet) hasHostMountPVC(pod *api.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil {
			pvc, err := kl.kubeClient.Core().PersistentVolumeClaims(pod.Namespace).Get(volume.PersistentVolumeClaim.ClaimName)
			if err != nil {
				glog.Warningf("unable to retrieve pvc %s:%s - %v", pod.Namespace, volume.PersistentVolumeClaim.ClaimName, err)
				continue
			}
			if pvc != nil {
				referencedVolume, err := kl.kubeClient.Core().PersistentVolumes().Get(pvc.Spec.VolumeName)
				if err != nil {
					glog.Warningf("unable to retrieve pvc %s - %v", pvc.Spec.VolumeName, err)
					continue
				}
				if referencedVolume != nil && referencedVolume.Spec.HostPath != nil {
					return true
				}
			}
		}
	}
	return false
}
