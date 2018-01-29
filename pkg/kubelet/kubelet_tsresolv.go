/*
This file contains routines used by kubelet to create TS custom resolv.conf file
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

	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
)

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
		buffer.WriteString("options ndots:2\n")
		buffer.WriteString("options timeout:1\n")
		buffer.WriteString("options attempts:5\n")
		buffer.WriteString("options edns0\n")

		return ioutil.WriteFile(resolveFilePath, buffer.Bytes(), 0644)
	} else {
		glog.Errorf(krbutils.TSE + "error getting DNS servers")
		return errors.New("Could not get DNS server IPs from host resolv.conf ")
	}
}
