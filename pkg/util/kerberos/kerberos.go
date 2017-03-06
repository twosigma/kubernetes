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

package pod

import (
	"bytes"
	goerrors "errors"
	"io"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/util/clock"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
)

// constants used by Kerberos extensions
const (
	// TODO: keytab owner, realm, and group should be parameters passed externally
	// user that we want to own Kerberos keytab file
	KeytabOwner = "tsk8s"

	CertsOwner = "root"

	// ticket file user group
	TicketUserGroup = "twosigma"

	// Kerberos realm
	KerberosRealm = "N.TWOSIGMA.COM"

	// keytab subdirectory within Pod's directory on the host
	KeytabDirForPod = "keytabs"

	// certs subdirectory within Pod's directory on the host
	CertsDirForPod = "certs"

	// location of ktutil
	KtutilPath = "/usr/bin/ktutil"

	//host keytab file
	HostKeytabFile = "/var/spool/keytabs/" + KeytabOwner

	//host certs directory
	HostCertsFile = "/var/spool/certs/" + CertsOwner

	// host directory with pre-stashed Kerberos tickets
	HostPrestashedTktsDir = "/home/" + KeytabOwner + "/tickets/"

	// URL of the kubelet REST service (for callback)
	KubeletRESTServiceURL = "http://localhost:10255/refreshkeytabs"

	// ticket subdirectory within Pod's directory on the host
	TicketDirForPod = "tkt"

	// keytab path inside of Pod
	KeytabPathInPod = "/var/spool/keytabs"

	// certs path inside of Pod
	CertsPathInPod = "/var/spool/certs/"

	// directory to store ticket file inside of the Pod
	TicketDirInPod = "/var/spool/tickets"

	// krb5_admin binary
	Krb5adminPath = "/usr/bin/krb5_admin"

	// krb5_keytab binary
	Krb5keytabPath = "/usr/sbin/krb5_keytab"

	// pwdb binary
	PwdbPath = "/usr/bin/pwdb"

	// location to generate ACL files for krb5_keytab delegation
	Krb5keytabAclDir = "/etc/krb5/krb5_keytab.service2user.d/"

	// location of gss-token binary
	GsstokenPath = "/usr/local/bin/gss-token"

	// location of chown binary
	ChownPath = "/bin/chown"

	// TS extended manifest annotations
	TSPrestashTkt                = "ts/prestashtkt"
	TSServicesAnnotation         = "ts/services"
	TSExternalClustersAnnotation = "ts/externalclusters"
	TSTicketAnnotation           = "ts/ticket"
	TSTokenAnnotation            = "ts/token"
	TSRunAsUserAnnotation        = "ts/runasusername"
	TSCertsAnnotation            = "ts/certs"
	TSPrefixedHostnameAnnotation = "ts/userprefixedhostname"
)

// Retrieve username of security context user based on userid
func GetRunAsUsername(pod *api.Pod) (string, error) {
	runAsUser := pod.Spec.SecurityContext.RunAsUser
	if runAsUser == nil {
		return "", goerrors.New("runAsUser is not set for Pod " + pod.Name)
	}

	uid := strconv.Itoa(int(*runAsUser))
	if user, err := user.LookupId(uid); err != nil {
		// LookupId failed, fall back to getent
		exe := utilexec.New()
		out, e2 := exe.Command("/usr/bin/getent", "passwd", uid).CombinedOutput()
		if e2 != nil || strings.TrimSpace(string(out)) == "" {
			return "", err
		}
		// assume the first
		res := strings.Split(string(out), ":")
		return res[0], nil
	} else {
		return user.Username, nil
	}
}

// Get domain name of the Pod (additional one allowing to address Pod's by their name)
// kube-dns has been modified to register these names in skydns
func GetPodDomainName(pod *api.Pod, clusterDomain string) string {
	return pod.Namespace + ".pods." + clusterDomain
}

// Get Kerberos KDC cluster name for the Pod
func GetPodKDCClusterNames(pod *api.Pod, clusterDomain string) ([]string, error) {
	podKDCHostnames := []string{}
	if userName, err := GetRunAsUsername(pod); err != nil {
		return []string{}, err
	} else {
		podKDCHostnames = append(podKDCHostnames, pod.Name+"."+GetPodDomainName(pod, clusterDomain))
		if prefixedHostname, ok := pod.ObjectMeta.Annotations[TSPrefixedHostnameAnnotation]; ok && prefixedHostname == "true" {
			podKDCHostnames = append(podKDCHostnames, userName+"."+pod.Name+"."+GetPodDomainName(pod, clusterDomain))
		}
		if externalClusters, ok := pod.ObjectMeta.Annotations[TSExternalClustersAnnotation]; ok && externalClusters != "" {
			for _, externalCluster := range strings.Split(externalClusters, ",") {
				podKDCHostnames = append(podKDCHostnames, externalCluster)
			}
		}
		return podKDCHostnames, nil
	}
}

const (
	// max number oif retries when calling Kerbereos utility functions
	MaxKrb5RetryCount = 5
	Krb5RetrySleepSec = 2 * time.Second
)

// Register the cluster in Kerberos KDC
func RegisterClusterInKDC(clusterName string) error {
	defer clock.ExecTime(time.Now(), "registerClusterInKDC", clusterName)
	var lastErr error
	var lastOut []byte
	var retry int
	for retry = 0; retry < MaxKrb5RetryCount; retry++ {
		if out, err := RunCommand("/usr/bin/krb5_admin", "create_logical_host", clusterName); err != nil {
			if !strings.Contains(string(out), "already exists") {
				lastErr = err
				lastOut = out
				glog.Errorf("error registering cluster %s in KDC, will retry %d, error: %v, output: %v",
					clusterName, retry, err, string(out))
				time.Sleep(Krb5RetrySleepSec)
			} else {
				glog.V(4).Infof("cluster %s is already in the KDC, not added", clusterName)
				return nil
			}
		} else {
			glog.V(5).Infof("cluster %s was added to the KDC with output %s", clusterName, string(out))
			return nil
		}
	}
	glog.Errorf("error registering cluster %s in KDC after %d retries, giving up, last error: %v, output: %v",
		clusterName, retry, lastErr, string(lastOut))
	return lastErr
}

func RunCommand(cmdToExec string, params ...string) ([]byte, error) {
	defer clock.ExecTime(time.Now(), "runCommand", cmdToExec)
	glog.V(4).Infof("will exec %s %+v", cmdToExec, params)
	exe := utilexec.New()
	cmd := exe.Command(cmdToExec, params...)
	return cmd.CombinedOutput()
}

// execute OS command with pipe
func ExecWithPipe(cmd1Str, cmd2Str string, par1, par2 []string) (bytes.Buffer, bytes.Buffer, error) {
	var o, e bytes.Buffer

	defer clock.ExecTime(time.Now(), "execWithPipe", cmd1Str+" "+cmd2Str)

	glog.V(4).Infof("entering execWithPipe() cmd1 %s cmd2 %s", cmd1Str, cmd2Str)

	r, w := io.Pipe()

	cmd1 := exec.Command(cmd1Str, par1...)
	cmd2 := exec.Command(cmd2Str, par2...)

	cmd1.Stdout = w
	cmd2.Stdin = r
	cmd2.Stdout = &o
	cmd2.Stderr = &e

	if err := cmd1.Start(); err != nil {
		glog.Errorf("unable to start command %s, error %+v", cmd1Str, err)
		return o, e, err
	}
	if err := cmd2.Start(); err != nil {
		glog.Errorf("unable to start command %s, error %+v", cmd2Str, err)
		return o, e, err
	}

	go func() {
		defer w.Close()
		if err := cmd1.Wait(); err != nil {
			glog.Errorf("error while waiting for the first command %s, error %+v", cmd1Str, err)
		}
	}()

	if err := cmd2.Wait(); err != nil {
		glog.Errorf("error while waiting for the second command %s, error %+v", cmd2Str, err)
		return o, e, err
	}
	return o, e, nil
}

func RemoveHostFromClusterInKDC(clusterName, hostName string) error {
	defer clock.ExecTime(time.Now(), "removeHostFromClusterInKDC", clusterName+" "+hostName)
	var lastErr error
	var lastOut []byte
	var retry int
	for retry = 0; retry < MaxKrb5RetryCount; retry++ {
		if out, err := RunCommand("/usr/bin/krb5_admin", "remove_hostmap", clusterName, hostName); err != nil {
			lastErr = err
			lastOut = out
			glog.Errorf("error removing host %s from cluster %s in KDC, will retry %d, error: %v, output: %v",
				hostName, clusterName, retry, err, string(out))
			time.Sleep(Krb5RetrySleepSec)
		} else {
			glog.V(5).Infof("removeHostFromClusterInKDC() returned output %s with no error", string(out))
			return nil
		}
	}
	glog.Errorf("error removing host %s from cluster %s in KDC after %d retries, giving up, error: %v, output: %v",
		hostName, clusterName, retry, lastErr, string(lastOut))
	return lastErr
}

// remove all member nodes from the service cluster in KDC
// This is invoked when service is deleted
func CleanServiceInKDC(clusterName string) error {
	// krb5_admin query_host <cluster_name> | awk '($1=="member:"){print $2;}'
	outb, errb, err := ExecWithPipe(
		"/usr/bin/krb5_admin",
		"awk",
		[]string{"query_host", clusterName},
		[]string{"-v", "p=member:", "($1==p){print $2;}"})
	if err != nil {
		glog.Errorf("exec with pipe failed while cleaning service cluster %s in KDC, error %v, errb %s, outb %s",
			clusterName, err, errb.String(), outb.String())
		return err
	}
	if errb.Len() > 0 {
		glog.Errorf("unable to list members of cluster %s in KDC, out %+v, error %+v", clusterName, outb.String(), errb.String())
		return goerrors.New(outb.String() + " " + errb.String())
	} else {
		glog.V(4).Infof("retrieved members of cluster %s are %+v", clusterName, outb.String())
	}
	memberNodes := strings.Trim(outb.String(), "\n")
	var lastErr error
	lastErr = nil
	for _, nodeName := range strings.Split(memberNodes, ",") {
		glog.V(4).Infof("removing node %s from cluster %s in KDC", nodeName, clusterName)
		if err := RemoveHostFromClusterInKDC(clusterName, nodeName); err != nil {
			lastErr = err
			glog.Errorf("error while removing node %s from KDC cluster %s, error %v", nodeName, clusterName, err)
		} else {
			glog.V(4).Infof("node %s removed from cluster %s in KDC", nodeName, clusterName)
		}
	}
	if lastErr != nil {
		glog.Errorf("error while removing one of the nodes from KDC cluster %s, error %v", clusterName, lastErr)
		return lastErr
	} else {
		return nil
	}
}
