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
	lock "k8s.io/kubernetes/pkg/util/lock"
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

	// Etcd subfolder for global locks
	EtcdGlobalFolder = "global/"

	// TTL for Etcd locks
	EtcdTTL = 120

	// replica-set name max length
	RSMaxNameLength = 6

	// keytab subdirectory within Pod's directory on the host
	KeytabDirForPod = "keytabs"

	// certs subdirectory within Pod's directory on the host
	CertsDirForPod = "certs"

	// location of ktutil
	KtutilPath = "/usr/bin/ktutil"

	// location of Heimdal ktutil
	HeimdalKtutilPath = "/opt/heimdal/bin/ktutil"

	// location of kimpersonate
	KImpersonatePath = "/root/kimpersonate"

	// local cert generator
	LocalCertGeneratorPath = "/root/generateCerts"

	//host keytab file
	HostKeytabFile = "/var/spool/keytabs/" + KeytabOwner

	//host certs directory
	HostCertsFile = "/var/spool/certs/" + CertsOwner

	// host directory for self-signed certificates
	HostSelfSignedCertsFile = "/var/spool/certs/self_signed"

	// host directory with pre-stashed Kerberos tickets
	HostPrestashedTktsDir = "/home/" + KeytabOwner + "/tickets/"

	// URL of the kubelet REST service (for callback)
	KubeletRESTServiceURL = "http://localhost:10255/refreshkeytabs"

	// ticket subdirectory within Pod's directory on the host
	TicketDirForPod = "tkt"

	// resolve.conf subdirectory within Pod's directory on the host
	ResolvePathForPod = "resolv.conf"

	// resolve.conf subdirectory within Pod's directory on the host
	ResolvePathInPod = "/etc/resolv.conf"

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

	// location of krb5 config file for extended skew option
	KRB5ConfFile = "/etc/krb5-extended-skew.conf"

	// location of chown binary
	ChownPath = "/bin/chown"

	// prefixes for logging
	TSL = "TSLOG "
	TSE = "TSERR "

	// TS extended manifest annotations
	TSPrestashTkt                = "ts/prestashtkt"
	TSServicesAnnotation         = "ts/services"
	TSExternalClustersAnnotation = "ts/externalclusters"
	TSTicketAnnotation           = "ts/ticket"
	TSTokenAnnotation            = "ts/token"
	TSRunAsUserAnnotation        = "ts/runasusername"
	TSCertsAnnotation            = "ts/certs"
	TSPrefixedHostnameAnnotation = "ts/userprefixedhostname"
	TSKrbLocal                   = "ts/krblocal"
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
	return pod.Namespace + "." + clusterDomain
}

// Get Kerberos KDC cluster name for the Pod
func GetPodKDCClusterNames(pod *api.Pod, clusterDomain string) (map[string]bool, error) {
	podKDCHostnames := make(map[string]bool)
	if userName, err := GetRunAsUsername(pod); err != nil {
		return podKDCHostnames, err
	} else {
		podKDCHostnames[pod.Name+"."+GetPodDomainName(pod, clusterDomain)] = true
		if prefixedHostname, ok := pod.ObjectMeta.Annotations[TSPrefixedHostnameAnnotation]; ok && prefixedHostname == "true" {
			podKDCHostnames[userName+"."+pod.Name+"."+GetPodDomainName(pod, clusterDomain)] = true
		}
		if externalClusters, ok := pod.ObjectMeta.Annotations[TSExternalClustersAnnotation]; ok && externalClusters != "" {
			for _, externalCluster := range strings.Split(externalClusters, ",") {
				podKDCHostnames[externalCluster] = true
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
func RegisterClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	defer clock.ExecTime(time.Now(), "registerClusterInKDC", clusterName)
	var lastErr error
	var lastOut []byte
	var retry int
	var err error
	var l *lock.Lock

	if mutex != nil {
		l, err = mutex.Acquire(EtcdGlobalFolder, "krb5_admin_createlogicalhost "+hostName+" "+clusterName, EtcdTTL)
		if err != nil {
			glog.Errorf(TSE+"error obtaining lock registering cluster %s during %d retry, error: %v",
				clusterName, retry, err)
			// attempt release to make sure no lock left
			if l != nil {
				l.Release()
			}
			return err
		} else {
			defer l.Release()
		}
	}

	for retry = 0; retry < MaxKrb5RetryCount; retry++ {
		out, err := RunCommand(Krb5adminPath, "create_logical_host", clusterName)
		if err != nil {
			if !strings.Contains(string(out), "already exists") {
				lastErr = err
				lastOut = out
				glog.V(2).Infof(TSL+"TSRETRY error registering cluster %s in KDC, will retry %d, error: %v, output: %v",
					clusterName, retry, err, string(out))
				time.Sleep(Krb5RetrySleepSec)
			} else {
				glog.V(4).Infof(TSL+"cluster %s is already in the KDC, not added", clusterName)
				return nil
			}
		} else {
			glog.V(5).Infof(TSL+"cluster %s was added to the KDC with output %s", clusterName, string(out))
			return nil
		}
	}
	glog.Errorf(TSE+"error registering cluster %s in KDC after %d retries, giving up, last error: %v, output: %v",
		clusterName, retry, lastErr, string(lastOut))
	return lastErr
}

func RunCommand(cmdToExec string, params ...string) ([]byte, error) {
	return RunCommandWithEnv(nil, cmdToExec, params...)
}

func RunCommandWithEnv(envArray []string, cmdToExec string, params ...string) ([]byte, error) {
	defer clock.ExecTime(time.Now(), "runCommand", cmdToExec)
	glog.V(5).Infof(TSL+"will exec %s %+v", cmdToExec, params)
	exe := utilexec.New()
	cmd := exe.Command(cmdToExec, params...)
	if envArray != nil {
		cmd.SetEnv(envArray)
	}
	return cmd.CombinedOutput()
}

// execute OS command with pipe
func ExecWithPipe(cmd1Str, cmd2Str string, par1, par2 []string) (bytes.Buffer, bytes.Buffer, error) {
	var o, e bytes.Buffer

	defer clock.ExecTime(time.Now(), "execWithPipe", cmd1Str+" "+cmd2Str)

	glog.V(4).Infof(TSL+"entering execWithPipe() cmd1 %s cmd2 %s", cmd1Str, cmd2Str)

	r, w := io.Pipe()

	cmd1 := exec.Command(cmd1Str, par1...)
	cmd2 := exec.Command(cmd2Str, par2...)

	cmd1.Stdout = w
	cmd2.Stdin = r
	cmd2.Stdout = &o
	cmd2.Stderr = &e

	if err := cmd1.Start(); err != nil {
		glog.Errorf(TSE+"unable to start command %s, error %+v", cmd1Str, err)
		return o, e, err
	}
	if err := cmd2.Start(); err != nil {
		glog.Errorf(TSE+"unable to start command %s, error %+v", cmd2Str, err)
		return o, e, err
	}

	go func() {
		defer w.Close()
		if err := cmd1.Wait(); err != nil {
			glog.Errorf(TSE+"error while waiting for the first command %s, error %+v", cmd1Str, err)
		}
	}()

	if err := cmd2.Wait(); err != nil {
		glog.Errorf(TSE+"error while waiting for the second command %s, error %+v", cmd2Str, err)
		return o, e, err
	}
	return o, e, nil
}

func RemoveHostFromClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	defer clock.ExecTime(time.Now(), "removeHostFromClusterInKDC", clusterName+" "+hostName)
	var lastErr error
	var lastOut []byte
	var retry int
	var err error
	var out []byte
	var l *lock.Lock

	// check if the node is a member of the KDC cluster
	// it may not be if the Pod is being deleted just after creation (and the Kerberos objects were not created yet)
	memberNodes, err := getKDCMemberNodes(clusterName)
	if err != nil {
		return err
	}
	if !strings.Contains(memberNodes, hostName) {
		glog.V(4).Infof(TSL+"cluster %s has no member %s, no need to remove", clusterName, hostName)
		return nil
	}

	if mutex != nil {
		l, err = mutex.Acquire(EtcdGlobalFolder, "krb5_admin_removehostmap "+hostName+" "+clusterName, EtcdTTL)
		if err != nil {
			glog.Errorf(TSE+"error obtaining lock while removing host %s from cluster %s during %d retry, error: %v",
				hostName, clusterName, retry, err)
			// attempt release to make sure no lock left
			if l != nil {
				l.Release()
			}
			return err
		} else {
			defer l.Release()
		}
	}

	// remove the node hostName from the KDC cluster
	for retry = 0; retry < MaxKrb5RetryCount; retry++ {
		out, err = RunCommand(Krb5adminPath, "remove_hostmap", clusterName, hostName)
		if err != nil {
			lastErr = err
			lastOut = out
			glog.V(2).Infof(TSL+"TSRETRY error removing host %s from cluster %s in KDC, will retry %d, error: %v, output: %v",
				hostName, clusterName, retry, err, string(out))
			time.Sleep(Krb5RetrySleepSec)
		} else {
			glog.V(5).Infof(TSL+"removeHostFromClusterInKDC() returned output %s with no error", string(out))
			return nil
		}
	}
	glog.Errorf(TSE+"error removing host %s from cluster %s in KDC after %d retries, giving up, error: %v, output: %v",
		hostName, clusterName, retry, lastErr, string(lastOut))
	return lastErr
}

func getKDCMemberNodes(clusterName string) (string, error) {
	// krb5_admin query_host <cluster_name> | awk '($1=="member:"){print $2;}'
	outb, errb, err := ExecWithPipe(
		Krb5adminPath,
		"awk",
		[]string{"query_host", clusterName},
		[]string{"-v", "p=member:", "($1==p){print $2;}"})
	if err != nil {
		glog.Errorf(TSE+"exec with pipe failed while cleaning service cluster %s in KDC, error %v, errb %s, outb %s",
			clusterName, err, errb.String(), outb.String())
		return "", err
	}
	if errb.Len() > 0 {
		glog.Errorf(TSE+"unable to list members of cluster %s in KDC, out %+v, error %+v", clusterName, outb.String(), errb.String())
		return "", goerrors.New(outb.String() + " " + errb.String())
	}
	memberNodes := strings.Trim(outb.String(), "\n")
	return memberNodes, nil
}

// remove all member nodes from the service cluster in KDC
// This is invoked when service is deleted
func CleanServiceInKDC(clusterName string) error {
	defer clock.ExecTime(time.Now(), "CleanServiceInKDC", clusterName)

	var lastErr error
	lastErr = nil

	memberNodes, err := getKDCMemberNodes(clusterName)
	if err != nil {
		return err
	}
	if memberNodes != "" {
		glog.V(4).Infof(TSL+"retrieved members of cluster %s are %+v", clusterName, memberNodes)
	} else {
		// nothing to clean-up
		return nil
	}

	for _, nodeName := range strings.Split(memberNodes, ",") {
		glog.V(4).Infof(TSL+"removing node %s from cluster %s in KDC", nodeName, clusterName)
		if err := RemoveHostFromClusterInKDC(clusterName, nodeName, nil); err != nil {
			lastErr = err
			glog.Errorf(TSE+"error while removing node %s from KDC cluster %s, error %v", nodeName, clusterName, err)
		} else {
			glog.V(4).Infof(TSL+"node %s removed from cluster %s in KDC", nodeName, clusterName)
		}
	}
	if lastErr != nil {
		glog.Errorf(TSE+"error while removing one of the nodes from KDC cluster %s, error %v", clusterName, lastErr)
		return lastErr
	} else {
		return nil
	}
}

func CheckIfHostInInKDCCluster(clusterName, hostName string) (bool, error) {
	var err error
	var out []byte

	out, err = RunCommand(Krb5adminPath, "query_host", clusterName)
	if err != nil {
		glog.Errorf(TSL+"TSERR error query_host for cluster %s, error: %v, output: %v", clusterName, err, string(out))
		return false, err
	} else {
		if strings.Contains(string(out), hostName) {
			return true, nil
		} else {
			return false, nil
		}
	}
}

// Add node on which the kubelet runs to the KDC cluster
func AddHostToClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	defer clock.ExecTime(time.Now(), "addHostToClusterInKDC", clusterName+" "+hostName)
	var lastErr error
	var lastOut []byte
	var retry int
	var err error
	var out []byte
	var l *lock.Lock

	if mutex != nil {
		l, err = mutex.Acquire(EtcdGlobalFolder, "krb5_admin_addhost "+hostName+" "+clusterName, EtcdTTL)
		if err != nil {
			glog.Errorf(TSE+"error obtaining lock while adding host %s to cluster %s during %d retry, error: %v",
				hostName, clusterName, retry, err)
			// attempt release to make sure no lock left
			if l != nil {
				l.Release()
			}
			return err
		} else {
			defer l.Release()
		}
	}

	for retry = 0; retry < MaxKrb5RetryCount; retry++ {
		out, err = RunCommand(Krb5adminPath, "insert_hostmap", clusterName, hostName)
		if err != nil {
			if !strings.Contains(string(out), "is already in cluster") {
				lastErr = err
				lastOut = out
				glog.V(2).Infof(TSL+"TSRETRY error adding host %s to cluster %s in KDC, will retry %d, error: %v, output: %v",
					hostName, clusterName, retry, err, string(out))
				time.Sleep(Krb5RetrySleepSec)
			} else {
				glog.V(2).Infof(TSL+"host %s is already in the cluster %s, not added", hostName, clusterName)
				return nil
			}
		} else {
			glog.V(5).Infof(TSL+"host %s was added to cluster %s with output %s", hostName, clusterName, string(out))
			return nil
		}
	}
	glog.Errorf(TSE+"error adding host %s to cluster %s in KDC after %d retries, giving up, error: %v, output: %v",
		hostName, clusterName, retry, lastErr, string(lastOut))
	return lastErr
}

func SetAnnotation(pod *api.Pod, key, value string) {
	if pod.ObjectMeta.Annotations == nil {
		pod.ObjectMeta.Annotations = map[string]string{}
	}
	pod.ObjectMeta.Annotations[key] = value
}
