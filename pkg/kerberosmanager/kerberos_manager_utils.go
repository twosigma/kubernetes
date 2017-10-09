/*
Utility functions supporting Kerberos management.
*/
package kerberosmanager

import (
	"bytes"
	"errors"
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

// GetRunAsUsername() retrieves username of security context user based on userid
//
// Paramaters:
// - pod - pod to get the username for
//
// Return:
// - username and error, if failed
func GetRunAsUsername(pod *api.Pod) (string, error) {
	// get user ID from pod security context
	if pod.Spec.SecurityContext == nil {
		return "", errors.New("security context not defined for Pod " + pod.Namespace + "/" + pod.Name)
	}
	runAsUser := pod.Spec.SecurityContext.RunAsUser
	if runAsUser == nil {
		return "", errors.New("runAsUser is not set for Pod " + pod.Namespace + "/" + pod.Name)
	}

	// attempt to lookup ID
	uid := strconv.Itoa(int(*runAsUser))
	if user, err := user.LookupId(uid); err != nil {
		// LookupId failed, fall back to getent
		out, e2 := RunCommand("/usr/bin/getent", "passwd", uid)
		if e2 != nil || strings.TrimSpace(string(out)) == "" {
			return "", err
		} else {
			// assume the first
			res := strings.Split(string(out), ":")
			return res[0], nil
		}
	} else {
		return user.Username, nil
	}
}

// RunCommand() executes command with parameters
//
// Paramaters:
// - cmdToExec - command to execute
// - params - string slice with parameters
//
// Return:
// - output in byte array and error, if failed
func RunCommand(cmdToExec string, params ...string) ([]byte, error) {
	return RunCommandWithEnv(nil, cmdToExec, params...)
}

// RunCommandWithEnv() executes command with parameters and environment variables set
//
// Paramaters:
// - envArray - array with environment variables
// - cmdToExec - command to execute
// - params - string slice with parameters
//
// Return:
// - output in byte array and error, if failed
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

// ExecWithPipe() executes command with parameters and pipes the output into another command
//
// Paramaters:
// - cmd1Str - first command to execute
// - par1 - string slice with parameters for the first command
// - cmd2Str - second command to execute
// - par2 - string slice with parameters for the second command
//
// Return:
// - std output in byte array, std error in byte array and error, if failed
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

// RetryFunction() retries the function call with exponential back-off. The retry count and delay are
// determined based on global constants.
//
// Parameters:
// - fn - function to execute
// Return:
// - error, if all retries failed
func RetryFunction(fn func(count int) error) error {
	var err error
	sleepTime := Krb5RetrySleepSec
	for retry := 0; retry < MaxKrb5RetryCount; retry++ {
		if err = fn(retry); err != nil {
			time.Sleep(sleepTime)
			sleepTime *= 2
		} else {
			return nil
		}
	}
	return err
}

// Filter() returns a list of strings for which a function returns true.
//
// Paramaters:
// - vs - string array to filter
// - f - function handler to apply to the array elements to filter the strings
// Return:
// - string array containing only the strings for which the function returns true
func Filter(vs []string, f func(string) bool) []string {
	vsf := make([]string, 0)
	for _, v := range vs {
		if f(v) {
			vsf = append(vsf, v)
		}
	}
	return vsf
}

// CopyFile(0 copies files using OS level cp function. It works only on POSIX unix,
// but doing the copy preserves the inode of the file (which if required to preserve
// the bindmount)
//
// Parameters:
// - src - path to source file
// - dst - path to the destination file
//
// Return:
// - error, if failed
//
// NOTE: could use os.Rename and bindmounting entire directory instead of the file
//       that can have security implications, so staying with bindmount of file
func CopyFile(src, dest string) error {
	exe := utilexec.New()
	cmd := exe.Command(
		"/bin/cp",
		"-f",
		src,
		dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Errorf(TSE+"unable to copy %s to %s ticket: %s %v", src, dest, out, err)
		return err
	} else {
		return nil
	}
}

// GetPodDomainName() gets domain name of the Pod (additional one allowing to address Pod's by their name)
// kube-dns has been modified to register these names in skydns
//
// Parameters:
// - pod - pod to get DNS name for
// - clusterDomain - DNS suffix of the cluster name
//
// Return:
// - domain name of the DNS name of the pod
func GetPodDomainName(pod *api.Pod, clusterDomain string) string {
	return pod.Namespace + "." + clusterDomain
}

// GetPodKDCClusterNames() gets Kerberos KDC cluster names for the pod. These include DNS name of the pod itself,,
// that of user prefixed DNS name (for TS special use case) and also all external clusters declared in the manifest
// using ts/externalclusters annotation.
//
// Parameters:
// - pod - pod to get KDC cluster names for
// - clusterDomain - DNS suffix of the cluster name
//
// Return:
// - map with DNS names of the KDC clusters that the pod belongs to and error, if failed
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
