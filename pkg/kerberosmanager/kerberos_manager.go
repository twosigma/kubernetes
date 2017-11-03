/*
This package contains interface definition and implementations of functions
managing Kerberos objects (tickets, keytabs, SSL certificates, KDC cluster
memberships). It is used to set up requested Kerberos state in pods.
*/
package kerberosmanager

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/util/clock"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
	lock "k8s.io/kubernetes/pkg/util/lock"
)

const (
	// TS extended manifest annotations used to request Kerberos objects
	TSPrestashTkt                = "ts/prestashtkt"
	TSServicesAnnotation         = "ts/services"
	TSExternalClustersAnnotation = "ts/externalclusters"
	TSTicketAnnotation           = "ts/ticket"
	TSTokenAnnotation            = "ts/token"
	TSRunAsUserAnnotation        = "ts/runasusername"
	TSCertsAnnotation            = "ts/certs"
	TSPrefixedHostnameAnnotation = "ts/userprefixedhostname"
	TSKrbLocal                   = "ts/krblocal"
	TSReverseHostsOrder          = "ts/reversehostsorder"

	// etcd locking related consts
	// Etcd subfolder for global locks
	EtcdGlobalFolder = "global/"
	// TTL for Etcd locks
	EtcdTTL = 120

	// root of Kerberos object directories on hosts
	KerberosObjectRootDefault = "/var/spool/"

	// ticket related consts
	//
	// ticket subdirectory within Pod's directory on the host
	TicketDirForPod = "tkt"
	// number of seconds that kimpersonate tickets expire after (3 days)
	LocalTicketExpirationSec = 72 * 3600
	// directory to store ticket file inside of the Pod
	TicketDirInPod = "/var/spool/tickets"
	// location of krb5 config file for extended ticket skew option
	KRB5ConfFile = "/etc/krb5-extended-skew.conf"

	// keytab related consts
	//
	// keytab subdirectory within Pod's directory on the host
	KeytabDirForPod = "keytabs"
	// keytab path inside of Pod
	KeytabPathInPod = "/var/spool/keytabs"
	// host keytab folder
	HostKeytabDirDefault = "/var/spool/keytabs/"

	// certs related consts
	//
	// certs subdirectory within Pod's directory on the host
	CertsDirForPod = "certs"
	// host directory for self-signed certificates
	HostSelfSignedCertsFile = "/var/spool/certs/self_signed"
	// certs path inside of Pod
	CertsPathInPod = "/var/spool/certs/"
	// host certs folder
	HostCertsDirDefault = "/var/spool/certs/"

	// paths to krb binaries on hosts
	//
	// location of ktutil
	KtutilPath = "/usr/bin/ktutil"
	// location of Heimdal ktutil
	HeimdalKtutilPath = "/opt/heimdal/bin/ktutil"
	// location of kimpersonate
	KImpersonatePath = "/root/kimpersonate"
	// local cert generator
	LocalCertGeneratorPath = "/root/generateCerts"
	// krb5_admin binary
	Krb5adminPath = "/usr/bin/krb5_admin"
	// krb5_keytab binary
	Krb5keytabPath = "/usr/sbin/krb5_keytab"
	// pwdb binary
	PwdbPath = "/usr/bin/pwdb"
	// location of gss-token binary
	GsstokenPath = "/usr/local/bin/gss-token"
	// location of chown binary
	ChownPath = "/bin/chown"

	// resolv.conf related consts
	//
	// resolve.conf subdirectory within Pod's directory on the host
	ResolvePathForPod = "resolv.conf"
	// resolve.conf subdirectory within Pod's directory on the host
	ResolvePathInPod = "/etc/resolv.conf"

	// other consts
	//
	// prefixes for logging
	TSL = "TSLOG "
	TSE = "TSERR "
	// URL of the kubelet REST service (for callback)
	KubeletRESTServiceURL = "http://localhost:10255/refreshkeytabs"
	// location to generate ACL files for krb5_keytab delegation
	Krb5keytabAclDir = "/etc/krb5/krb5_keytab.service2user.d/"
	// this option should be removed (no need for cgroups control)
	CgroupOwnerGroup = "tsk8s"
	// max number of retries when calling Kerbereos utility functions
	// it is used of exponential back-off in retry function
	MaxKrb5RetryCount = 6
	Krb5RetrySleepSec = 2 * time.Second
	// replica-set name max length
	RSMaxNameLength = 6

	// NOTE: the 4 consts below are used as defaults if not provided
	// when creating the interface
	KeytabOwnerDefault     = "tsk8s"
	CertsOwnerDefault      = "root"
	TicketUserGroupDefault = "twosigma"
	KerberosRealmDefault   = "N.TWOSIGMA.COM"
)

// parameters structure for the Keberos manager
type KrbManagerParameters struct {
	// etcd configuration for locking
	TSLockEtcdServerList []string
	TSLockEtcdCertFile   string
	TSLockEtcdKeyFile    string
	TSLockEtcdCAFile     string

	// owner of the keytab file on the host
	KeytabOwner string
	// certificate file owner on the host
	CertsOwner string
	// ticket file user group
	TicketUserGroup string
	// Kerberos realm
	KerberosRealm string
	// location of keytab, certs, and prestash tickets on hosts
	HostKeytabFile        string
	HostCertsFile         string
	HostPrestashedTktsDir string
}

// interface to Kerberos subsystem and related support functions
// the functions are implemented as call-outs to a set of Kerberos utilities,
// specifically:
// - krb5_admin
// - krb5_keytab
// - pwdb cert
// - gss-token
type KrbManager interface {
	// Kerberos ticket management
	EncryptTicket(tokenFile, destHost string) (string, error)
	PrepareEncryptedTicket(assumed *api.Pod, destHost string) error
	DecryptTicket(dest, data, user, group string, pod *api.Pod) error
	AddKimpersonateTicket(dest, user, realm, principal, podKeytabFile string) error

	// KDC cluster management
	RegisterClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error
	AddHostToClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error
	CheckIfHostInKDCCluster(clusterName, hostName string) (bool, error)
	RemoveHostFromClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error
	CleanServiceInKDC(clusterName string) error

	// Kerberos keytab requesting
	SetupKrbACLFile(srv, clusterName string) error
	RequestKey(srv, clusterName string, mutex *lock.Mutex, hostname string) error
	CreateLocalKey(podKeytabFile, principal string) error
	GetKeyVersionsFromKeytab(keytabFilePath string) (map[string]int, map[string]bool, map[string]int, error)

	// Kerberos pwdb SSL cert management functions
	GetPwdbSSLCert(clusterName string) error
	GetSelfSignedSSLCert(clusterName string) error

	// config access and support functions
	GetKeytabOwner() string
	GetCertsOwner() string
	GetTicketUserGroup() string
	GetKerberosRealm() string
	GetHostKeytabFile() string
	GetHostCertsFile() string
	GetHostPrestashedTktsDir() string
	ChangeFileOwnership(file, user, group string) error
}

// Kerberos manager object
type KerberosManager struct {
	// params for etcd connections for locking
	TSLockEtcdServerList []string
	TSLockEtcdCertFile   string
	TSLockEtcdKeyFile    string
	TSLockEtcdCAFile     string

	// params of the Kerberos configuration on hosts
	// owner of the keytab file on the host
	KeytabOwner string
	// certificate file owner on the host
	CertsOwner string
	// ticket file user group
	TicketUserGroup string
	// Kerberos realm
	KerberosRealm string
	// location of keytabs, certs nd tickets on the host
	HostKeytabFile        string
	HostCertsFile         string
	HostPrestashedTktsDir string
}

// setDefaults() sets default values (as defined in teh structure default annotations)
// to the parameters that were not set
//
// Parameters:
// - config - config structure to set defaults for
//
// Return:
// - nothing, the structure gets modified
func setDefaults(config *KrbManagerParameters) {
	if config.KeytabOwner == "" {
		config.KeytabOwner = KeytabOwnerDefault
	}
	if config.CertsOwner == "" {
		config.CertsOwner = CertsOwnerDefault
	}
	if config.TicketUserGroup == "" {
		config.TicketUserGroup = TicketUserGroupDefault
	}
	if config.KerberosRealm == "" {
		config.KerberosRealm = KerberosRealmDefault
	}
	if config.HostKeytabFile == "" {
		config.HostKeytabFile = HostKeytabDirDefault + config.KeytabOwner
	}
	if config.HostCertsFile == "" {
		config.HostCertsFile = HostCertsDirDefault + config.CertsOwner
	}
}

// constructor that initializes the Kerberos manager with the etcd locking configuration
func NewKerberosManager(config KrbManagerParameters) (*KerberosManager, error) {
	// set default values for unset config params
	setDefaults(&config)
	return &KerberosManager{
		TSLockEtcdServerList:  config.TSLockEtcdServerList,
		TSLockEtcdCertFile:    config.TSLockEtcdCertFile,
		TSLockEtcdKeyFile:     config.TSLockEtcdKeyFile,
		TSLockEtcdCAFile:      config.TSLockEtcdCAFile,
		KeytabOwner:           config.KeytabOwner,
		CertsOwner:            config.CertsOwner,
		TicketUserGroup:       config.TicketUserGroup,
		KerberosRealm:         config.KerberosRealm,
		HostKeytabFile:        config.HostKeytabFile,
		HostCertsFile:         config.HostCertsFile,
		HostPrestashedTktsDir: "/home/" + config.KeytabOwner + "/tickets/",
	}, nil
}

// EncryptTicket() encrypts the ticket using destination host's public key, specifically:
//    KRB5CCNAME=<path-to-ticket> gss-token -D <user>@<pod's-host>
// NOTE: gss-token emits the encrypted ticket to standard output
//
// Parameters:
// - tokenFile - file containing ticket to encrypt
// - destHost - destination host (to pick appropriate encrytpion key)
//
// Return:
// - touple of encrypted ticket and error, if failed
func (km *KerberosManager) EncryptTicket(tokenFile, destHost string) (string, error) {
	env := fmt.Sprintf("KRB5CCNAME=%s", tokenFile)
	exe := utilexec.New()
	cmd := exe.Command(
		GsstokenPath,
		"-D",
		fmt.Sprintf("%s@%s", km.KeytabOwner, destHost))
	cmd.SetEnv([]string{env})
	out, err := cmd.CombinedOutput()
	if err == nil {
		glog.V(5).Infof(TSL+"token created: %s", out)
		return string(out), nil
	} else {
		glog.Errorf(TSE+"token generation failed: %v; output: %v; dest=%v; env=%v",
			err, string(out), destHost, env)
		return "", err
	}
}

// PrepareEncryptedTicket() checks is pod needs Kerberos tickets and, if so, prepares the
// required ticket and places it in the manifest. It is invoked from pod scheduler.
// Specifically:
// 1. If pod has ts/token annotation containing encrypted ticket. if it does, decrypt
//    the ticket with master node's private key, re-encrypt with the destHost public key,
//    and place in the pod manifest ts/ticket annotation.
// 2. Otherwise, if pod has ts/prestashtkt annotation and also ts/runasuser annotation then
//    pick up the ticket from the pre-stash folder, encrypt with the destHost public key,
//    and place in the pod manifest ts/ticket annotation.
// After this, the function return modified pod manifest (with the encrypted ticket) to
// scheduler. The manifest is then picked up by a kubelet running on destHost and acted upon.
// The kubelet decrypts the ticket (using the private key of the destHost on which it runs)
// and deposits the decrypted ticket in pod's filesystem.
//
// Parameters:
// - assumed - pod to be processed
// - destHost - DNS name of the destination host on which the pod is scheduled to run
//
// Return:
// - error, if failed
func (km *KerberosManager) PrepareEncryptedTicket(assumed *api.Pod, destHost string) error {
	// path to temporary file with the ticket
	tokenFilePath := ""

	// check if pod already has a token (encrypted ticket) included
	// this takes precedence over prestashed tickets
	if token, ok := assumed.ObjectMeta.Annotations[TSTokenAnnotation]; ok {
		glog.V(4).Infof(TSL+"got annotation %s for pod %s/%s", TSTokenAnnotation, assumed.Namespace, assumed.Name)
		// create temporary file to hold decrypted token
		file, err := ioutil.TempFile(os.TempDir(), "k8s-token")
		if err != nil {
			glog.Errorf(TSE+"failed to create tmp file: error %v", err)
			return err
		} else {
			tmpFile := file.Name()
			defer os.Remove(tmpFile)
			// decrypt the token with the host's private key
			env := "KRB5_KTNAME=" + km.HostKeytabFile
			exe := utilexec.New()
			cmd := exe.Command(
				GsstokenPath,
				"-r",
				"-C",
				tmpFile)
			cmd.SetEnv([]string{env})
			stdin, err := cmd.StdinPipe()
			if err != nil {
				glog.Errorf(TSE+"unable to obtain stdin of child process: %v", err)
				return err
			} else {
				io.WriteString(stdin, token+"\n")
				stdin.Close()
				out, err := cmd.CombinedOutput()
				if err == nil {
					tokenFilePath = tmpFile
					glog.Infof(TSL+"token decrypted successfully to %s for %s/%s, output %v", tmpFile,
						assumed.Namespace, assumed.Name, out)
				} else {
					glog.Errorf(TSE+"unable to decode token for %s/%s, output %v, error %v",
						assumed.Namespace, assumed.Name, out, err)
					return err
				}
			}
		}
	} else if user, ok := assumed.ObjectMeta.Annotations[TSRunAsUserAnnotation]; ok {
		if assumed.ObjectMeta.Annotations[TSPrestashTkt] == "true" {
			// no ts/token annotation and ts/runasuser are present, so we use prestashed ticket and encrypt
			glog.Infof(TSL+"got %s=%s, KerberosRealm=%s, trying to create token from prestashed ticket",
				TSRunAsUserAnnotation, user, km.KerberosRealm)
			tktPath := fmt.Sprintf(km.HostPrestashedTktsDir+"@%s/%s", km.KerberosRealm, user)
			if _, err := os.Stat(tktPath); os.IsNotExist(err) {
				glog.Errorf(TSE+"prestashed ticket for %s@%s does not exist", user, km.KerberosRealm)
				return err
			} else {
				// set the token file to point at the prestashed ticket (it is not encrypted)
				tokenFilePath = tktPath
			}
		}
	}

	// if a ticket is provided, encrypt it with the key of the host on which the pod is scheduled to run
	// and put the encryptet ticket in the pod annotation. Kubelet will extract this encryptet ticket,
	// decrypt with its host's private key, and deposit in pod's filesystem.
	if tokenFilePath != "" {
		if encryptedTicket, err := km.EncryptTicket(tokenFilePath, destHost); err != nil {
			glog.Errorf(TSE+"ticket encryption failed: error %v", err)
			return err
		} else {
			// deposit the encrypted ticket in the pod's manifest
			assumed.ObjectMeta.Annotations[TSTicketAnnotation] = encryptedTicket
		}
	}
	return nil
}

// DecryptTicket() performs decryption of the encrypted ticket using host's key
//
// Paramaters:
// - dest - location to place the decoded ticket (on host's filesystem)
// - data - encrypted ticket to decode
// - user - username of the owner of the pod's processes (and the ticket file)
// - group - group that should own the ticket file
// - pod - pod to decrypt the ticket for
// Return:
// - error, if failed
func (km *KerberosManager) DecryptTicket(dest, data, user, group string, pod *api.Pod) error {
	// decrypt the ticket by running:
	//    echo data | KRB5_KTNAME=<host-key-file> KRB5_CONFIG=<host-kerb-config> gss-token -r -C <dest>
	exe := utilexec.New()
	cmd := exe.Command(GsstokenPath, "-r", "-C", dest)
	env := "KRB5_KTNAME=" + km.HostKeytabFile
	env1 := "KRB5_CONFIG=" + KRB5ConfFile
	cmd.SetEnv([]string{env, env1})
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	io.Copy(stdin, bytes.NewBufferString(data))
	stdin.Close()
	out, err1 := cmd.CombinedOutput()
	if err1 != nil {
		glog.Errorf(TSE+"error decoding ticket, error: %v, output: %v", err1, string(out))
		return err1
	}

	// update file access rights and owner
	return km.ChangeFileOwnership(dest, user, group)
}

// AddKimpersonateTicket() creates impersonated ticket for a given key in keytab. It can be used locally
// to authenticate. This option is used for low-cost keytab creation ofr pods used in QA and test use cases.
// NOTE: this model does not require interaction with KDC so is fast.
//
// Paramaters:
// - dest - credential cache to add the impersonated ticket to
// - user - user who ownes the credentials cache
// - realm - Kerberos realm
// - principal - principal (contained in the keytab file) to get ticket for
// - podKeytabFile - keytab file containing the key to generate impersonated ticket for
//
// Return:
// - error, if failed
func (km *KerberosManager) AddKimpersonateTicket(dest, user, realm, principal, podKeytabFile string) error {
	// add service ticket for the "local/fake" keytab and principal principal+"@"+realm
	// to the refreshed credentials cache by running:
	//
	// KRB5CCNAME=<tmp-ticket-file> kimpersonate -A -c <user>@<realm> -e <expiration_sec>
	//      -s <principal>@<realm> -t aes128-cts -k <pod-keytab-file>
	//
	if out, err := RunCommandWithEnv([]string{"KRB5CCNAME=" + dest}, KImpersonatePath, "-A", "-c",
		user+"@"+realm, "-e", strconv.Itoa(LocalTicketExpirationSec), "-s", principal+"@"+realm, "-t",
		"aes128-cts", "-k", podKeytabFile); err != nil {
		glog.Errorf(TSE+"error adding ticket for local keytab %s and %s@%s, error: %v, out: %v",
			principal, user, realm, err, string(out))
		return err
	} else {
		return nil
	}
}

// RegisterClusterInKDC() registers the cluster in Kerberos KDC
//
// Paramaters:
// - cluserName - cluster name to register in KDC
// - hostName - hostname of the host that is registering
// - mutex - mutex to use to serialize operations
//
// Return:
// - error, if failed
func (km *KerberosManager) RegisterClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	defer clock.ExecTime(time.Now(), "registerClusterInKDC", clusterName)

	if err := RetryFunction(func(retry int) error {
		// if mutex provided, lock on it
		if mutex != nil {
			l, err := mutex.Acquire(EtcdGlobalFolder, "krb5_admin_createlogicalhost "+hostName+" "+clusterName, EtcdTTL)
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

		// execute the command
		if out, err := RunCommand(Krb5adminPath, "create_logical_host", clusterName); err != nil {
			if !strings.Contains(string(out), "already exists") {
				glog.V(2).Infof(TSL+"TSRETRY error registering cluster %s in KDC, will retry %d, error: %v, output: %v",
					clusterName, retry, err, string(out))
				return err
			} else {
				glog.V(4).Infof(TSL+"cluster %s is already in the KDC, not added", clusterName)
				return nil
			}
		} else {
			glog.V(5).Infof(TSL+"cluster %s was added to the KDC with output %s", clusterName, string(out))
			return nil
		}
	}); err != nil {
		glog.Errorf(TSE+"error registering cluster %s in KDC after retries, giving up, error: %v", clusterName, err)
		return err
	} else {
		return nil
	}
}

// RemoveHostFromClusterInKDC() removes host from cluster in KDC
//
// Parameters:
// - clusterName - DNS name of the KDC cluster to remove from KDC
// - hostName - hostname of the host to be removed from teh KDC cluster
// - mutex - mutex to lock on, or nil
//
// Return:
// - error, if failed
func (km *KerberosManager) RemoveHostFromClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	defer clock.ExecTime(time.Now(), "removeHostFromClusterInKDC", clusterName+" "+hostName)

	// check if the node is a member of the KDC cluster
	// it may not be if the Pod is being deleted just after creation (and the Kerberos objects were not created yet)
	memberNodes, err := km.getKDCMemberNodes(clusterName)
	if err != nil {
		return err
	}
	if !strings.Contains(memberNodes, hostName) {
		glog.V(4).Infof(TSL+"cluster %s has no member %s, no need to remove", clusterName, hostName)
		return nil
	}

	if err := RetryFunction(func(retry int) error {
		// if mutex provided, lock on it
		if mutex != nil {
			l, err := mutex.Acquire(EtcdGlobalFolder, "krb5_admin_removehostmap "+hostName+" "+clusterName, EtcdTTL)
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
		if out, err := RunCommand(Krb5adminPath, "remove_hostmap", clusterName, hostName); err != nil {
			glog.V(2).Infof(TSL+"TSRETRY error removing host %s from cluster %s in KDC, will retry %d, error: %v, output: %v",
				hostName, clusterName, retry, err, string(out))
			return err
		} else {
			glog.V(5).Infof(TSL+"removeHostFromClusterInKDC() returned output %s with no error", string(out))
			return nil
		}
	}); err != nil {
		glog.Errorf(TSE+"error removing host %s from cluster %s in KDC after retries, giving up, error: %v",
			hostName, clusterName, err)
		return err
	} else {
		return nil
	}
}

// getKDCMemberNodes() retrieves all memebers of the cluster from KDC
//
// Parameters:
// - clusterName - KDC cluster name to retrieve members of
//
// Return:
// - comma-separated list of cluster members and error, if failed
func (km *KerberosManager) getKDCMemberNodes(clusterName string) (string, error) {
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
		return "", errors.New(outb.String() + " " + errb.String())
	}
	memberNodes := strings.Trim(outb.String(), "\n")
	return memberNodes, nil
}

// CleanServiceInKDC() removes all member nodes from the service cluster in KDC
// This is invoked when service is deleted
//
// Parameters:
// - clusterName - service cluster name to clean in KDC
//
// Return:
// - error, if failed
func (km *KerberosManager) CleanServiceInKDC(clusterName string) error {
	defer clock.ExecTime(time.Now(), "CleanServiceInKDC", clusterName)

	var lastErr error
	lastErr = nil

	memberNodes, err := km.getKDCMemberNodes(clusterName)
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
		if err := km.RemoveHostFromClusterInKDC(clusterName, nodeName, nil); err != nil {
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

// CheckIfHostInKDCCluster() checks if a host is a member of the KDC cluster
//
// Parameters:
// - clusterName - KDC cluster to check membership in
// - hostName - hostname to check if cluster member
//
// Return:
// - boolean indicating if the host is member of the cluster and error, if failed
func (km *KerberosManager) CheckIfHostInKDCCluster(clusterName, hostName string) (bool, error) {
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

// AddHostToClusterInKDC() adds node to the KDC cluster
//
// Parameters:
// - clusterName - KDC cluster to add teh node to
// - hostName - hostname to add to the KDC cluster
// - mutex - mutex to lock on
// Return:
// - error, if failed
func (km *KerberosManager) AddHostToClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	defer clock.ExecTime(time.Now(), "addHostToClusterInKDC", clusterName+" "+hostName)

	if err := RetryFunction(func(retry int) error {
		// if mutex provided, lock on it
		if mutex != nil {
			l, err := mutex.Acquire(EtcdGlobalFolder, "krb5_admin_addhost "+hostName+" "+clusterName, EtcdTTL)
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

		// run the command
		if out, err := RunCommand(Krb5adminPath, "insert_hostmap", clusterName, hostName); err != nil {
			if !strings.Contains(string(out), "is already in cluster") {
				glog.V(2).Infof(TSL+"TSRETRY error adding host %s to cluster %s in KDC, will retry %d, error: %v, output: %v",
					hostName, clusterName, retry, err, string(out))
				return err
			} else {
				glog.V(2).Infof(TSL+"host %s is already in the cluster %s, not added", hostName, clusterName)
				return nil
			}
		} else {
			glog.V(5).Infof(TSL+"host %s was added to cluster %s with output %s", hostName, clusterName, string(out))
			return nil
		}
	}); err != nil {
		glog.Errorf(TSE+"error adding host %s to cluster %s in KDC after retries, giving up, error: %v", hostName, clusterName, err)
		return err
	} else {
		return nil
		// validate that the host was added to KDC
		/*	if errVerify := RetryFunction(func(retry int) error {
				if isMember, errMember := km.CheckIfHostInKDCCluster(clusterName, hostName); errMember != nil {
					return errMember
				} else {
					if isMember {
						return nil
					} else {
						glog.Errorf(TSL+"host %s is not in KDC cluster %s after retry %d", hostName, clusterName, retry)
						return errors.New("host " + hostName + " not in KDC cluster " + clusterName + " yet")
					}
				}
			}); errVerify != nil {
				glog.Errorf(TSE+"could not verify that host %s is in KDC cluster %s after retries, giving up, error: %v",
					hostName, clusterName, errVerify)
				return errVerify
			} else {
				glog.V(5).Infof(TSL+"host %s was verified present in KDC cluster %s", hostName, clusterName)
				return nil
			}
		*/
	}
}

// GetKeyVersionsFromKeytab() retrieves Kerberos key versions present in the keytab file. It does that by inspecting
// the output of the ktutil utility.
//
// Parameters:
// - keytabFilePath - path to the keytab file to retrieve versions from
//
// Return:
// - triple consisting of map with highest key versions for each cluster, map with cluster names,
//   map with number of keys, and error, if failed
func (km *KerberosManager) GetKeyVersionsFromKeytab(keytabFilePath string) (map[string]int, map[string]bool, map[string]int, error) {
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
	outb, errb, err := ExecWithPipe("printf", KtutilPath, []string{"rkt " + keytabFilePath + "\nlist\nq\n"}, []string{})
	if err != nil {
		glog.Errorf(TSE+"exec with pipe failed, error %v", err)
		return nil, nil, nil, err
	}
	if errb.Len() > 0 {
		glog.Errorf(TSE+"unable to list keys in keytab file %s, output %s, error %s", keytabFilePath, outb.String(), errb.String())
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
			glog.Errorf(TSE+"could not convert key version %s to integer, error: %+v", items[1], err)
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

// SetupKrbACLFile() creates ACL file in /etc allowing non-root user to get keytabs
//
// Parameters:
// - srv - service for which keytab is needed
// - clusterName - cluser name for which teh keytab is needed
//
// Return:
// - error, if failed
func (km *KerberosManager) SetupKrbACLFile(srv, clusterName string) error {
	if file, err := ioutil.TempFile(os.TempDir(), "k8s-ACL"); err != nil {
		glog.Errorf(TSE+"failed to create tmp file for ACL : error %v", err)
		return err
	} else {
		tmpFile := file.Name()
		defer os.Remove(tmpFile)
		data := []byte(km.KeytabOwner + " " + km.KerberosRealm + " " + srv + " " + clusterName)
		if err := ioutil.WriteFile(tmpFile, data, 0664); err != nil {
			glog.Errorf(TSE+"can not create ACL file for service %s in cluster %s, error: %v", srv, clusterName, err)
			return err
		} else if errRename := os.Rename(tmpFile, Krb5keytabAclDir+srv+"-"+clusterName); errRename != nil {
			glog.Errorf(TSE+"can not rename ACL file %s for service %s in cluster %s, error: %v", tmpFile, srv, clusterName, errRename)
			return errRename
		} else {
			glog.V(5).Infof(TSL+"ACL file for service %s in cluster %s has been created", srv, clusterName)
			return nil
		}
	}
}

// RequestKey() requests the keytab refresh and retries if needed
//
// Parameters:
// - srv - service to request
// - clusterName - cluster name of teh service
// - doLock - indicates whether to lock
// - mutex - mutex to lock on
// - hostname - hostname to request keytab on
// - principal -
func (km *KerberosManager) RequestKey(srv, clusterName string, mutex *lock.Mutex, hostname string) error {
	return RetryFunction(func(retry int) error {
		// if mutex provided, lock on it
		if mutex != nil {
			l, err := mutex.Acquire(EtcdGlobalFolder, "krb5_keytab "+hostname+" "+srv+"/"+clusterName, EtcdTTL)
			if err != nil {
				glog.Errorf(TSE+"error obtaining lock while getting key for service "+
					"%s in cluster %s during %d retry, error: %v", srv, clusterName, retry, err)
				if l != nil {
					l.Release()
				}
				return err
			} else {
				defer l.Release()
			}
		}
		// run the command
		if out, err := RunCommand(Krb5keytabPath, "-f", "-p", km.KeytabOwner, srv+"/"+clusterName); err != nil {
			glog.V(2).Infof(TSL+"TSRETRY error creating service key for service %s "+
				"in cluster %s during %d retry, error: %v, output: %v", srv, clusterName, retry, err, string(out))
			return err
		} else {
			glog.V(5).Infof(TSL+"keytabfile content has been fetched for principal %s/%s "+
				"after %d retries, returned output %s with no error", srv, clusterName, retry, string(out))
			return nil
		}
	})
}

// CreateLocalKey() creates local key in keytab file
// exeutes:
//    ktutil -k <pod-keytab-file> add -re aes128-cts -V 2 -p <principal>
//
// Parameters:
// - podKeytabFile - keytabfile to add the key to
// - principal - principal to add
//
// Return:
// - error, if failed
func (km *KerberosManager) CreateLocalKey(podKeytabFile, principal string) error {
	if out, err := RunCommand(HeimdalKtutilPath, "-k", podKeytabFile, "add", "-re",
		"aes128-cts", "-V", "2", "-p", principal); err != nil {
		glog.Errorf(TSE+"error creating local keytab for principal %s, error: %v, output: %v",
			principal, err, string(out))
		return err
	} else {
		return nil
	}
}

// GetPwdbSSLCert() create SSL certificate using pwd cert
//
// Parameters:
// - clusterName - name of teh cluster to get certs for
//
// Return:
// - error, if failed
func (km *KerberosManager) GetPwdbSSLCert(clusterName string) error {
	// check if the certs are already present and fresh (on the node)
	// we can not retry here since exit status of 1 is a normal condition
	// indicating expired certificate
	// TODO: check if we can change pwdb output to differentiate between expired cert and other error
	if out, err := RunCommand(PwdbPath, "cert", "-e", "-h", clusterName); err != nil {
		glog.V(1).Infof(TSL+"certificate files for cluster %s is expired (or other error happened), error: %v, output: %v",
			clusterName, err, string(out))
		// request the certs file refresh and retry if needed
		if err1 := RetryFunction(func(retry int) error {
			if out, err := RunCommand(PwdbPath, "cert", "-h", clusterName); err != nil {
				glog.Errorf(TSE+"error creating certificate files for cluster %s during %d retry, error: %v, output: %v",
					clusterName, retry, err, string(out))
				return err
			} else {
				glog.V(5).Infof(TSL+"certs have been fetched for cluster %s after %d retries, returned output %s with no error",
					clusterName, retry, string(out))
				return nil
			}
		}); err1 != nil {
			glog.Errorf(TSE+"error creating certificate files for cluster %s after all retries, error: %v, output: %v",
				clusterName, err, string(out))
			return err1
		}
		// TODO: [ future improvement ] mark the Pod indicating that certs were refreshed
		// this can be used to restart the Pod or notify the user when the SSL cert refreshes.
	} else {
		glog.V(5).Infof(TSL+"certificate files for cluster %s are fresh, no need to refresh, returned output %s with no error",
			clusterName, string(out))
	}
	return nil
}

// GetSelfSignedSSLCert() gets self-signed (no KDC registration) SSL certificate
// executes:
//    generateCerts <KDC-cluster-DNS> <host-self-signed-cert-directory>
//
// Parameters:
// - clusterName - KDC cluster name to get certificate for
//
// Return:
// - error, if failed
func (km *KerberosManager) GetSelfSignedSSLCert(clusterName string) error {
	if out, err := RunCommand(LocalCertGeneratorPath, clusterName, HostSelfSignedCertsFile); err != nil {
		glog.Errorf(TSE+"error creating local certs for cluster %s, error: %v, output: %v", clusterName, err, string(out))
		return err
	} else {
		return nil
	}
}

// ChangeFileOwnership() changes file ownership to desired one
//
// Parameters:
// - file - path to the file to change
// - user - user to become the file owner
// - group - group to be the owning group
// Return:
// - error, if failed
func (km *KerberosManager) ChangeFileOwnership(file, user, group string) error {
	err := os.Chmod(file, 0600)
	if err != nil {
		glog.Errorf(TSE+"error changing file %s permission to 0600, error: %v", file, err)
		return err
	}
	owner := user + ":" + group
	exe := utilexec.New()
	cmd := exe.Command(ChownPath, owner, file)
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Errorf(TSE+"error changing owner to %v, error: %v, output %s", owner, err, string(out))
		return err
	}
	return nil
}

// member access functions
func (km *KerberosManager) GetKeytabOwner() string {
	return km.KeytabOwner
}
func (km *KerberosManager) GetCertsOwner() string {
	return km.CertsOwner
}
func (km *KerberosManager) GetTicketUserGroup() string {
	return km.TicketUserGroup
}
func (km *KerberosManager) GetKerberosRealm() string {
	return km.KerberosRealm
}
func (km *KerberosManager) GetHostKeytabFile() string {
	return km.HostKeytabFile
}
func (km *KerberosManager) GetHostCertsFile() string {
	return km.HostCertsFile
}
func (km *KerberosManager) GetHostPrestashedTktsDir() string {
	return km.HostPrestashedTktsDir
}
