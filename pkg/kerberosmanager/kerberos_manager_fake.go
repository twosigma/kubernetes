/*
This file contains mock implementations of the KrbManager interface from ./kerberos_manager.go
The functions are used for unit testing.
*/
package kerberosmanager

import (
	"errors"
	"io/ioutil"
	"os"

	"k8s.io/kubernetes/pkg/api"
	lock "k8s.io/kubernetes/pkg/util/lock"
)

const (
	// simulated messages
	//
	// ticket related messages
	KimpersonateTicketContent = "kimpersonate-ticket"
	DecodeNoTicketBody        = "decode no ticket body"
	KimpersonateNoDestFile    = "kimpersonate no destination file"
	//keytab related messages
	NoRunAsUser = "no run as user annotation"
)

// Kerberos manager mock for testing
// It has data structures simulating state of the KDC, specifically:
// - list of clusters registered in KDC
// - list of hosts registered as members of each of teh clusters
// - list of ACL files that should be defined on a host
type FakeKerberosManager struct {
	// inherit methods not overloaded by the mock
	KerberosManager

	// store for simulated KDC cluster membership
	clustersInKDC map[string]map[string]bool

	// ACL files simulator
	aclFiles map[string]bool
}

// NewFakeKerberosManager() creates a new instance of the Kerberos Manager mock
//
// Parameters:
// - kubeletRoot - root directory of the kubelet (to simulate Kerberos files)
//
// Return:
// - mock Kerberos manager and error, if failed
func NewFakeKerberosManager(kubeletRoot string) (*FakeKerberosManager, error) {
	// create mock folders for keytabs and certs on teh kubelet
	HostKeytabFile := kubeletRoot + "/keytabs"
	HostCertsFile := kubeletRoot + "/certs"
	if err := os.MkdirAll(HostKeytabFile, 0700); err != nil {
		return nil, errors.New("can't mkdir " + HostKeytabFile + " err " + err.Error())
	}
	if err := os.MkdirAll(HostCertsFile, 0700); err != nil {
		return nil, errors.New("can't mkdir " + HostCertsFile + " err " + err.Error())
	}

	// initialize the new instance of Kerberos manager (master class)
	// overloading locations of Keytab objects on the hosts
	km, _ := NewKerberosManager(KrbManagerParameters{
		HostKeytabFile: HostKeytabFile,
		HostCertsFile:  HostCertsFile,
	})

	// construct and return fake manager
	return &FakeKerberosManager{
		KerberosManager: *km,
		clustersInKDC:   make(map[string]map[string]bool),
		aclFiles:        make(map[string]bool),
	}, nil
}

// mock of ticket encryption
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) EncryptTicket(tokenFile, destHost string) (string, error) {
	if dataBytes, err := ioutil.ReadFile(tokenFile); err != nil {
		return "", err
	} else {
		return string(dataBytes), nil
	}
}

// mock of preparation of the ticket
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) PrepareEncryptedTicket(assumed *api.Pod, destHost string) error {
	if token, ok := assumed.ObjectMeta.Annotations[TSTokenAnnotation]; ok {
		assumed.ObjectMeta.Annotations[TSTicketAnnotation] = "ticket encrypted with " + destHost + " public key coming from token " + token
	} else if _, ok := assumed.ObjectMeta.Annotations[TSRunAsUserAnnotation]; ok {
		if assumed.ObjectMeta.Annotations[TSPrestashTkt] == "true" {
			assumed.ObjectMeta.Annotations[TSTicketAnnotation] = "ticket encrypted with " + destHost + " public key coming from prestash"
		}
	}
	return nil
}

// mock of ticket decryption
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) DecryptTicket(dest, data, user, group string, pod *api.Pod) error {
	if data == "" {
		return errors.New(DecodeNoTicketBody)
	}
	dataBytes := []byte(data)
	return ioutil.WriteFile(dest, dataBytes, 0600)
}

// mock of ticket impersonation
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) AddKimpersonateTicket(dest, user, realm, principal, podKeytabFile string) error {
	if user == KimpersonateNoDestFile {
		return errors.New(KimpersonateNoDestFile)
	}
	if f, err := os.OpenFile(dest, os.O_APPEND|os.O_WRONLY, 0600); err != nil {
		return err
	} else {
		_, err = f.WriteString("--" + KimpersonateTicketContent + " " + user + "@" + realm + " " + principal)
		return err
	}
}

// mock of get user
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) GetRunAsUsername(pod *api.Pod) (string, error) {
	if user, ok := pod.ObjectMeta.Annotations[TSRunAsUserAnnotation]; ok {
		return user, nil
	} else {
		return "", errors.New(NoRunAsUser)
	}
}

// mock of adding host to KDC cluster
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) AddHostToClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	if _, ok := km.clustersInKDC[clusterName]; ok {
		// adding is no-op if already added
		return nil
	} else {
		if _, ok2 := km.clustersInKDC[clusterName][hostName]; ok2 {
			return errors.New("host " + hostName + "already in KDC cluster " + clusterName)
		} else {
			km.clustersInKDC[clusterName][hostName] = true
			return nil
		}
	}
}

// mock of checker for host presence in KDC cluster registrations
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) CheckIfHostInKDCCluster(clusterName, hostName string) (bool, error) {
	if _, ok := km.clustersInKDC[clusterName]; ok {
		return false, errors.New("cluster " + clusterName + " not registered in KDC")
	} else {
		if _, ok2 := km.clustersInKDC[clusterName][hostName]; ok2 {
			return true, nil
		} else {
			return false, nil
		}
	}
}

// mock of host deregistration from KDC
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) RegisterClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	if _, ok := km.clustersInKDC[clusterName]; ok {
		return nil
	} else {
		km.clustersInKDC[clusterName] = make(map[string]bool)
		return nil
	}
}

// mock of removing
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) RemoveHostFromClusterInKDC(clusterName, hostName string, mutex *lock.Mutex) error {
	if _, ok := km.clustersInKDC[clusterName]; ok {
		delete(km.clustersInKDC, clusterName)
	}
	// deletion of non-existing cluster generates no error (simulating the same behavior)
	return nil
}

// mock of getting key versions from keytab file
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) GetKeyVersionsFromKeytab(keytabFilePath string) (map[string]int, map[string]bool, map[string]int, error) {
	return map[string]int{}, map[string]bool{}, map[string]int{}, nil
}

// mock of settin up ACL file in /etc/
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) SetupKrbACLFile(srv, clusterName string) error {
	registrationACL := srv + "/" + clusterName
	km.aclFiles[registrationACL] = true
	return nil
}

// mock of requesting key for keytab file from KDC
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) RequestKey(srv, clusterName string, mutex *lock.Mutex, hostname string) error {
	// simulate the check if the operation is entitled
	expectedRegistrationACL := srv + "/" + clusterName
	if _, ok := km.aclFiles[expectedRegistrationACL]; !ok {
		// the ACL has not been registered, fail
		return errors.New("no ACL registration " + expectedRegistrationACL)
	}

	// simulate the key fetch operation
	if f, err := os.OpenFile(km.GetHostKeytabFile()+"/"+km.GetKeytabOwner(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		return err
	} else {
		defer f.Close()
		_, err = f.WriteString("key-for-" + srv + "-" + clusterName + "\n")
		return err
	}
}

// mock of creation of local key in keytab file
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) CreateLocalKey(podKeytabFile, principal string) error {
	if f, err := os.OpenFile(podKeytabFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		return err
	} else {
		defer f.Close()
		_, err = f.WriteString(principal)
		return err
	}
}

// mock for pwdb based SSL cert generation
// generate test SSL cert content
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) GetPwdbSSLCert(clusterName string) error {
	if f, err := os.OpenFile(km.GetHostCertsFile()+"/"+clusterName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		return err
	} else {
		defer f.Close()
		_, err = f.WriteString("pwdb-generated-SSL-cert-file-for-" + clusterName + "\n")
		return err
	}
}

// mock of changing file ownership
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) ChangeFileOwnership(file, user, group string) error {
	// no-op since the user IDs and groups may not be present
	return nil
}

// mock of creating self-signed SSL certificate
// - look at related definition in kerberos_manager.go for semantics of original method
func (km *FakeKerberosManager) GetSelfSignedSSLCert(clusterName string) error {
	if f, err := os.OpenFile(km.GetHostCertsFile()+"/"+clusterName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		return err
	} else {
		defer f.Close()
		_, err = f.WriteString("self-signed-SSL-cert-file-for-" + clusterName + "\n")
		return err
	}
}
