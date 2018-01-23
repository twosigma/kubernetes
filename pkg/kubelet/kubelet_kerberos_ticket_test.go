package kubelet

import (
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/kerberosmanager"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
)

const (
	runAsUser         = "tsuser"
	namespace         = "testnamespace1"
	name              = "testpod1"
	newTicketContent  = "new tgt free text ticket"
	TestClusterDomain = "test.com"
)

// verify ticket mount function
func TestMakeTktMount(t *testing.T) {
	userId := int64(0)

	// create test kubelet
	kubelet := prepareKubelet(t)
	pod := prepareTestPod(name, namespace, "false", "false", "", newTicketContent, runAsUser, &userId)
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)

	// validate that error is returned when no ticket data in the manifest
	_, err := kubelet.makeTktMount(runAsUser, "", &pod)
	require.Error(t, err, "No error returned for makeTktMount with no ticket body")
	assert.Equal(t, err.Error(), kerberosmanager.DecodeNoTicketBody, "wrong error handling for empty ticket")

	// positive test when ticket data is not empty
	mount, err := kubelet.makeTktMount(runAsUser, newTicketContent, &pod)
	expectedMount := kubecontainer.Mount{
		Name:          "ts-tkt",
		ContainerPath: krbutils.TicketDirInPod + "/" + runAsUser,
		HostPath:      kubelet.getPodDir(pod.UID) + "/" + krbutils.TicketDirForPod,
		ReadOnly:      false,
	}
	assert.Equal(t, &expectedMount, mount, "wrong ticket mount in the pod")
	require.NoError(t, err, "Error returned when decrypting ticket")

	// validate the ticket content is in the right file
	dataWritten, err := ioutil.ReadFile(kubelet.getPodDir(pod.UID) + "/" + krbutils.TicketDirForPod)
	require.NoError(t, err, "Error returned when confirming the ticket content")
	assert.Equal(t, newTicketContent, string(dataWritten[:]), "ticket content did not match")

}

// validate ticket refresh function
func TestRefreshTSTkt(t *testing.T) {
	// create test kubelet
	kubelet := prepareKubelet(t)

	// test for lack of ticket file in original pod
	testRefreshTicket(t, kubelet, "true", "false", "", runAsUser, newTicketContent, false)

	// test for no new ticket data in the update
	testRefreshTicket(t, kubelet, "true", "false", "", runAsUser, "", true)

	// test for old and new ticket present and no local keytabs (so no need for kimpersonate tickets)
	testRefreshTicket(t, kubelet, "true", "false", "", runAsUser, newTicketContent, true)

	// test for old and new ticket present and with local keytab, 1 service, and no user prefixed hostname
	testRefreshTicket(t, kubelet, "true", "false", "HTTP", runAsUser, newTicketContent, true)

	// test for old and new ticket present and with local keytab, 1 service, and with user prefixed hostname
	testRefreshTicket(t, kubelet, "true", "true", "HTTP", runAsUser, newTicketContent, true)

	// test for old and new ticket present and with local keytab, 2 services, and no user prefixed hostname
	testRefreshTicket(t, kubelet, "true", "false", "HTTP,postgres", runAsUser, newTicketContent, true)

	// test for old and new ticket present and with local keytab, 2 services, and with user prefixed hostname
	testRefreshTicket(t, kubelet, "true", "true", "HTTP,postgres", runAsUser, newTicketContent, true)

	// test for old and new ticket present and with local keytab, 2 services, and with user prefixed hostname
	// and with kimpersonate error
	testRefreshTicket(t, kubelet, "true", "false", "HTTP,postgres", kerberosmanager.KimpersonateNoDestFile, newTicketContent, true)
}

// test refresh with "fake/local" keytabs - should add new entry for kimitator
func testRefreshTicket(t *testing.T, kubelet *Kubelet, localKrb,
	userPrefixed, services, user, ticketContent string, haveExistingPodTktFile bool) {
	// prepare test pod and add to kubelet state
	userId := int64(0)
	pod := prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, user, &userId)
	kubelet.podManager.SetPods([]*api.Pod{&pod})
	//	assert.Equal(t, "aa", kubelet.podManager.GetPods()[0].ObjectMeta.UID, "aaa")

	// prepare existing ticket file in the pod, if requested
	ticketFileLocation := path.Join(kubelet.getPodDir(pod.UID), krbutils.TicketDirForPod)
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)
	if haveExistingPodTktFile {
		data := []byte("existing ticket")
		err := ioutil.WriteFile(ticketFileLocation, data, 0600)
		require.NoError(t, err, "Can not create test ticket file")
	}

	// execute the tested method
	err := kubelet.refreshTSTkt(&pod, user, ticketContent)

	// verify if correct

	// CASE 1: pod being refreshed has no ticket file
	if !haveExistingPodTktFile {
		require.Error(t, err, "No error returned for pod with no existing ticket during refresh")
		assert.Equal(t, err.Error(), krbutils.TSE+"ticket file does not exist at "+ticketFileLocation,
			"Error returned with no ticket file in existing pod not matching")
		return
	}

	// CASE 2: new ticket empty
	if ticketContent == "" {
		require.Error(t, err, "No error returned for decode with empty ticket content")
		assert.Equal(t, err.Error(), kerberosmanager.DecodeNoTicketBody,
			"Error returned with empty ticket body failure not matching")
		return
	}

	// CASE 3: new ticket body present, no local keytabs
	if localKrb == "false" {
		dataWritten, err := ioutil.ReadFile(ticketFileLocation)
		require.NoError(t, err, "Error in refreshTSTkt")
		assert.Equal(t, ticketContent, string(dataWritten[:]))
		return
	}

	// CASE 4: error in kimpersonate (simulated using special user value)
	if user == kerberosmanager.KimpersonateNoDestFile {
		require.Error(t, err, "No error returned for pod with no existing ticket during refresh")
		assert.Equal(t, err.Error(), kerberosmanager.KimpersonateNoDestFile,
			"Error returned with no kimpersonate error not matching")
		return
	}

	// CASE 5: we have local keytabs and need kimpersonate tickets for them
	dataWritten, err := ioutil.ReadFile(ticketFileLocation)
	expectedTicketContent := ticketContent
	if services != "" {
		for _, service := range strings.Split(services, ",") {
			expectedTicketContent = expectedTicketContent + "--" + kerberosmanager.KimpersonateTicketContent +
				" " + runAsUser + "@" + kubelet.krbManager.GetKerberosRealm() + " " + service + "/" + name + "." +
				namespace + "." + TestClusterDomain
			if userPrefixed == "true" {
				expectedTicketContent = expectedTicketContent + "--" + kerberosmanager.KimpersonateTicketContent +
					" " + runAsUser + "@" + kubelet.krbManager.GetKerberosRealm() + " " + service + "/" + runAsUser + "." +
					name + "." + namespace + "." + TestClusterDomain
			}
		}
	}
	require.NoError(t, err, "Error in refreshTSTkt")
	assert.Equal(t, expectedTicketContent, string(dataWritten[:]))

}

// helper functions

func prepareKubelet(t *testing.T) *Kubelet {
	testKubelet := newTestKubelet(t, false)
	kubelet := testKubelet.kubelet
	kubelet.clusterDomain = TestClusterDomain
	return kubelet
}

func prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, runAsUser string, secContextUserId *int64) api.Pod {
	return api.Pod{
		ObjectMeta: api.ObjectMeta{
			UID:       "uuid-of-pod",
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				krbutils.TSKrbLocal:                   localKrb,
				krbutils.TSPrefixedHostnameAnnotation: userPrefixed,
				krbutils.TSServicesAnnotation:         services,
				krbutils.TSTicketAnnotation:           ticketContent,
				krbutils.TSRunAsUserAnnotation:        runAsUser,
			},
		},
		Spec: api.PodSpec{
			SecurityContext: &api.PodSecurityContext{
				RunAsUser: secContextUserId,
			},
		},
	}
}
