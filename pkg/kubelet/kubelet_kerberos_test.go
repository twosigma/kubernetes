package kubelet

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/kerberosmanager"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
)

// validate making ticket related mounts
func testMakeTSMounts_ticket(t *testing.T) {
	var kubelet *Kubelet
	userId := int64(0)
	// prepare test pod
	localKrb := "false"
	userPrefixed := "false"
	services := ""
	ticketContent := "existing ticket"
	podIP := "192.168.1.1"
	pod := prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, runAsUser, &userId)
	kubelet = prepareKubelet(t)
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)
	kubelet.podManager.SetPods([]*api.Pod{&pod})

	// validate that error is returned when no ticket data in the manifest
	pod.Annotations[krbutils.TSTicketAnnotation] = ""
	mounts, err := kubelet.makeTSMounts(&pod, podIP, false)
	require.Error(t, err, "No error returned for makeTSMounts with no ticket body")
	assert.Equal(t, err.Error(), kerberosmanager.DecodeNoTicketBody)

	// positive test when data is included
	pod.Annotations[krbutils.TSTicketAnnotation] = ticketContent
	podIP = ""
	mounts, err = kubelet.makeTSMounts(&pod, podIP, false)
	require.NoError(t, err, "Error returned when making ticket mount ticket")
	expectedMount := kubecontainer.Mount{
		Name:          "ts-tkt",
		ContainerPath: krbutils.TicketDirInPod + "/" + runAsUser,
		HostPath:      kubelet.getPodDir(pod.UID) + "/" + krbutils.TicketDirForPod,
		ReadOnly:      false,
	}
	assert.Equal(t, []kubecontainer.Mount{expectedMount}, mounts, "wrong ticket mount in the pod")
	require.NoError(t, err, "Error returned when decrypting ticket")
}

// validate making keytab related mounts
func testMakeTSMounts_keytab(t *testing.T) {
	var localKrb, userPrefixed, services, ticketContent, podIP string
	var pod api.Pod
	var mounts, expectedMount []kubecontainer.Mount
	var err error
	var kubelet *Kubelet
	userId := int64(0)

	// validate that standard keytab (not a local keytab) is created (and also ticket)
	localKrb = "false"
	userPrefixed = "false"
	services = "HTTP"
	ticketContent = "existing ticket"
	podIP = "192.168.1.1"
	pod = prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, runAsUser, &userId)
	kubelet = prepareKubelet(t)
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)
	// run the test
	mounts, err = kubelet.makeTSMounts(&pod, podIP, false)
	// verify results
	require.NoError(t, err, "Error returned for makeTSMounts")
	expectedMount = []kubecontainer.Mount{
		{
			Name:          "ts-tkt",
			ContainerPath: krbutils.TicketDirInPod + "/" + runAsUser,
			HostPath:      kubelet.getPodDir(pod.UID) + "/" + krbutils.TicketDirForPod,
			ReadOnly:      false,
		},
		{
			Name:          "ts-keytab",
			ContainerPath: krbutils.KeytabPathInPod,
			HostPath:      kubelet.getPodDir(pod.UID) + "/keytabs",
			ReadOnly:      false,
		},
	}
	assert.Equal(t, expectedMount, mounts, "wrong keytab mount in the pod")

	// validate that the local keytab can be created
	localKrb = "true"
	userPrefixed = "false"
	services = "HTTP"
	ticketContent = "existing ticket"
	podIP = "192.168.1.1"
	pod = prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, runAsUser, &userId)
	kubelet = prepareKubelet(t)
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)
	// run the test
	mounts, err = kubelet.makeTSMounts(&pod, podIP, false)
	// verify results
	require.NoError(t, err, "Error returned for makeTSMounts")
	expectedMount = []kubecontainer.Mount{
		{
			Name:          "ts-tkt",
			ContainerPath: krbutils.TicketDirInPod + "/" + runAsUser,
			HostPath:      kubelet.getPodDir(pod.UID) + "/" + krbutils.TicketDirForPod,
			ReadOnly:      false,
		},
		{
			Name:          "ts-keytab",
			ContainerPath: krbutils.KeytabPathInPod,
			HostPath:      kubelet.getPodDir(pod.UID) + "/keytabs",
			ReadOnly:      false,
		},
	}
	assert.Equal(t, expectedMount, mounts, "wrong keytab mount in the pod")
}

// validate making SSL cert related mounts
func testMakeTSMounts_certs(t *testing.T) {
	var localKrb, userPrefixed, services, ticketContent, podIP string
	var pod api.Pod
	var mounts, expectedMount []kubecontainer.Mount
	var err error
	var kubelet *Kubelet
	userId := int64(0)

	// validate that standard SSL certs (not a local self-signed) are created (and also ticket)
	localKrb = "false"
	userPrefixed = "false"
	services = "HTTP"
	ticketContent = "existing ticket"
	podIP = "192.168.1.1"
	pod = prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, runAsUser, &userId)
	kubelet = prepareKubelet(t)
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)
	pod.ObjectMeta.Annotations[krbutils.TSCertsAnnotation] = "true"
	mounts, err = kubelet.makeTSMounts(&pod, podIP, false)
	require.NoError(t, err, "Error returned for makeTSMounts")
	expectedMount = []kubecontainer.Mount{
		{
			Name:          "ts-tkt",
			ContainerPath: krbutils.TicketDirInPod + "/" + runAsUser,
			HostPath:      kubelet.getPodDir(pod.UID) + "/" + krbutils.TicketDirForPod,
			ReadOnly:      false,
		},
		{
			Name:          "ts-keytab",
			ContainerPath: krbutils.KeytabPathInPod,
			HostPath:      kubelet.getPodDir(pod.UID) + "/keytabs",
			ReadOnly:      false,
		},
		{
			Name:          "ts-certs",
			ContainerPath: krbutils.CertsPathInPod + "/" + runAsUser,
			HostPath:      kubelet.getPodDir(pod.UID) + "/certs",
			ReadOnly:      false,
		},
	}
	assert.Equal(t, expectedMount, mounts, "wrong keytab mount in the pod")

	// validate that local self-signed SSL certs are created (and also ticket)
	localKrb = "true"
	userPrefixed = "false"
	services = "HTTP"
	ticketContent = "existing ticket"
	podIP = "192.168.1.1"
	pod = prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, runAsUser, &userId)
	kubelet = prepareKubelet(t)
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)
	kubelet.podManager.SetPods([]*api.Pod{&pod})
	pod.ObjectMeta.Annotations[krbutils.TSCertsAnnotation] = "true"
	// run the test
	mounts, err = kubelet.makeTSMounts(&pod, podIP, false)
	// verify results
	require.NoError(t, err, "Error returned for makeTSMounts")
	expectedMount = []kubecontainer.Mount{
		{
			Name:          "ts-tkt",
			ContainerPath: krbutils.TicketDirInPod + "/" + runAsUser,
			HostPath:      kubelet.getPodDir(pod.UID) + "/" + krbutils.TicketDirForPod,
			ReadOnly:      false,
		},
		{
			Name:          "ts-keytab",
			ContainerPath: krbutils.KeytabPathInPod,
			HostPath:      kubelet.getPodDir(pod.UID) + "/keytabs",
			ReadOnly:      false,
		},
		{
			Name:          "ts-certs",
			ContainerPath: krbutils.CertsPathInPod + "/" + runAsUser,
			HostPath:      kubelet.getPodDir(pod.UID) + "/certs",
			ReadOnly:      false,
		},
	}
	assert.Equal(t, expectedMount, mounts, "wrong keytab mount in the pod")

}

func testMakeTSResolveConf(t *testing.T) {

	var localKrb, userPrefixed, services, ticketContent, podIP string
	var pod api.Pod
	var mounts, expectedMount []kubecontainer.Mount
	var err error
	var kubelet *Kubelet
	userId := int64(0)

	// validate that standard SSL certs (not a local self-signed) are created (and also ticket)
	localKrb = "false"
	userPrefixed = "false"
	services = "HTTP"
	ticketContent = "existing ticket"
	podIP = "192.168.1.1"
	pod = prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, runAsUser, &userId)
	kubelet = prepareKubelet(t)
	kubelet.resolverConfig = "/etc/resolv.conf"
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)
	pod.ObjectMeta.Annotations[krbutils.TSCertsAnnotation] = "true"
	mounts, err = kubelet.makeTSMounts(&pod, podIP, true)
	require.NoError(t, err, "Error returned for makeTSMounts")
	expectedMount = []kubecontainer.Mount{
		{
			Name:          "ts-tkt",
			ContainerPath: krbutils.TicketDirInPod + "/" + runAsUser,
			HostPath:      kubelet.getPodDir(pod.UID) + "/" + krbutils.TicketDirForPod,
			ReadOnly:      false,
		},
		{
			Name:          "ts-keytab",
			ContainerPath: krbutils.KeytabPathInPod,
			HostPath:      kubelet.getPodDir(pod.UID) + "/keytabs",
			ReadOnly:      false,
		},
		{
			Name:          "ts-certs",
			ContainerPath: krbutils.CertsPathInPod + "/" + runAsUser,
			HostPath:      kubelet.getPodDir(pod.UID) + "/certs",
			ReadOnly:      false,
		},
		{
			Name:          "resolv",
			ContainerPath: "/etc/resolv.conf",
			HostPath:      kubelet.getPodDir(pod.UID) + "/resolv.conf",
			ReadOnly:      false,
		},
	}
	assert.Equal(t, expectedMount, mounts, "wrong keytab mount in the pod")
}

func testPodUpdateKerberos(t *testing.T) {
	var localKrb, userPrefixed, services, ticketContent string
	var pod api.Pod
	var kubelet *Kubelet
	userId := int64(0)

	// validate that standard SSL certs (not a local self-signed) are created (and also ticket)
	localKrb = "false"
	userPrefixed = "false"
	services = "HTTP"
	ticketContent = "existing ticket"
	pod = prepareTestPod(name, namespace, localKrb, userPrefixed, services, ticketContent, runAsUser, &userId)
	kubelet = prepareKubelet(t)
	kubelet.resolverConfig = "/etc/resolv.conf"
	os.Mkdir(kubelet.getPodDir(pod.UID), 0700)
	pod.ObjectMeta.Annotations[krbutils.TSCertsAnnotation] = "true"
	kubelet.podUpdateKerberos(&pod)
}

func TestMakeTSMounts(t *testing.T) {
	// test ticket related mounts
	testMakeTSMounts_ticket(t)

	// test keytab creation
	testMakeTSMounts_keytab(t)

	// test certificate creation
	testMakeTSMounts_certs(t)

	// test custom resolv.conf creation
	testMakeTSResolveConf(t)

	// test pod update
	testPodUpdateKerberos(t)
}
