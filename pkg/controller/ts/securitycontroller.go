/*
This package containes functions required to manage refresh of Kerberos tickets that
are delegated to the pods. The tickets are periodically refreshed on master nodes.
When ticket for a given user is refreshed, the controller recognizes that (based on the
file timestamp) and performs an update operation on all pods belonging to the user.
The update operation sends an updated manifest to kublet running the pod. The manifest
contains new (updated) ticket in enrypted form (using host key for encryption).
*/
package tssecurity

import (
	"fmt"
	"os"
	"time"

	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
)

const (
	// interval for ticket refresh i.e., controller checks for updated ticket
	// every allowedTktAgeMinutes minutes
	allowedTktAgeMinutes = time.Duration(60) * time.Minute
)

type SecurityCredentialsController struct {
	kubeClient           clientset.Interface
	allowedTktAgeMinutes time.Duration
	// podLister is able to list/get pods and is populated by the shared informer passed to
	// NewEndpointController.
	podLister corelisters.PodLister
}

// NewSecurityCredentialsController() creates an instance of TS security controller
// responsible for ticket refresh
//
// Parameters:
// - kubeClient - interface to perform pod updates
//
// Return:
// - security credentials controller and error, if failed
func NewSecurityCredentialsController(
	podInformer coreinformers.PodInformer,
	client clientset.Interface) *SecurityCredentialsController {

	controller := &SecurityCredentialsController{
		kubeClient:           client,
		allowedTktAgeMinutes: allowedTktAgeMinutes,
		podLister:            podInformer.Lister(),
	}

	return controller
}

// Run() is security credential's controller main function. It (periodically)
// checks the status of the tickets (using timestamp) for all pods. If pod's
// ticket has refreshed since the last check, the controller performs:
// 1. Reads the ticket from file on the host
// 2. Identifies the host on which the pod is currently running
// 3. Encrypts the ticket using host's key
// 4. Updates pod's manifest with the new encrypted ticket (in annotation)
// 5. Issues update operation on the pod.
//
// When update is issued, kubelet running on the node hosting the pod gets it
// and decrypts the ticket using its private key and then updates the ticket
// in the pod's directory. These operations are implemented by refreshTSTkt()
// (in pkg/kubelet/kubelet_kerberos_tickets.go) that is invoked from HandlePodUpdates()
// (in pkg/kubelet/kubelet.go).
//
// Parameters:
// - stopCh - stop channel to terminate the controller
//
// Return:
// - none - controller should not return
func (sc *SecurityCredentialsController) Run(stopCh <-chan struct{}) {
	glog.Infof(krbutils.TSL + "Starting TS Security Credentials Controller")
	defer utilruntime.HandleCrash()

	// keep track of the last time the ticket check was performed so each time the check runs
	// only the tickets for which the modification timestamp is after the last run are refreshed.
	// Ideally, the ticket refresh process on K8s master nodes should be staggered as to spread the
	// refreshes over time.
	lastRunTime := time.Time{}

	// get an instance of Kerberos manager for ticket encryption
	krbManager, _ := krbutils.NewKerberosManager(
		krbutils.KrbManagerParameters{},
	)

	// periodically check for refreshed ticket files (based on file mod date) and refresh all pods
	// using the updated ticket
	go wait.Until(func() {
		var modTime time.Time
		curRunTime := time.Now()
		glog.V(4).Infof(krbutils.TSL + "check for Kerberos tickets that need a refresh")

		if pods, err := sc.podLister.Pods(api.NamespaceAll).List(labels.Everything()); err != nil {
			//		if pods, err := sc.kubeClient.Core().Pods(api.NamespaceAll).List(api.ListOptions{}); err != nil {
			glog.Errorf(krbutils.TSE+"Error listing PODs: %v", err)
		} else {
			for _, pod := range pods {
				// process only pods that have user set and requested tickets
				if user, ok := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]; ok {
					if hasTkt, tktOk := pod.ObjectMeta.Annotations[krbutils.TSPrestashTkt]; tktOk && (hasTkt == "true") {
						glog.V(5).Infof(krbutils.TSL+"checking ticket for POD %s for user %s@%s",
							pod.Name, user, krbManager.KerberosRealm)
						tktPath := fmt.Sprintf("%s/@%s/%s", krbManager.HostPrestashedTktsDir, krbManager.KerberosRealm, user)
						if fileInfo, err := os.Stat(tktPath); err != nil {
							if os.IsNotExist(err) {
								glog.Errorf(krbutils.TSE+"prestashed ticket for %s@%s does not exist",
									user, krbManager.KerberosRealm)
							} else {
								glog.Errorf(krbutils.TSE+"fatal error when trying to check ticket file mod date %v", err)
							}
						} else {
							// check if the ticket was refreshed since the last run
							modTime = fileInfo.ModTime()
							if modTime.After(lastRunTime) || modTime.Equal(lastRunTime) {
								glog.V(2).Infof(krbutils.TSL+"ticket for user %s@%s was updated, refreshing",
									user, krbManager.KerberosRealm)
								if err := sc.UpdateTicketForPod(pod, krbManager, tktPath); err != nil {
									glog.Errorf(krbutils.TSE+"Error refetching POD %s: %v", pod.Name, err)
								} else {
									glog.V(4).Infof(krbutils.TSL+"updated POD %s", pod.Name)
								}
							} else {
								glog.V(5).Infof(krbutils.TSL+"ticket for user %s@%s does not require a refresh",
									user, krbManager.KerberosRealm)
							}
						}
					}
				}
			}
		}
		lastRunTime = curRunTime
	}, sc.allowedTktAgeMinutes, stopCh)
	glog.V(2).Infof(krbutils.TSL + "TS Security Credentials Controller started")

	<-stopCh
}

// UpdateTicketForPod() updates the ticket for a given Pod. It does that by encrypting the pre-stashed ticket
// and sending (in the updated manifest) to the kubelet that performes the actual update.
//
// Parameters:
// - pod - pod to be updated
// - krbManager - handle to Kerberos manager
// - tktPath - path to prestashed ticket on the host
//
// Return:
// - error, if failed
func (sc *SecurityCredentialsController) UpdateTicketForPod(pod *api.Pod, krbManager krbutils.KrbManager, tktPath string) error {
	// identify the node where the pod runs
	dest := pod.Spec.NodeName
	if dest == "" {
		// no destination node, Pod is Pending, skip
		glog.V(5).Infof(krbutils.TSL+"pod %s does not have node assigned, skipping refresh",
			pod.Name)
		return nil
	}
	// encrypt the ticket with destination public key of the host on which the pod runs
	if encryptedTicket, err := krbManager.EncryptTicket(tktPath, dest); err != nil {
		glog.Errorf(krbutils.TSE+"ticket encryption failed: error %v", err)
		return err
	} else {
		glog.V(5).Infof(krbutils.TSL + "ticket encrypted")
		// put the encrypted ticket in pod's manifest
		pod.ObjectMeta.Annotations[krbutils.TSTicketAnnotation] = encryptedTicket
		// invoke pod update - send updated manifest to the apiserver
		// the kubelet will get it, decrypt using host's private key, and deposit in
		// pod's filesystem
		if _, err := sc.kubeClient.Core().Pods(pod.ObjectMeta.Namespace).Update(pod); err != nil {
			glog.Errorf(krbutils.TSE+"error updating POD %s on first attempt: %v", pod.Name, err)
			// update may fail because pod has changed, fetch fresh pod object and retry
			if podToUpdate, errFetch := sc.kubeClient.Core().Pods(pod.ObjectMeta.Namespace).Get(pod.Name, metav1.GetOptions{}); errFetch != nil {
				glog.Errorf(krbutils.TSE+"Error refetching POD %s: %v", pod.Name, errFetch)
				return errFetch
			} else {
				// refetch succeeded, attempt to update
				podToUpdate.ObjectMeta.Annotations[krbutils.TSTicketAnnotation] = encryptedTicket
				if _, errRetry := sc.kubeClient.Core().Pods(podToUpdate.ObjectMeta.Namespace).Update(podToUpdate); errRetry != nil {
					glog.Errorf(krbutils.TSE+"Error updating POD %s after refetch: %v", pod.Name, errRetry)
					return errRetry
				} else {
					glog.V(4).Infof(krbutils.TSL+"updated POD %s after refetch", pod.Name)
					return nil
				}
			}
		} else {
			return nil
		}
	}
}
