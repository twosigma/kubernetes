package tssecurity

import (
	"fmt"
	"os"
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/util/exec"
	krbutils "k8s.io/kubernetes/pkg/util/kerberos"
	utilruntime "k8s.io/kubernetes/pkg/util/runtime"
	"k8s.io/kubernetes/pkg/util/wait"
)

const (
	allowedTktAgeMinutes = time.Duration(60) * time.Minute
)

type SecurityCredentialsController struct {
	kubeClient           clientset.Interface
	allowedTktAgeMinutes time.Duration
}

func NewSecurityCredentialsController(
	kubeClient clientset.Interface) (*SecurityCredentialsController, error) {
	controller := &SecurityCredentialsController{
		kubeClient:           kubeClient,
		allowedTktAgeMinutes: allowedTktAgeMinutes,
	}
	return controller, nil
}

func (sc *SecurityCredentialsController) Run() {
	glog.Infof("Starting TS Security Credentials Controller")
	defer utilruntime.HandleCrash()
	// keep track of the last time the ticket check was performed so each time the check runs
	// only the tickets for which the modification timestamp is after the last run are refreshed
	// ideally, the ticket refresh process on K8s master nodes should be staggered as to spread the
	// refreshes over time
	lastRunTime := time.Time{}
	go wait.Until(func() {
		var modTime time.Time
		curRunTime := time.Now()
		glog.V(2).Infof("check for Kerberos tickets that need a refresh")
		// TODO: this could be improved by creating selector for List to only return
		// PODs with the ts/ticket annotation. Could not find a good example, yet.
		if pods, err := sc.kubeClient.Core().Pods(api.NamespaceAll).List(api.ListOptions{}); err != nil {
			glog.Errorf("Error listing PODs: %v", err)
		} else {
			for _, pod := range pods.Items {
				if user, ok := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]; ok {
					realm := krbutils.KerberosRealm
					glog.V(5).Infof("checking ticket for POD %s for user %s@%s", pod.Name, user, realm)
					tktPath := fmt.Sprintf("%s/@%s/%s", krbutils.HostPrestashedTktsDir, realm, user)
					if fileInfo, err := os.Stat(tktPath); err != nil {
						if os.IsNotExist(err) {
							glog.Errorf("prestashed ticket for %s@%s does not exist", user, realm)
						} else {
							glog.Errorf("fatal error when trying to check ticket file mod date %v", err)
						}
					} else {
						modTime = fileInfo.ModTime()
						if modTime.After(lastRunTime) || modTime.Equal(lastRunTime) {
							glog.V(2).Infof("ticket for user %s@%s was updated since last run, refreshing it", user, realm)
							dest := pod.Spec.NodeName
							env := fmt.Sprintf("KRB5CCNAME=%s", tktPath)
							exe := exec.New()
							cmd := exe.Command(
								krbutils.GsstokenPath,
								"-D",
								fmt.Sprintf("%s@%s", krbutils.KeytabOwner, dest))
							cmd.SetEnv([]string{env})
							out, err := cmd.CombinedOutput()
							if err == nil {
								glog.V(5).Infof("token created: %s", out)
								pod.ObjectMeta.Annotations[krbutils.TSTicketAnnotation] = string(out)
							} else {
								glog.Errorf("token generation failed: %v; output: %v; dest=%v; env=%v",
									err, string(out), dest, env)
							}
							if _, err := sc.kubeClient.Core().Pods(pod.ObjectMeta.Namespace).Update(&pod); err != nil {
								glog.Errorf("Error updating POD: %v", err)
							} else {
								glog.V(5).Infof("updated POD %s", pod.Name)
							}
						} else {
							glog.V(5).Infof("ticket for user %s@%s does not require a refresh", user, realm)
						}
					}
				}
			}
		}
		lastRunTime = curRunTime
	}, sc.allowedTktAgeMinutes, wait.NeverStop)
	glog.V(2).Infof("TS Security Credentials Controller exited")
}
