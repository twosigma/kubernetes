/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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

package scheduler

// Note: if you change code in this file, you might need to change code in
// contrib/mesos/pkg/scheduler/.

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/record"
	"k8s.io/kubernetes/pkg/util/exec"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/plugin/pkg/scheduler/algorithm"
	"k8s.io/kubernetes/plugin/pkg/scheduler/metrics"
	"k8s.io/kubernetes/plugin/pkg/scheduler/schedulercache"

	"github.com/golang/glog"
)

// Binder knows how to write a binding.
type Binder interface {
	Bind(binding *api.Binding) error
}

type PodConditionUpdater interface {
	Update(pod *api.Pod, podCondition *api.PodCondition) error
}

// Scheduler watches for new unscheduled pods. It attempts to find
// nodes that they fit on and writes bindings back to the api server.
type Scheduler struct {
	config *Config
}

type Config struct {
	// It is expected that changes made via SchedulerCache will be observed
	// by NodeLister and Algorithm.
	SchedulerCache schedulercache.Cache
	NodeLister     algorithm.NodeLister
	Algorithm      algorithm.ScheduleAlgorithm
	Binder         Binder
	// PodConditionUpdater is used only in case of scheduling errors. If we succeed
	// with scheduling, PodScheduled condition will be updated in apiserver in /bind
	// handler so that binding and setting PodCondition it is atomic.
	PodConditionUpdater PodConditionUpdater

	// NextPod should be a function that blocks until the next pod
	// is available. We don't use a channel for this, because scheduling
	// a pod may take some amount of time and we don't want pods to get
	// stale while they sit in a channel.
	NextPod func() *api.Pod

	// Error is called if there is an error. It is passed the pod in
	// question, and the error
	Error func(*api.Pod, error)

	// Recorder is the EventRecorder to use
	Recorder record.EventRecorder

	// Close this to shut down the scheduler.
	StopEverything chan struct{}
}

// New returns a new scheduler.
func New(c *Config) *Scheduler {
	s := &Scheduler{
		config: c,
	}
	metrics.Register()
	return s
}

// Run begins watching and scheduling. It starts a goroutine and returns immediately.
func (s *Scheduler) Run() {
	go wait.Until(s.scheduleOne, 0, s.config.StopEverything)
}

func (s *Scheduler) scheduleOne() {
	pod := s.config.NextPod()

	glog.V(3).Infof("Attempting to schedule: %+v", pod)
	start := time.Now()
	dest, err := s.config.Algorithm.Schedule(pod, s.config.NodeLister)
	if err != nil {
		glog.V(1).Infof("Failed to schedule: %+v", pod)
		s.config.Error(pod, err)
		s.config.Recorder.Eventf(pod, api.EventTypeWarning, "FailedScheduling", "%v", err)
		s.config.PodConditionUpdater.Update(pod, &api.PodCondition{
			Type:   api.PodScheduled,
			Status: api.ConditionFalse,
			Reason: "Unschedulable",
		})
		return
	}
	metrics.SchedulingAlgorithmLatency.Observe(metrics.SinceInMicroseconds(start))

	// Optimistically assume that the binding will succeed and send it to apiserver
	// in the background.
	// The only risk in this approach is that if the binding fails because of some
	// reason, scheduler will be assuming that it succeeded while scheduling next
	// pods, until the assumption in the internal cache expire (expiration is
	// defined as "didn't read the binding via watch within a given timeout",
	// timeout is currently set to 30s). However, after this timeout, the situation
	// will self-repair.
	assumed := *pod
	assumed.Spec.NodeName = dest

	tokenFile := ""
	// go with a simple hard coded version as poc
	if token, ok := assumed.ObjectMeta.Annotations["ts/token"]; ok {
		// first we check if "ts/token" is present, if so we decode the token and re-encrypt
		glog.Infof("got ts/token=%s", token)

		file, err := ioutil.TempFile(os.TempDir(), "k8s-token")
		if err != nil {
			glog.Errorf("failed to create tmp file: %v", err)
		} else {
			tmpFile := file.Name()
			defer os.Remove(tmpFile)
			env := "KRB5_KTNAME=/var/spool/keytabs/tsk8s"
			exe := exec.New()
			cmd := exe.Command(
				"/usr/local/bin/gss-token",
				"-r",
				"-C",
				tmpFile)
			cmd.SetEnv([]string{env})
			stdin, err := cmd.StdinPipe()
			if err != nil {
				glog.Errorf("unable to obtain stdin of child process: %v", err)
			} else {
				io.WriteString(stdin, token+"\n")
				stdin.Close()
				out, err := cmd.CombinedOutput()
				if err == nil {
					tokenFile = tmpFile
					glog.Infof("token decrypt successfully to %s", tmpFile)
				} else {
					glog.Errorf("unable to decode token: %s", out)
				}
			}
		}
	} else if user, ok := assumed.ObjectMeta.Annotations["ts/user"]; ok {
		// second we check if "ts/user" is present, if so we use prestashed ticket and encrypt
		if realm, ok := assumed.ObjectMeta.Annotations["ts/realm"]; ok {
			// user/realm are specified, we should encrypt tickets and stick it inside
			glog.Infof("got ts/user=%s, ts/realm=%s, trying to create token from prestashed ticket", user, realm)
			tktPath := fmt.Sprintf("/home/tsk8s/tickets/@%s/%s", realm, user)
			if _, err := os.Stat(tktPath); os.IsNotExist(err) {
				glog.Errorf("prestashed ticket for %s@%s does not exist", user, realm)
			} else {
				tokenFile = tktPath
			}
		}
	}

	if tokenFile != "" {
		env := fmt.Sprintf("KRB5CCNAME=%s", tokenFile)
		exe := exec.New()
		cmd := exe.Command(
			"/usr/local/bin/gss-token",
			"-D",
			fmt.Sprintf("%s@%s", "tsk8s", dest))
		cmd.SetEnv([]string{env})
		out, err := cmd.CombinedOutput()
		if err == nil {
			glog.V(5).Infof("token created: %s", out)
			assumed.ObjectMeta.Annotations["ts/ticket"] = string(out)
		} else {
			glog.Errorf("token generation failed: %v; output: %v; dest=%v; env=%v",
				err, string(out), dest, env)
		}
	}

	if err := s.config.SchedulerCache.AssumePod(&assumed); err != nil {
		glog.Errorf("scheduler cache AssumePod failed: %v", err)
	}

	go func() {
		defer metrics.E2eSchedulingLatency.Observe(metrics.SinceInMicroseconds(start))

		b := &api.Binding{
			ObjectMeta: api.ObjectMeta{Namespace: pod.Namespace, Name: pod.Name, Annotations: assumed.ObjectMeta.Annotations},
			Target: api.ObjectReference{
				Kind: "Node",
				Name: dest,
			},
		}

		bindingStart := time.Now()
		// If binding succeeded then PodScheduled condition will be updated in apiserver so that
		// it's atomic with setting host.
		err := s.config.Binder.Bind(b)
		if err != nil {
			glog.V(1).Infof("Failed to bind pod: %v/%v", pod.Namespace, pod.Name)
			s.config.Error(pod, err)
			s.config.Recorder.Eventf(pod, api.EventTypeNormal, "FailedScheduling", "Binding rejected: %v", err)
			s.config.PodConditionUpdater.Update(pod, &api.PodCondition{
				Type:   api.PodScheduled,
				Status: api.ConditionFalse,
				Reason: "BindingRejected",
			})
			return
		}
		metrics.BindingLatency.Observe(metrics.SinceInMicroseconds(bindingStart))
		s.config.Recorder.Eventf(pod, api.EventTypeNormal, "Scheduled", "Successfully assigned %v to %v", pod.Name, dest)
	}()
}
