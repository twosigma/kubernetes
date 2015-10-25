/*
Copyright 2014 The Kubernetes Authors All rights reserved.
Copyright 2016 Yuvi Panda <yuvipanda@wikimedia.org>

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

package hostautomounter

import (
	"flag"
	"fmt"
	"io"
	"strings"

	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"

	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/util/sets"
)

var (
	hostautomounts = flag.String("host-automounts", "", "Comma separated list of paths that will be automatically mounted from container host to container")
)

func init() {
	admission.RegisterPlugin("HostAutomounter", func(client clientset.Interface, config io.Reader) (admission.Interface, error) {
		hostmountset := sets.NewString(strings.Split(*hostautomounts, ",")...)
		admission := NewHostAutomounter(client, hostmountset)
		return admission, nil
	})
}

type hostAutomounter struct {
	*admission.Handler

	mounts sets.String
}

// NewServiceAccount returns an admission.Interface implementation which modifies new pods
// to make sure they have mounted all the mounts specified in *mounts from the host that
// containers are running on to the container itself.
// As an example, this can be used to ensure that all containers mount an nslcd or nscd socket.
func NewHostAutomounter(cl clientset.Interface, mounts sets.String) *hostAutomounter {
	return &hostAutomounter{
		Handler: admission.NewHandler(admission.Create),
		mounts:  mounts,
	}
}

// This does the following:
// 1. Makes a set of all paths that need mounting
// 2. Make sure that all paths have a volume assigned.
// 3. Build a dict of volume paths to their names
// 4. Make sure all the volumes are mounted on all the
//    containers
func (s *hostAutomounter) Admit(a admission.Attributes) (err error) {
	if a.GetResource().GroupResource() != api.Resource("pods") {
		return nil
	}
	obj := a.GetObject()
	if obj == nil {
		return nil
	}
	pod, ok := obj.(*api.Pod)
	if !ok {
		return nil
	}

	volumeNameMap := make(map[string]string)

	// Iterate through all existing volumes on the pod
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			if s.mounts.Has(volume.HostPath.Path) {
				volumeNameMap[volume.HostPath.Path] = volume.Name
			}
		}
	}

	for volumePath := range s.mounts {
		if _, exists := volumeNameMap[volumePath]; !exists {
			volumeName := api.SimpleNameGenerator.GenerateName(fmt.Sprintf("%s-", strings.Replace(volumePath, "/", "", -1)))
			volumeNameMap[volumePath] = volumeName
			volume := api.Volume{
				Name: volumeName,
				VolumeSource: api.VolumeSource{
					HostPath: &api.HostPathVolumeSource{
						Path: volumePath,
					},
				},
			}
			pod.Spec.Volumes = append(pod.Spec.Volumes, volume)
		}
	}

	for i, container := range pod.Spec.Containers {
		containerMounts := sets.NewString()
		for _, volumeMount := range container.VolumeMounts {
			containerMounts.Insert(volumeMount.MountPath)
		}

		requiredMounts := s.mounts.Difference(containerMounts)
		for mountPath := range requiredMounts {
			volumeMount := api.VolumeMount{
				Name:      volumeNameMap[mountPath],
				MountPath: mountPath,
			}
			pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts, volumeMount)
		}
	}

	return nil
}
