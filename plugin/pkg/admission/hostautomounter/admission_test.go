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
	"testing"

	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
	"k8s.io/kubernetes/pkg/util/sets"
)

// Test that an empty pod with no mounts, see if it comes back
// with the appropriate mounts + volumes
func TestEmptyPod(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	testPod := api.Pod{ObjectMeta: api.ObjectMeta{Name: "testPod", Namespace: "test"},
		Spec: api.PodSpec{},
	}
	testPod.Spec.Containers = make([]api.Container, 0, 2)
	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "b-registry.example.com/someimage",
	})
	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "a-registry.example.com/someimage",
	})
	mounts := sets.NewString("/var/run/nslcd/socket", "/var/run/nscd/socket")
	handler := NewHostAutomounter(clientset, mounts)

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err != nil {
		t.Errorf("Expected admission to pass but it failed!")
	}

	foundVolumes := sets.NewString()
	for _, volume := range testPod.Spec.Volumes {
		if volume.HostPath != nil {
			foundVolumes.Insert(volume.HostPath.Path)
		}
	}

	if !foundVolumes.IsSuperset(mounts) {
		t.Errorf("Expected Volumes not found!")
	}

	for _, container := range testPod.Spec.Containers {
		containerMounts := sets.NewString()
		for _, volumeMount := range container.VolumeMounts {
			containerMounts.Insert(volumeMount.MountPath)
		}
		if !containerMounts.IsSuperset(mounts) {
			t.Errorf("Expected VolumeMounts not found!")
		}
	}
}

// Test that a pod with custom volumes and mounts, see if
// our automounts get added properly
func TestNonEmptyPod(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	testPod := api.Pod{ObjectMeta: api.ObjectMeta{Name: "testPod", Namespace: "test"},
		Spec: api.PodSpec{},
	}
	testPod.Spec.Containers = make([]api.Container, 0, 2)
	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "b-registry.example.com/someimage",
	})
	testPod.Spec.Containers[0].VolumeMounts = make([]api.VolumeMount, 0, 1)
	testPod.Spec.Containers[0].VolumeMounts = append(testPod.Spec.Containers[0].VolumeMounts, api.VolumeMount{
		Name:      "just-a-test",
		ReadOnly:  true,
		MountPath: "/tmp/watelse",
	})

	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "a-registry.example.com/someimage",
	})

	testPod.Spec.Volumes = make([]api.Volume, 1)
	testPod.Spec.Volumes = append(testPod.Spec.Volumes, api.Volume{
		Name: "just-a-test",
		VolumeSource: api.VolumeSource{
			HostPath: &api.HostPathVolumeSource{
				Path: "/tmp/wat",
			},
		},
	})

	mounts := sets.NewString("/var/run/nslcd/socket", "/var/run/nscd/socket")
	handler := NewHostAutomounter(clientset, mounts)

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err != nil {
		t.Errorf("Expected admission to pass but it failed!")
	}

	foundVolumes := sets.NewString()
	for _, volume := range testPod.Spec.Volumes {
		if volume.HostPath != nil {
			foundVolumes.Insert(volume.HostPath.Path)
		}
	}

	if !foundVolumes.IsSuperset(mounts) {
		t.Errorf("Expected Volumes not found!")
	}

	for _, container := range testPod.Spec.Containers {
		containerMounts := sets.NewString()
		for _, volumeMount := range container.VolumeMounts {
			containerMounts.Insert(volumeMount.MountPath)
		}
		if !containerMounts.IsSuperset(mounts) {
			t.Errorf("Expected VolumeMounts not found!")
		}
	}
}

// Test that a pod with one of the host automounts manually
// mounted gets the other one
func TestPartialMountedPod(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	testPod := api.Pod{ObjectMeta: api.ObjectMeta{Name: "testPod", Namespace: "test"},
		Spec: api.PodSpec{},
	}
	testPod.Spec.Containers = make([]api.Container, 0, 2)
	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "b-registry.example.com/someimage",
	})
	testPod.Spec.Containers[0].VolumeMounts = make([]api.VolumeMount, 0, 1)
	testPod.Spec.Containers[0].VolumeMounts = append(testPod.Spec.Containers[0].VolumeMounts, api.VolumeMount{
		Name:      "nslcd",
		ReadOnly:  true,
		MountPath: "/var/run/nslcd/socket",
	})

	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "a-registry.example.com/someimage",
	})

	testPod.Spec.Volumes = make([]api.Volume, 1)
	testPod.Spec.Volumes = append(testPod.Spec.Volumes, api.Volume{
		Name: "nslcd",
		VolumeSource: api.VolumeSource{
			HostPath: &api.HostPathVolumeSource{
				Path: "/var/run/nslcd/socket",
			},
		},
	})

	mounts := sets.NewString("/var/run/nslcd/socket", "/var/run/nscd/socket")
	handler := NewHostAutomounter(clientset, mounts)

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err != nil {
		t.Errorf("Expected admission to pass but it failed!")
	}

	foundVolumes := sets.NewString()
	for _, volume := range testPod.Spec.Volumes {
		if volume.HostPath != nil {
			foundVolumes.Insert(volume.HostPath.Path)
		}
	}

	if !foundVolumes.IsSuperset(mounts) {
		t.Errorf("Expected Volumes not found!")
	}

	for _, container := range testPod.Spec.Containers {
		containerMounts := sets.NewString()
		for _, volumeMount := range container.VolumeMounts {
			containerMounts.Insert(volumeMount.MountPath)
		}
		if !containerMounts.IsSuperset(mounts) {
			t.Errorf("Expected VolumeMounts not found! ")
		}
	}
}
