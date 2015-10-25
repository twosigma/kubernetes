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

package hostpathenforcer

import (
	"testing"

	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
	"k8s.io/kubernetes/pkg/util/sets"
)

// Test that admission fails with unauthorized volume only
func TestUnauthorizedVolume(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	testPod := api.Pod{ObjectMeta: api.ObjectMeta{Name: "testPod", Namespace: "test"},
		Spec: api.PodSpec{},
	}
	testPod.Spec.Containers = make([]api.Container, 0, 1)
	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "b-registry.example.com/someimage",
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

	allowedPaths := sets.NewString("/tmp/no", "/var/lib")
	allowedPrefixes := make([]string, 0, 0)

	handler := NewHostPathEnforcer(clientset, allowedPaths, allowedPrefixes)

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err == nil {
		t.Errorf("Expected admission to fail but it passed!")
	}
}

// Test that admission passes with authorized volumes with exact path match
func TestAuthorizedVolume(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	testPod := api.Pod{ObjectMeta: api.ObjectMeta{Name: "testPod", Namespace: "test"},
		Spec: api.PodSpec{},
	}
	testPod.Spec.Containers = make([]api.Container, 0, 1)
	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "b-registry.example.com/someimage",
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

	allowedPaths := sets.NewString("/tmp/wat", "/var/lib")
	allowedPrefixes := make([]string, 0, 0)

	handler := NewHostPathEnforcer(clientset, allowedPaths, allowedPrefixes)

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err != nil {
		t.Errorf("Expected admission to pass but it failed!")
	}
}

// Test that admission passes with some volumes authorized by exact match & some by prefix match
func TestMixedAuthorizedVolume(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	testPod := api.Pod{ObjectMeta: api.ObjectMeta{Name: "testPod", Namespace: "test"},
		Spec: api.PodSpec{},
	}
	testPod.Spec.Containers = make([]api.Container, 0, 1)
	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "b-registry.example.com/someimage",
	})

	testPod.Spec.Volumes = make([]api.Volume, 2)
	testPod.Spec.Volumes = append(testPod.Spec.Volumes, api.Volume{
		Name: "just-a-test",
		VolumeSource: api.VolumeSource{
			HostPath: &api.HostPathVolumeSource{
				Path: "/tmp/wat",
			},
		},
	})
	testPod.Spec.Volumes = append(testPod.Spec.Volumes, api.Volume{
		Name: "just-another-test",
		VolumeSource: api.VolumeSource{
			HostPath: &api.HostPathVolumeSource{
				Path: "/var/lib",
			},
		},
	})

	allowedPaths := sets.NewString("/var/lib")
	allowedPrefixes := []string{"/tmp/"}

	handler := NewHostPathEnforcer(clientset, allowedPaths, allowedPrefixes)

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err != nil {
		t.Errorf("Expected admission to pass but it failed!")
	}
}

// Test that admission fails with some authorized volumes & some unauthorized
func TestMixedUnauthorizedVolume(t *testing.T) {
	clientset := fake.NewSimpleClientset()

	testPod := api.Pod{ObjectMeta: api.ObjectMeta{Name: "testPod", Namespace: "test"},
		Spec: api.PodSpec{},
	}
	testPod.Spec.Containers = make([]api.Container, 0, 1)
	testPod.Spec.Containers = append(testPod.Spec.Containers, api.Container{
		Image: "b-registry.example.com/someimage",
	})

	testPod.Spec.Volumes = make([]api.Volume, 2)
	testPod.Spec.Volumes = append(testPod.Spec.Volumes, api.Volume{
		Name: "just-a-test",
		VolumeSource: api.VolumeSource{
			HostPath: &api.HostPathVolumeSource{
				Path: "/tmp/wat",
			},
		},
	})
	testPod.Spec.Volumes = append(testPod.Spec.Volumes, api.Volume{
		Name: "just-another-test",
		VolumeSource: api.VolumeSource{
			HostPath: &api.HostPathVolumeSource{
				Path: "/var/lib/secret",
			},
		},
	})

	allowedPaths := sets.NewString("/var/lib")
	allowedPrefixes := []string{"/tmp/"}

	handler := NewHostPathEnforcer(clientset, allowedPaths, allowedPrefixes)

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Create, nil))
	if err == nil {
		t.Errorf("Expected admission to fail but it passed!")
	}
}
