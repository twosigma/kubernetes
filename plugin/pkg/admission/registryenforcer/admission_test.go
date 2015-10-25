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

package registryenforcer

import (
	"strconv"
	"testing"

	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
)

func validPod(name string, numContainers int, imagePrefix string) api.Pod {
	pod := api.Pod{ObjectMeta: api.ObjectMeta{Name: name, Namespace: "test"},
		Spec: api.PodSpec{},
	}
	pod.Spec.Containers = make([]api.Container, 0, numContainers)
	for i := 0; i < numContainers; i++ {
		pod.Spec.Containers = append(pod.Spec.Containers, api.Container{
			Image: imagePrefix + strconv.Itoa(i),
		})
	}
	return pod
}

// Test that a pod with a valid image & an invalid image fails
func TestMixedImage(t *testing.T) {
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
	handler := &plugin{
		clientset: clientset,
		registry:  "a-registry.example.com",
	}

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Update, nil))
	if err == nil {
		t.Errorf("Expected admission to fail but it passed!")
	}
}

// Test that a pod with only invalid images fails
func TestUnauthorizedImage(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	testPod := validPod("test", 2, "test-registry.example.com/testimage:")

	handler := &plugin{
		clientset: clientset,
		registry:  "another-registry.example.com",
	}

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Update, nil))
	if err == nil {
		t.Errorf("Expected admission to fail but it passed!")
	}
}

// Test that a pod with only valid images passes
func TestAuthorizedImage(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	testPod := validPod("test", 2, "test-registry.example.com/testimage:")

	handler := &plugin{
		clientset: clientset,
		registry:  "test-registry.example.com",
	}

	err := handler.Admit(admission.NewAttributesRecord(&testPod, nil, api.Kind("Pod").WithVersion("version"), testPod.Namespace, testPod.Name, api.Resource("pods").WithVersion("version"), "", admission.Update, nil))
	if err != nil {
		t.Errorf("Expected admission to pass but it failed!")
	}
}
