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
	"flag"
	"io"
	"strings"

	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	apierrors "k8s.io/kubernetes/pkg/api/errors"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
)

var (
	registry = flag.String("enforced-docker-registry", "", "Only registry docker is allowed to fetch containers from")
)

func init() {
	admission.RegisterPlugin("RegistryEnforcer", func(clientset clientset.Interface, config io.Reader) (admission.Interface, error) {
		return NewRegistryEnforcer(clientset, *registry), nil
	})
}

// plugin contains the client used by the RegistryEnforcer admin controller
type plugin struct {
	*admission.Handler
	clientset clientset.Interface
	registry  string
}

// NewRegistryEnforcer creates a new instance of the RegistryEnforcer admission controller
func NewRegistryEnforcer(clientset clientset.Interface, registry string) admission.Interface {
	return &plugin{
		Handler:   admission.NewHandler(admission.Create, admission.Update),
		clientset: clientset,
		registry:  registry,
	}
}

func (p *plugin) Admit(a admission.Attributes) (err error) {
	if p.registry == "" {
		return apierrors.NewBadRequest("registryenforcer enabled but --enforced-docker-registry not set")
	}

	if a.GetResource().GroupResource() != api.Resource("pods") {
		return nil
	}

	pod, ok := a.GetObject().(*api.Pod)
	if !ok {
		return apierrors.NewBadRequest("Could not get Pod object from resource marked as pod.")

	}

	for i := 0; i < len(pod.Spec.Containers); i++ {
		container := &pod.Spec.Containers[i]
		if !strings.HasPrefix(container.Image, p.registry+"/") {
			return apierrors.NewBadRequest("Attempt to use docker image not in approved registry")
		}
	}
	return nil
}
