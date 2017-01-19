/*
Copyright 2015 The Kubernetes Authors.

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

package enforcerunasuser

import (
	"errors"
	"io"

	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	apierrors "k8s.io/kubernetes/pkg/api/errors"
	podutil "k8s.io/kubernetes/pkg/util/pod"
)

func init() {
	admission.RegisterPlugin("TSEnforceRunAsUser", func(client clientset.Interface, config io.Reader) (admission.Interface, error) {
		return NewTSEnforceRunAsUser(), nil
	})
}

type enforceRunAsUser struct {
	*admission.Handler
}

func (a *enforceRunAsUser) Admit(attributes admission.Attributes) (err error) {
	// Ignore all calls to subresources or resources other than pods.
	if len(attributes.GetSubresource()) != 0 || attributes.GetResource().GroupResource() != api.Resource("pods") {
		return nil
	}
	pod, ok := attributes.GetObject().(*api.Pod)
	if !ok {
		return apierrors.NewBadRequest("Resource was marked with kind Pod but was unable to be converted")
	}

	if runAsUserName, err := podutil.GetRunAsUsername(pod); err != nil {
		glog.Errorf("no runAsUser annotation for pod %s in namespace %s, error is: %+v",
			attributes.GetName(), attributes.GetNamespace(), err)
		return admission.NewForbidden(attributes, errors.New("runAsUser is required in the manifest"))
	} else {
		pod.ObjectMeta.Annotations["ts/runasusername"] = runAsUserName
		glog.V(0).Infof(
			"there is annotation %s for pod %s in namespace %s",
			pod.ObjectMeta.Annotations["ts/runasusername"],
			attributes.GetName(), attributes.GetNamespace())
		return nil
	}
}

func NewTSEnforceRunAsUser() admission.Interface {
	return &enforceRunAsUser{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}
