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
	"fmt"
	"io"

	"github.com/golang/glog"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"

	//	apierrors "k8s.io/kubernetes/pkg/api/errors"
	//	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/api/errors"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	glog.V(1).Infof("AKAK registering admission runasuser")
	plugins.Register("TSEnforceRunAsUser", func(config io.Reader) (admission.Interface, error) {
		return NewTSEnforceRunAsUser(), nil
	})
}

var _ = admission.Interface(&enforceRunAsUser{})

type enforceRunAsUser struct {
	*admission.Handler
}

func (a *enforceRunAsUser) Admit(attributes admission.Attributes) (err error) {
	// Ignore all calls to subresources or resources other than pods.
	// Ignore all operations other than CREATE.
	if len(attributes.GetSubresource()) != 0 ||
		attributes.GetResource().GroupResource() != api.Resource("pods") || attributes.GetOperation() != admission.Create {
		return nil
	}

	pod, ok := attributes.GetObject().(*api.Pod)
	if !ok {
		return errors.NewBadRequest("Resource was marked with kind Pod but was unable to be converted")
	}

	if runAsUserName, err := krbutils.GetRunAsUsername_Legacy(pod); err != nil {
		namespace := attributes.GetNamespace()
		if (namespace == "kube-system") || (namespace == "contadm") {
			glog.V(5).Infof(krbutils.TSL+"TSAdmission: admitting system namespace %s", namespace)
			return nil
		} else {
			glog.Errorf(krbutils.TSE+"no runAsUser annotation for pod %s in namespace %s, error is: %+v",
				attributes.GetName(), namespace, err)
			return admission.NewForbidden(attributes, fmt.Errorf("unable to %s %v at this time because runAsUser is required in the manifest",
				attributes.GetOperation(), attributes.GetResource()))
		}
	} else {
                namespace := attributes.GetNamespace()
                if (namespace != "kube-system") && (namespace != "contadm") {
		        // verify that all init and regular containers within the Pod have the same runAsUser as the Pod, if set
		        allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
		        for _, cont := range allContainers {
			        if cont.SecurityContext != nil && cont.SecurityContext.RunAsUser != nil {
				        if int(*cont.SecurityContext.RunAsUser) != int(*pod.Spec.SecurityContext.RunAsUser) {
					        return admission.NewForbidden(attributes, fmt.Errorf("unable to %s %v at this time because runAsUser at container level has to match the Pod level, if set", attributes.GetOperation(), attributes.GetResource()))
				        }
			        }
		        }
                } else {
                        glog.V(5).Infof(krbutils.TSL+"TSAdmission: Admitting system namespace %s, skipping validation.", namespace)
                }
		if pod.ObjectMeta.Annotations == nil {
			pod.ObjectMeta.Annotations = map[string]string{}
		}
		pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation] = runAsUserName
		glog.V(0).Infof(
			krbutils.TSL+"there is annotation tsrunasuser %s for pod %s in namespace %s",
			pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation],
			attributes.GetName(), attributes.GetNamespace())
		return nil
	}
}

func NewTSEnforceRunAsUser() admission.Interface {
	return &enforceRunAsUser{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}
