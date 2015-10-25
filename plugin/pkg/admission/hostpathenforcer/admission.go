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
	"flag"
	"fmt"
	"io"
	"strings"

	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"

	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	apierrors "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/util/sets"
)

var (
	pathsAllowedExactFlag    = flag.String("host-paths-allowed", "", "Comma separated list of exact paths on the host that containers are allowed to mount")
	pathsAllowedPrefixesFlag = flag.String("host-path-prefixes-allowed", "", "Comma separated list of prefixes allowed in paths on the host that can be mounted by containers")
)

func init() {
	admission.RegisterPlugin("HostPathEnforcer", func(client clientset.Interface, config io.Reader) (admission.Interface, error) {
		pathsAllowedSet := sets.NewString(strings.Split(*pathsAllowedExactFlag, ",")...)
		pathsAllowedPrefixes := strings.Split(*pathsAllowedPrefixesFlag, ",")
		admission := NewHostPathEnforcer(client, pathsAllowedSet, pathsAllowedPrefixes)
		return admission, nil
	})
}

type plugin struct {
	*admission.Handler

	pathsAllowedSet      sets.String
	pathsAllowedPrefixes []string
}

func NewHostPathEnforcer(cl clientset.Interface, pathsAllowedSet sets.String, pathsAllowedPrefixes []string) *plugin {
	return &plugin{
		Handler:              admission.NewHandler(admission.Create),
		pathsAllowedSet:      pathsAllowedSet,
		pathsAllowedPrefixes: pathsAllowedPrefixes,
	}
}

// If there are any Volumes that are using HostPath to mount paths from the Host,
// this will ensure that they are all either directly approved paths, or exist in
// prefixes that are directly approved. Note that this is not foolproof (symlinks,
// bindmounts, etc) but attacks against those require you have control of the
// node already anyway.
func (s *plugin) Admit(a admission.Attributes) (err error) {
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

	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			if !s.pathsAllowedSet.Has(volume.HostPath.Path) {
				prefixMatch := false
				for _, prefix := range s.pathsAllowedPrefixes {
					if strings.HasPrefix(volume.HostPath.Path, prefix) {
						prefixMatch = true
						break
					}
				}
				if !prefixMatch {
					return apierrors.NewBadRequest(fmt.Sprintf("%s is not in allowed host paths nor allowed host path prefixes", volume.HostPath.Path))
				}
			}
		}
	}

	return nil
}
