package toleration

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/golang/glog"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"

	"k8s.io/apimachinery/pkg/api/errors"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register("TSToleration", func(config io.Reader) (admission.Interface, error) {
		return NewTSToleration(), nil
	})
}

var _ = admission.Interface(&toleration{})

type toleration struct {
	*admission.Handler
}

// toleration json object passed in annotation
type tolerationAnnotation struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Admit() checks of the Pod declares toleration annotation (in the pre 1.6 format) and, if so, adds toleration to the PodSpec
//
// Inputs:
// - attributes - admission request, including the Pod
//
// Output:
// - err - error, if any, or nil
func (a *toleration) Admit(attributes admission.Attributes) (err error) {
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

	if pod.ObjectMeta.Annotations != nil {
		if annotation, ok := pod.ObjectMeta.Annotations["scheduler.alpha.kubernetes.io/tolerations"]; ok {
			tolerationArray := []tolerationAnnotation{}
			if err := json.Unmarshal([]byte(annotation), &tolerationArray); err == nil {
				for _, toleration := range tolerationArray {
					t := api.Toleration{
						Key:      toleration.Key,
						Operator: api.TolerationOpEqual,
						Value:    toleration.Value,
					}
					if pod.Spec.Tolerations == nil {
						pod.Spec.Tolerations = []api.Toleration{}
					}
					pod.Spec.Tolerations = append(pod.Spec.Tolerations, t)
				}
			} else {
				return errors.NewBadRequest(fmt.Sprintf("Toleration json string %s in annotation could not be unmarshalled: %+v",
					annotation, err))
			}
		}
	}
	glog.V(3).Infof(
		krbutils.TSL+"the final Pod tolerations for pod %s in namespace %s are %+v",
		attributes.GetName(),
		attributes.GetNamespace(),
		pod.Spec.Tolerations)
	return nil
}

// create a new TStoleration controller
func NewTSToleration() admission.Interface {
	return &toleration{
		Handler: admission.NewHandler(admission.Create, admission.Update),
	}
}
