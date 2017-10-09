/*
Copyright 2014 The Kubernetes Authors.

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

package server

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	restful "github.com/emicklei/go-restful"
	"github.com/golang/glog"
	cadvisorapi "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	"github.com/prometheus/client_golang/prometheus"

	"k8s.io/kubernetes/pkg/api"
	apierrs "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/api/validation"
	"k8s.io/kubernetes/pkg/auth/authenticator"
	"k8s.io/kubernetes/pkg/auth/authorizer"
	"k8s.io/kubernetes/pkg/healthz"
	"k8s.io/kubernetes/pkg/httplog"
	krbutils "k8s.io/kubernetes/pkg/kerberosmanager"
	"k8s.io/kubernetes/pkg/kubelet/cm"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/server/portforward"
	"k8s.io/kubernetes/pkg/kubelet/server/remotecommand"
	"k8s.io/kubernetes/pkg/kubelet/server/stats"
	"k8s.io/kubernetes/pkg/kubelet/server/streaming"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util/clock"
	"k8s.io/kubernetes/pkg/util/configz"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
	"k8s.io/kubernetes/pkg/util/flushwriter"
	"k8s.io/kubernetes/pkg/util/limitwriter"
	"k8s.io/kubernetes/pkg/util/term"
	"k8s.io/kubernetes/pkg/volume"
)

const (
	metricsPath = "/metrics"
	specPath    = "/spec/"
	statsPath   = "/stats/"
	logsPath    = "/logs/"
)

// Server is a http.Handler which exposes kubelet functionality over HTTP.
type Server struct {
	auth             AuthInterface
	host             HostInterface
	restfulCont      containerInterface
	resourceAnalyzer stats.ResourceAnalyzer
	runtime          kubecontainer.Runtime
	// Kerberos manager
	krbManager krbutils.KrbManager
}

type TLSOptions struct {
	Config   *tls.Config
	CertFile string
	KeyFile  string
}

// containerInterface defines the restful.Container functions used on the root container
type containerInterface interface {
	Add(service *restful.WebService) *restful.Container
	Handle(path string, handler http.Handler)
	Filter(filter restful.FilterFunction)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	RegisteredWebServices() []*restful.WebService

	// RegisteredHandlePaths returns the paths of handlers registered directly with the container (non-web-services)
	// Used to test filters are being applied on non-web-service handlers
	RegisteredHandlePaths() []string
}

// filteringContainer delegates all Handle(...) calls to Container.HandleWithFilter(...),
// so we can ensure restful.FilterFunctions are used for all handlers
type filteringContainer struct {
	*restful.Container
	registeredHandlePaths []string
}

func (a *filteringContainer) Handle(path string, handler http.Handler) {
	a.HandleWithFilter(path, handler)
	a.registeredHandlePaths = append(a.registeredHandlePaths, path)
}
func (a *filteringContainer) RegisteredHandlePaths() []string {
	return a.registeredHandlePaths
}

// ListenAndServeKubeletServer initializes a server to respond to HTTP network requests on the Kubelet.
func ListenAndServeKubeletServer(
	host HostInterface,
	resourceAnalyzer stats.ResourceAnalyzer,
	address net.IP,
	port uint,
	tlsOptions *TLSOptions,
	auth AuthInterface,
	enableDebuggingHandlers bool,
	runtime kubecontainer.Runtime,
	criHandler http.Handler) {
	glog.Infof("Starting to listen on %s:%d", address, port)
	handler := NewServer(host, resourceAnalyzer, auth, enableDebuggingHandlers, runtime, criHandler)
	s := &http.Server{
		Addr:           net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)),
		Handler:        &handler,
		MaxHeaderBytes: 1 << 20,
	}
	if tlsOptions != nil {
		s.TLSConfig = tlsOptions.Config
		glog.Fatal(s.ListenAndServeTLS(tlsOptions.CertFile, tlsOptions.KeyFile))
	} else {
		glog.Fatal(s.ListenAndServe())
	}
}

// ListenAndServeKubeletReadOnlyServer initializes a server to respond to HTTP network requests on the Kubelet.
func ListenAndServeKubeletReadOnlyServer(host HostInterface, resourceAnalyzer stats.ResourceAnalyzer, address net.IP, port uint, runtime kubecontainer.Runtime) {
	glog.V(1).Infof("Starting to listen read-only on %s:%d", address, port)
	s := NewServer(host, resourceAnalyzer, nil, false, runtime, nil)

	server := &http.Server{
		Addr:           net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)),
		Handler:        &s,
		MaxHeaderBytes: 1 << 20,
	}
	glog.Fatal(server.ListenAndServe())
}

// AuthInterface contains all methods required by the auth filters
type AuthInterface interface {
	authenticator.Request
	authorizer.RequestAttributesGetter
	authorizer.Authorizer
}

// HostInterface contains all the kubelet methods required by the server.
// For testablitiy.
type HostInterface interface {
	GetContainerInfo(podFullName string, uid types.UID, containerName string, req *cadvisorapi.ContainerInfoRequest) (*cadvisorapi.ContainerInfo, error)
	GetContainerInfoV2(name string, options cadvisorapiv2.RequestOptions) (map[string]cadvisorapiv2.ContainerInfo, error)
	GetRawContainerInfo(containerName string, req *cadvisorapi.ContainerInfoRequest, subcontainers bool) (map[string]*cadvisorapi.ContainerInfo, error)
	GetCachedMachineInfo() (*cadvisorapi.MachineInfo, error)
	GetPods() []*api.Pod
	GetRunningPods() ([]*api.Pod, error)
	GetPodByName(namespace, name string) (*api.Pod, bool)
	RunInContainer(name string, uid types.UID, container string, cmd []string) ([]byte, error)
	ExecInContainer(name string, uid types.UID, container string, cmd []string, in io.Reader, out, err io.WriteCloser, tty bool, resize <-chan term.Size, timeout time.Duration) error
	AttachContainer(name string, uid types.UID, container string, in io.Reader, out, err io.WriteCloser, tty bool, resize <-chan term.Size) error
	GetKubeletContainerLogs(podFullName, containerName string, logOptions *api.PodLogOptions, stdout, stderr io.Writer) error
	ServeLogs(w http.ResponseWriter, req *http.Request)
	PortForward(name string, uid types.UID, port uint16, stream io.ReadWriteCloser) error
	StreamingConnectionIdleTimeout() time.Duration
	ResyncInterval() time.Duration
	GetHostname() string
	GetNode() (*api.Node, error)
	GetNodeConfig() cm.NodeConfig
	LatestLoopEntryTime() time.Time
	ImagesFsInfo() (cadvisorapiv2.FsInfo, error)
	RootFsInfo() (cadvisorapiv2.FsInfo, error)
	ListVolumesForPod(podUID types.UID) (map[string]volume.Volume, bool)
	PLEGHealthCheck() (bool, error)
	GetExec(podFullName string, podUID types.UID, containerName string, cmd []string, streamOpts remotecommand.Options) (*url.URL, error)
	GetAttach(podFullName string, podUID types.UID, containerName string, streamOpts remotecommand.Options) (*url.URL, error)
	GetPortForward(podName, podNamespace string, podUID types.UID) (*url.URL, error)
	GetPodDir(podUID types.UID) string
	GetClusterDomain() string
	GetPodServiceClusters(pod *api.Pod) (map[string]bool, error)
	GetAllPodKDCClusterNames(pod *api.Pod) (map[string]bool, error)
}

// NewServer initializes and configures a kubelet.Server object to handle HTTP requests.
func NewServer(
	host HostInterface,
	resourceAnalyzer stats.ResourceAnalyzer,
	auth AuthInterface,
	enableDebuggingHandlers bool,
	runtime kubecontainer.Runtime,
	criHandler http.Handler) Server {
	server := Server{
		host:             host,
		resourceAnalyzer: resourceAnalyzer,
		auth:             auth,
		restfulCont:      &filteringContainer{Container: restful.NewContainer()},
		runtime:          runtime,
	}
	if auth != nil {
		server.InstallAuthFilter()
	}
	server.InstallDefaultHandlers()
	if enableDebuggingHandlers {
		server.InstallDebuggingHandlers(criHandler)
	}
	// create Kerberos manager instance
	// no locking in server manager, so no lock config passed
	server.krbManager, _ = krbutils.NewKerberosManager(
		krbutils.KrbManagerParameters{},
	)

	return server
}

// InstallAuthFilter installs authentication filters with the restful Container.
func (s *Server) InstallAuthFilter() {
	s.restfulCont.Filter(func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		// Authenticate
		u, ok, err := s.auth.AuthenticateRequest(req.Request)
		if err != nil {
			glog.Errorf("Unable to authenticate the request due to an error: %v", err)
			resp.WriteErrorString(http.StatusUnauthorized, "Unauthorized")
			return
		}
		if !ok {
			resp.WriteErrorString(http.StatusUnauthorized, "Unauthorized")
			return
		}

		// Get authorization attributes
		attrs := s.auth.GetRequestAttributes(u, req.Request)

		// Authorize
		authorized, _, err := s.auth.Authorize(attrs)
		if err != nil {
			msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", u.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
			glog.Errorf(msg, err)
			resp.WriteErrorString(http.StatusInternalServerError, msg)
			return
		}
		if !authorized {
			msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", u.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
			glog.V(2).Info(msg)
			resp.WriteErrorString(http.StatusForbidden, msg)
			return
		}

		// Continue
		chain.ProcessFilter(req, resp)
	})
}

// InstallDefaultHandlers registers the default set of supported HTTP request
// patterns with the restful Container.
func (s *Server) InstallDefaultHandlers() {
	healthz.InstallHandler(s.restfulCont,
		healthz.PingHealthz,
		healthz.NamedCheck("syncloop", s.syncLoopHealthCheck),
		healthz.NamedCheck("pleg", s.plegHealthCheck),
	)
	var ws *restful.WebService
	ws = new(restful.WebService)
	ws.
		Path("/pods").
		Produces(restful.MIME_JSON)
	ws.Route(ws.GET("").
		To(s.getPods).
		Operation("getPods"))
	s.restfulCont.Add(ws)

	s.restfulCont.Add(stats.CreateHandlers(statsPath, s.host, s.resourceAnalyzer))
	s.restfulCont.Handle(metricsPath, prometheus.Handler())

	ws = new(restful.WebService)
	ws.
		Path(specPath).
		Produces(restful.MIME_JSON)
	ws.Route(ws.GET("").
		To(s.getSpec).
		Operation("getSpec").
		Writes(cadvisorapi.MachineInfo{}))
	s.restfulCont.Add(ws)

	// A handle to refresh Kerberos keytabs.
	// It gets invoked by krb5_keytab callback utility
	// each time the underlying keytab file on the host
	// has been updated.
	ws = new(restful.WebService)
	ws.
		Path("/refreshkeytabs")
	ws.Route(ws.POST("").
		To(s.refreshKeytabs))
	s.restfulCont.Add(ws)
}

const pprofBasePath = "/debug/pprof/"

// InstallDeguggingHandlers registers the HTTP request patterns that serve logs or run commands/containers
func (s *Server) InstallDebuggingHandlers(criHandler http.Handler) {
	var ws *restful.WebService

	ws = new(restful.WebService)
	ws.
		Path("/run")
	ws.Route(ws.POST("/{podNamespace}/{podID}/{containerName}").
		To(s.getRun).
		Operation("getRun"))
	ws.Route(ws.POST("/{podNamespace}/{podID}/{uid}/{containerName}").
		To(s.getRun).
		Operation("getRun"))
	s.restfulCont.Add(ws)

	ws = new(restful.WebService)
	ws.
		Path("/exec")
	ws.Route(ws.GET("/{podNamespace}/{podID}/{containerName}").
		To(s.getExec).
		Operation("getExec"))
	ws.Route(ws.POST("/{podNamespace}/{podID}/{containerName}").
		To(s.getExec).
		Operation("getExec"))
	ws.Route(ws.GET("/{podNamespace}/{podID}/{uid}/{containerName}").
		To(s.getExec).
		Operation("getExec"))
	ws.Route(ws.POST("/{podNamespace}/{podID}/{uid}/{containerName}").
		To(s.getExec).
		Operation("getExec"))
	s.restfulCont.Add(ws)

	ws = new(restful.WebService)
	ws.
		Path("/attach")
	ws.Route(ws.GET("/{podNamespace}/{podID}/{containerName}").
		To(s.getAttach).
		Operation("getAttach"))
	ws.Route(ws.POST("/{podNamespace}/{podID}/{containerName}").
		To(s.getAttach).
		Operation("getAttach"))
	ws.Route(ws.GET("/{podNamespace}/{podID}/{uid}/{containerName}").
		To(s.getAttach).
		Operation("getAttach"))
	ws.Route(ws.POST("/{podNamespace}/{podID}/{uid}/{containerName}").
		To(s.getAttach).
		Operation("getAttach"))
	s.restfulCont.Add(ws)

	ws = new(restful.WebService)
	ws.
		Path("/portForward")
	ws.Route(ws.POST("/{podNamespace}/{podID}").
		To(s.getPortForward).
		Operation("getPortForward"))
	ws.Route(ws.POST("/{podNamespace}/{podID}/{uid}").
		To(s.getPortForward).
		Operation("getPortForward"))
	s.restfulCont.Add(ws)

	ws = new(restful.WebService)
	ws.
		Path(logsPath)
	ws.Route(ws.GET("").
		To(s.getLogs).
		Operation("getLogs"))
	ws.Route(ws.GET("/{logpath:*}").
		To(s.getLogs).
		Operation("getLogs").
		Param(ws.PathParameter("logpath", "path to the log").DataType("string")))
	s.restfulCont.Add(ws)

	ws = new(restful.WebService)
	ws.
		Path("/containerLogs")
	ws.Route(ws.GET("/{podNamespace}/{podID}/{containerName}").
		To(s.getContainerLogs).
		Operation("getContainerLogs"))
	s.restfulCont.Add(ws)

	configz.InstallHandler(s.restfulCont)

	handlePprofEndpoint := func(req *restful.Request, resp *restful.Response) {
		name := strings.TrimPrefix(req.Request.URL.Path, pprofBasePath)
		switch name {
		case "profile":
			pprof.Profile(resp, req.Request)
		case "symbol":
			pprof.Symbol(resp, req.Request)
		case "cmdline":
			pprof.Cmdline(resp, req.Request)
		default:
			pprof.Index(resp, req.Request)
		}
	}

	// Setup pprof handlers.
	ws = new(restful.WebService).Path(pprofBasePath)
	ws.Route(ws.GET("/{subpath:*}").To(func(req *restful.Request, resp *restful.Response) {
		handlePprofEndpoint(req, resp)
	})).Doc("pprof endpoint")
	s.restfulCont.Add(ws)

	// The /runningpods endpoint is used for testing only.
	ws = new(restful.WebService)
	ws.
		Path("/runningpods/").
		Produces(restful.MIME_JSON)
	ws.Route(ws.GET("").
		To(s.getRunningPods).
		Operation("getRunningPods"))
	s.restfulCont.Add(ws)

	if criHandler != nil {
		s.restfulCont.Handle("/cri/", criHandler)
	}
}

// Checks if kubelet's sync loop  that updates containers is working.
func (s *Server) syncLoopHealthCheck(req *http.Request) error {
	duration := s.host.ResyncInterval() * 2
	minDuration := time.Minute * 5
	if duration < minDuration {
		duration = minDuration
	}
	enterLoopTime := s.host.LatestLoopEntryTime()
	if !enterLoopTime.IsZero() && time.Now().After(enterLoopTime.Add(duration)) {
		return fmt.Errorf("Sync Loop took longer than expected.")
	}
	return nil
}

// Checks if pleg, which lists pods periodically, is healthy.
func (s *Server) plegHealthCheck(req *http.Request) error {
	if ok, err := s.host.PLEGHealthCheck(); !ok {
		return fmt.Errorf("PLEG took longer than expected: %v", err)
	}
	return nil
}

// getContainerLogs handles containerLogs request against the Kubelet
func (s *Server) getContainerLogs(request *restful.Request, response *restful.Response) {
	podNamespace := request.PathParameter("podNamespace")
	podID := request.PathParameter("podID")
	containerName := request.PathParameter("containerName")

	if len(podID) == 0 {
		// TODO: Why return JSON when the rest return plaintext errors?
		// TODO: Why return plaintext errors?
		response.WriteError(http.StatusBadRequest, fmt.Errorf(`{"message": "Missing podID."}`))
		return
	}
	if len(containerName) == 0 {
		// TODO: Why return JSON when the rest return plaintext errors?
		response.WriteError(http.StatusBadRequest, fmt.Errorf(`{"message": "Missing container name."}`))
		return
	}
	if len(podNamespace) == 0 {
		// TODO: Why return JSON when the rest return plaintext errors?
		response.WriteError(http.StatusBadRequest, fmt.Errorf(`{"message": "Missing podNamespace."}`))
		return
	}

	query := request.Request.URL.Query()
	// backwards compatibility for the "tail" query parameter
	if tail := request.QueryParameter("tail"); len(tail) > 0 {
		query["tailLines"] = []string{tail}
		// "all" is the same as omitting tail
		if tail == "all" {
			delete(query, "tailLines")
		}
	}
	// container logs on the kubelet are locked to the v1 API version of PodLogOptions
	logOptions := &api.PodLogOptions{}
	if err := api.ParameterCodec.DecodeParameters(query, v1.SchemeGroupVersion, logOptions); err != nil {
		response.WriteError(http.StatusBadRequest, fmt.Errorf(`{"message": "Unable to decode query."}`))
		return
	}
	logOptions.TypeMeta = unversioned.TypeMeta{}
	if errs := validation.ValidatePodLogOptions(logOptions); len(errs) > 0 {
		response.WriteError(apierrs.StatusUnprocessableEntity, fmt.Errorf(`{"message": "Invalid request."}`))
		return
	}

	pod, ok := s.host.GetPodByName(podNamespace, podID)
	if !ok {
		response.WriteError(http.StatusNotFound, fmt.Errorf("pod %q does not exist\n", podID))
		return
	}
	// Check if containerName is valid.
	containerExists := false
	for _, container := range pod.Spec.Containers {
		if container.Name == containerName {
			containerExists = true
		}
	}
	if !containerExists {
		for _, container := range pod.Spec.InitContainers {
			if container.Name == containerName {
				containerExists = true
			}
		}
	}
	if !containerExists {
		response.WriteError(http.StatusNotFound, fmt.Errorf("container %q not found in pod %q\n", containerName, podID))
		return
	}

	if _, ok := response.ResponseWriter.(http.Flusher); !ok {
		response.WriteError(http.StatusInternalServerError, fmt.Errorf("unable to convert %v into http.Flusher, cannot show logs\n", reflect.TypeOf(response)))
		return
	}
	fw := flushwriter.Wrap(response.ResponseWriter)
	// Byte limit logic is already implemented in kuberuntime. However, we still need this for
	// old runtime integration.
	// TODO(random-liu): Remove this once we switch to CRI integration.
	if logOptions.LimitBytes != nil {
		fw = limitwriter.New(fw, *logOptions.LimitBytes)
	}
	response.Header().Set("Transfer-Encoding", "chunked")
	if err := s.host.GetKubeletContainerLogs(kubecontainer.GetPodFullName(pod), containerName, logOptions, fw, fw); err != nil {
		if err != limitwriter.ErrMaximumWrite {
			response.WriteError(http.StatusBadRequest, err)
		}
		return
	}
}

type test_struct struct {
	path string
}

// encodePods creates an api.PodList object from pods and returns the encoded
// PodList.
func encodePods(pods []*api.Pod) (data []byte, err error) {
	podList := new(api.PodList)
	for _, pod := range pods {
		podList.Items = append(podList.Items, *pod)
	}
	// TODO: this needs to be parameterized to the kubelet, not hardcoded. Depends on Kubelet
	//   as API server refactor.
	// TODO: Locked to v1, needs to be made generic
	codec := api.Codecs.LegacyCodec(unversioned.GroupVersion{Group: api.GroupName, Version: "v1"})
	return runtime.Encode(codec, podList)
}

// mutex to ensure that only one keytab refresh is happenning at a time
var keytabLock sync.RWMutex

// Refreshes keytabs for all containers using them. The keytab file content, which contains
// principals for all PODs on this node, gets split into parts and propagated into respective
// POD keytab files. It also trims the keytab file by removing all principals that are not
// referenced by any of the Pods known to kubelet.
func (s *Server) refreshKeytabs(request *restful.Request, response *restful.Response) {
	startLock := time.Now()
	keytabLock.Lock()
	defer keytabLock.Unlock()

	defer clock.ExecTime(time.Now(), "refreshKeytabs", "")
	trimKeytab := true
	glog.V(4).Infof(krbutils.TSL+"starting Keytab refresh in REST servlet, lock wait time was %d ns", time.Since(startLock).Nanoseconds())

	var lastError error
	response.AddHeader("Content-Type", "text/plain")
	if body, err := ioutil.ReadAll(request.Request.Body); err != nil {
		glog.Errorf(krbutils.TSE+"failed while reading POST body: %v", err)
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	} else {
		values, errParse := url.ParseQuery(string(body))
		if errParse != nil {
			glog.Errorf(krbutils.TSE+"failed while parsing the POST body: %v", errParse)
			response.WriteErrorString(http.StatusInternalServerError, errParse.Error())
			return
		}
		keytabFile := values["keytabpath"][0]
		if v, ok := values["trimkeytab"]; ok {
			if v[0] == "true" {
				trimKeytab = true
			} else {
				trimKeytab = false
			}
		} else {
			trimKeytab = true
		}
		glog.V(4).Infof(krbutils.TSL+"Keytab file (to be distributed to containers) is %s", keytabFile)

		pods := s.host.GetPods()
		allNeededPrincipals := map[string]bool{}
		realm := s.krbManager.GetKerberosRealm()
		for _, pod := range pods {
			if user, ok := pod.ObjectMeta.Annotations[krbutils.TSRunAsUserAnnotation]; ok {
				if services, ok := pod.ObjectMeta.Annotations[krbutils.TSServicesAnnotation]; ok {
					// do not distribute keytabs to Pods that use local keytabs (since they do not come from host keytab file)
					if krbLocal, ok := pod.ObjectMeta.Annotations[krbutils.TSKrbLocal]; ok && krbLocal == "true" {
						continue
					}
					if pod.Spec.SecurityContext.RunAsUser != nil {
						// skip the Pods being deleted
						if pod.DeletionTimestamp != nil {
							continue
						}
						glog.V(5).Infof(krbutils.TSL+"will refresh keytab file for pod %s", pod.Name)
						// extract from global keytab file the parts relevant to this POD
						if principals, err := s.refreshKeytab(keytabFile, pod, user, services, realm); err != nil {
							glog.Errorf(krbutils.TSE+"keytab refresh for pod %s failed: %v", pod.Name, err)
							lastError = err
						} else {
							glog.V(5).Infof(krbutils.TSL+"keytab file refresh for pod %s completed", pod.Name)
							// store which principals are still being used (for trimming of the keytab file later)
							for p := range principals {
								if !allNeededPrincipals[p] {
									allNeededPrincipals[p] = true
								}
							}
						}
					}
				}
			}
		}
		if lastError != nil {
			glog.V(3).Infof(krbutils.TSL+"keytab distribution to containers failed, reporting last error %+v", lastError.Error())
			response.WriteErrorString(http.StatusInternalServerError, lastError.Error())
		} else if trimKeytab {
			if nodeHostname, err := os.Hostname(); err != nil {
				glog.Errorf(krbutils.TSE+"could not retrieve hostname of the node, error: %+v", err)
			} else {
				// in addition, we need to protect user's keytab from being trimmed
				allNeededPrincipals[s.krbManager.GetKeytabOwner()+"/"+nodeHostname+"@"+s.krbManager.GetKerberosRealm()] = true
				glog.V(4).Infof(krbutils.TSL+"trimming will preserve principals: %+v", allNeededPrincipals)
				if err := trimKeytabFile(keytabFile, allNeededPrincipals); err != nil {
					glog.Errorf(krbutils.TSE+"error trimming the keytab file %+v", err)
					response.WriteErrorString(http.StatusInternalServerError, lastError.Error())
				} else {
					glog.V(2).Infof(krbutils.TSL + "Ending Keytab refresh in REST servlet with success")
				}
			}
		} else {
			glog.V(4).Infof(krbutils.TSL + "skipping keytab trimming")
		}
	}
}

// Refresh keytab file for a specific Pod by extracting the relevant principals (as declared in the Pod's manifest) and
// copying them into the container bindmount.
func (s *Server) refreshKeytab(keytabFile string, pod *api.Pod, userName, services, realm string) (map[string]bool, error) {
	// extract part of the keytab file that contains data related to this Pod
	// the only way to do it using ktutil is to make a copy of the master file
	// and remove all of the entries that are not needed

	defer clock.ExecTime(time.Now(), "refreshKeytab", keytabFile)

	glog.V(4).Infof(krbutils.TSL+"starting keytab refresh for pod %s and userName %s", pod.Name, userName)

	podDir := s.host.GetPodDir(pod.UID)

	file, err := ioutil.TempFile(os.TempDir(), "k8s-keytab")
	if err != nil {
		glog.Errorf(krbutils.TSE+"failed to create temp file: %v", err)
		return nil, err
	}
	tmpFile := file.Name()
	//	defer os.Remove(tmpFile)

	fileOut, err := ioutil.TempFile(os.TempDir(), "k8s-keytab-out")
	if err != nil {
		glog.Errorf(krbutils.TSE+"failed to create output temp file: %v", err)
		return nil, err
	}
	tmpFileOut := fileOut.Name()
	//	defer os.Remove(tmpFileOut)

	podAllClusters, err := s.host.GetAllPodKDCClusterNames(pod)
	if err != nil {
		glog.Errorf(krbutils.TSE+"error while getting service clusters for the POD %s during update, error: %v",
			pod.Name, err)
		return nil, err
	}

	//generate cartesian product of services and cluster names that represents all Kerberos principals this Pod needs
	principals := map[string]bool{}
	for clusterName, _ := range podAllClusters {
		for _, srv := range strings.Split(services, ",") {
			principals[srv+"/"+clusterName+"@"+realm] = true
		}
	}
	glog.V(4).Infof(krbutils.TSL+"refreshing keytab for POD %s with clusterNames %+v podDir %s for user %s and services %+v principals %+v",
		pod.Name, podAllClusters, podDir, userName, services, principals)
	if out, err := krbutils.RunCommand("/bin/cp", "-f", keytabFile, tmpFile); err != nil {
		glog.Errorf(krbutils.TSE+"error copying master keytab file to temporary file, error: %v, output: %s", err, string(out))
		return nil, err
	}

	// extract the required principals
	if err := extractKeytab(tmpFile, tmpFileOut, principals); err != nil {
		glog.Errorf(krbutils.TSE+"extraction of principals from keytab %s for pod %s failed, error: %v", tmpFile, pod.Name, err)
		return nil, err
	}
	if _, err := os.Stat(tmpFileOut); os.IsNotExist(err) {
		// this POD does not yet have entry in the host keytab file, do not attempt to create a keytab
		// this situation happens when the Pod is already in K8s data structures, but Kubelet did not
		// invoke krb5_keytab for it yet.
		glog.V(4).Infof(krbutils.TSL + "extraction produced the empty keytab, returning")
		return principals, nil
	}

	startCopyAndOwnership := time.Now()
	// create the Pod directory - we need to do it since the docker was not invoked yet
	podKeytabDirectory := path.Join(podDir, krbutils.KeytabDirForPod)
	exe := utilexec.New()
	cmd := exe.Command(
		"mkdir",
		"-p",
		podKeytabDirectory)
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Errorf(krbutils.TSE+"unable to create Pod keytab directory: %s %v", out, err)
	}

	// copy the extracted part of the keytab to the container's keytab directory
	podKeytabFile := path.Join(podDir, krbutils.KeytabDirForPod, userName)
	exe = utilexec.New()
	cmd = exe.Command(
		"/bin/cp",
		"-f",
		tmpFileOut,
		podKeytabFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Errorf(krbutils.TSE+"unable to copy the extracted keytab for user %s from tmpFile %s to destination %s: %s %v",
			userName, tmpFileOut, podKeytabFile, out, err)
		return nil, err
	}

	// modify the file permissions so the keytab file is readable only to the runAsUser declared in the manifest
	runAsUser := pod.Spec.SecurityContext.RunAsUser
	if runAsUser == nil {
		glog.V(4).Infof(krbutils.TSL + "runAsUser not set, skipping keytab ownership change")
		return principals, nil
	}
	owner := strconv.Itoa(int(*runAsUser)) + ":" + s.krbManager.GetTicketUserGroup()
	glog.V(4).Infof(krbutils.TSL+"keytab file %s ownership will be changed to runAsUser %s", podKeytabFile, owner)
	err = os.Chmod(podKeytabFile, 0600)
	if err != nil {
		glog.Errorf(krbutils.TSE+"error changing keytab file %s permission to 0600, error: %v", podKeytabFile, err)
		return nil, err
	}
	cmd = exe.Command("/bin/chown", owner, podKeytabFile)
	_, err = cmd.CombinedOutput()
	if err != nil {
		glog.Errorf(krbutils.TSE+"error changing owner of the keytab file %s to %v, error: %v", podKeytabFile, owner, err)
		return nil, err
	}
	glog.V(4).Infof(krbutils.TSL+"keytab file %s ownership has been changed to runAsUser %s, copy and ownership exectime %s",
		podKeytabFile, owner, time.Since(startCopyAndOwnership))
	return principals, nil
}

// trim keytab file by removing principals that are not referenced by any Pod. The second argument
// holds all principals that are needed, all others are removed.
func trimKeytabFile(keytabFile string, allNeededPrincipals map[string]bool) error {
	defer clock.ExecTime(time.Now(), "trimKeytabFile", keytabFile)

	glog.V(4).Infof(krbutils.TSL+"will trim keytab file %s keeping principals %+v", keytabFile, allNeededPrincipals)
	tmpFileOut, err := ioutil.TempFile(os.TempDir(), "k8s-keytab-out")
	if err != nil {
		glog.Errorf(krbutils.TSE+"failed to create output temp file for trimming: %+v", err)
		return err
	}
	tmpFileOutName := tmpFileOut.Name()
	//	defer os.Remove(tmpFileOutName)

	if err := extractKeytab(keytabFile, tmpFileOutName, allNeededPrincipals); err != nil {
		glog.Errorf(krbutils.TSE+"failed to extract keytab for trimming: %+v", err)
		return err
	}
	exe := utilexec.New()
	cmd := exe.Command(
		"/bin/cp",
		"-f",
		tmpFileOutName,
		keytabFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Errorf(krbutils.TSE+"unable to copy the trimmed keytab file %s to destination %s, output %s, err %+v",
			tmpFileOut, keytabFile, out, err)
		return err
	} else {
		glog.V(4).Infof(krbutils.TSL+"keytab has been trimmed at %s, output %s", keytabFile, out)
		return nil
	}
}

func extractKeytab(keytabFilename, keytabFilenameOut string, principals map[string]bool) error {
	defer clock.ExecTime(time.Now(), "extractKeytab", keytabFilename)

	// list all entries in the keytab file
	outb, errb, err := krbutils.ExecWithPipe("printf", krbutils.KtutilPath, []string{"rkt " + keytabFilename + "\nlist\nq\n"}, []string{})
	if err != nil {
		glog.Errorf(krbutils.TSE+"exec with pipe failed, error %v", err)
		return err
	}
	if errb.Len() > 0 {
		glog.Errorf(krbutils.TSE+"unable to list keys in keytab file %s, output %v, error %v", keytabFilename, outb, errb)
		return errors.New(outb.String() + " " + errb.String())
	}

	glog.V(4).Infof(krbutils.TSL + "preparing keytab extraction string")
	re := regexp.MustCompile("  +")
	keyArray := strings.Split(string(re.ReplaceAll(bytes.TrimSpace(outb.Bytes()), []byte(" "))), "\n")
	toRemove := "rkt " + keytabFilename + "\n"
	for c := len(keyArray) - 1; c >= 0; c-- {
		key := strings.Trim(keyArray[c], " ")
		// skip header outputed by the ktutil
		if c < 4 {
			continue
		}
		items := strings.Split(key, " ")
		// skip irrelevant parts of the klist output
		if len(items) != 3 {
			continue
		}
		if !principals[items[2]] {
			toRemove = toRemove + "delent " + items[0] + "\n"
		}
	}
	toRemove = toRemove + "wkt " + keytabFilenameOut + "\nq\n"
	glog.V(4).Infof(krbutils.TSL + "keytab extraction string to be executed has been prepared")

	// need to remove actual tmpfile since ktutil can not write to an existing empty file
	// (if attempted, an incorrect file format error is raised)
	if err := os.Remove(keytabFilenameOut); err != nil {
		glog.Errorf(krbutils.TSE+"unable to remove  ORtempfile %s, error %v", keytabFilenameOut, err)
		return err
	}

	// extract the keys
	outb, errb, err = krbutils.ExecWithPipe("printf", krbutils.KtutilPath, []string{toRemove}, []string{})
	if err != nil {
		glog.Errorf(krbutils.TSE+"exec with pipe failed while extracting the keys, error %v", err)
		return err
	}
	if errb.Len() > 0 {
		glog.Errorf(krbutils.TSE+"unable to remove keys from keytab file %s and write to keytab file %s, output %v, error %v",
			keytabFilename, keytabFilenameOut, outb.String(), errb.String())
		return errors.New(outb.String() + " " + errb.String())
	} else {
		glog.V(4).Infof(krbutils.TSL+"ktutil returned with, %s", outb.String())
	}
	return nil
}

// getPods returns a list of pods bound to the Kubelet and their spec.
func (s *Server) getPods(request *restful.Request, response *restful.Response) {
	pods := s.host.GetPods()
	data, err := encodePods(pods)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
		return
	}
	writeJsonResponse(response, data)
}

// getRunningPods returns a list of pods running on Kubelet. The list is
// provided by the container runtime, and is different from the list returned
// by getPods, which is a set of desired pods to run.
func (s *Server) getRunningPods(request *restful.Request, response *restful.Response) {
	pods, err := s.host.GetRunningPods()
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
		return
	}
	data, err := encodePods(pods)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
		return
	}
	writeJsonResponse(response, data)
}

// getLogs handles logs requests against the Kubelet.
func (s *Server) getLogs(request *restful.Request, response *restful.Response) {
	s.host.ServeLogs(response, request.Request)
}

// getSpec handles spec requests against the Kubelet.
func (s *Server) getSpec(request *restful.Request, response *restful.Response) {
	info, err := s.host.GetCachedMachineInfo()
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
		return
	}
	response.WriteEntity(info)
}

type requestParams struct {
	podNamespace  string
	podName       string
	podUID        types.UID
	containerName string
	cmd           []string
	streamOpts    remotecommand.Options
}

func getRequestParams(req *restful.Request) requestParams {
	streamOpts, err := remotecommand.NewOptions(req.Request)
	if err != nil {
		glog.Warningf("Unable to parse request stream options: %v", err)
	}
	if streamOpts == nil {
		streamOpts = &remotecommand.Options{}
	}
	return requestParams{
		podNamespace:  req.PathParameter("podNamespace"),
		podName:       req.PathParameter("podID"),
		podUID:        types.UID(req.PathParameter("uid")),
		containerName: req.PathParameter("containerName"),
		cmd:           req.Request.URL.Query()[api.ExecCommandParamm],
		streamOpts:    *streamOpts,
	}
}

// getAttach handles requests to attach to a container.
func (s *Server) getAttach(request *restful.Request, response *restful.Response) {
	params := getRequestParams(request)
	pod, ok := s.host.GetPodByName(params.podNamespace, params.podName)
	if !ok {
		response.WriteError(http.StatusNotFound, fmt.Errorf("pod does not exist"))
		return
	}

	podFullName := kubecontainer.GetPodFullName(pod)
	redirect, err := s.host.GetAttach(podFullName, params.podUID, params.containerName, params.streamOpts)
	if err != nil {
		response.WriteError(streaming.HTTPStatus(err), err)
		return
	}
	if redirect != nil {
		http.Redirect(response.ResponseWriter, request.Request, redirect.String(), http.StatusFound)
		return
	}

	remotecommand.ServeAttach(response.ResponseWriter,
		request.Request,
		s.host,
		podFullName,
		params.podUID,
		params.containerName,
		s.host.StreamingConnectionIdleTimeout(),
		remotecommand.DefaultStreamCreationTimeout,
		remotecommand.SupportedStreamingProtocols)
}

// getExec handles requests to run a command inside a container.
func (s *Server) getExec(request *restful.Request, response *restful.Response) {
	params := getRequestParams(request)
	pod, ok := s.host.GetPodByName(params.podNamespace, params.podName)
	if !ok {
		response.WriteError(http.StatusNotFound, fmt.Errorf("pod does not exist"))
		return
	}

	podFullName := kubecontainer.GetPodFullName(pod)
	redirect, err := s.host.GetExec(podFullName, params.podUID, params.containerName, params.cmd, params.streamOpts)
	if err != nil {
		response.WriteError(streaming.HTTPStatus(err), err)
		return
	}
	if redirect != nil {
		http.Redirect(response.ResponseWriter, request.Request, redirect.String(), http.StatusFound)
		return
	}

	remotecommand.ServeExec(response.ResponseWriter,
		request.Request,
		s.host,
		podFullName,
		params.podUID,
		params.containerName,
		s.host.StreamingConnectionIdleTimeout(),
		remotecommand.DefaultStreamCreationTimeout,
		remotecommand.SupportedStreamingProtocols)
}

// getRun handles requests to run a command inside a container.
func (s *Server) getRun(request *restful.Request, response *restful.Response) {
	params := getRequestParams(request)
	pod, ok := s.host.GetPodByName(params.podNamespace, params.podName)
	if !ok {
		response.WriteError(http.StatusNotFound, fmt.Errorf("pod does not exist"))
		return
	}

	// For legacy reasons, run uses different query param than exec.
	params.cmd = strings.Split(request.QueryParameter("cmd"), " ")
	data, err := s.host.RunInContainer(kubecontainer.GetPodFullName(pod), params.podUID, params.containerName, params.cmd)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
		return
	}
	writeJsonResponse(response, data)
}

// Derived from go-restful writeJSON.
func writeJsonResponse(response *restful.Response, data []byte) {
	if data == nil {
		response.WriteHeader(http.StatusOK)
		// do not write a nil representation
		return
	}
	response.Header().Set(restful.HEADER_ContentType, restful.MIME_JSON)
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(data); err != nil {
		glog.Errorf("Error writing response: %v", err)
	}
}

// getPortForward handles a new restful port forward request. It determines the
// pod name and uid and then calls ServePortForward.
func (s *Server) getPortForward(request *restful.Request, response *restful.Response) {
	params := getRequestParams(request)
	pod, ok := s.host.GetPodByName(params.podNamespace, params.podName)
	if !ok {
		response.WriteError(http.StatusNotFound, fmt.Errorf("pod does not exist"))
		return
	}
	if len(params.podUID) > 0 && pod.UID != params.podUID {
		response.WriteError(http.StatusNotFound, fmt.Errorf("pod not found"))
		return
	}

	redirect, err := s.host.GetPortForward(pod.Name, pod.Namespace, pod.UID)
	if err != nil {
		response.WriteError(streaming.HTTPStatus(err), err)
		return
	}
	if redirect != nil {
		http.Redirect(response.ResponseWriter, request.Request, redirect.String(), http.StatusFound)
		return
	}

	portforward.ServePortForward(response.ResponseWriter,
		request.Request,
		s.host,
		kubecontainer.GetPodFullName(pod),
		params.podUID,
		s.host.StreamingConnectionIdleTimeout(),
		remotecommand.DefaultStreamCreationTimeout)
}

// ServeHTTP responds to HTTP requests on the Kubelet.
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer httplog.NewLogged(req, &w).StacktraceWhen(
		httplog.StatusIsNot(
			http.StatusOK,
			http.StatusFound,
			http.StatusMovedPermanently,
			http.StatusTemporaryRedirect,
			http.StatusBadRequest,
			http.StatusNotFound,
			http.StatusSwitchingProtocols,
		),
	).Log()
	s.restfulCont.ServeHTTP(w, req)
}
