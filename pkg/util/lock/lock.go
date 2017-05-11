package lock

import (
	"crypto/tls"
	"github.com/coreos/etcd/client"
	"github.com/coreos/etcd/pkg/tlsutil"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"k8s.io/kubernetes/pkg/util/clock"
	"net"
	"net/http"
	"sort"
	"time"
)

const (
	// prefix in Etcd for the Kerberos locks
	EtcdPrefix = "/ts/kerberos-locks/"
)

type Mutex struct {
	cl   client.Client
	kapi client.KeysAPI
}

type Lock struct {
	kapi  client.KeysAPI
	key   string
	index uint64
}

// create new Mutex connection
func NewMutex(endpoints []string, certFile, keyFile, CAFile string) (*Mutex, error) {
	defer clock.ExecTime(time.Now(), "NewMutex", "None")
	var transport client.CancelableTransport
	if certFile != "" && keyFile != "" && CAFile != "" {
		glog.V(5).Infof("TSLOG TSLOCK NewMutex setting SSL certFile %s keyFile %s CAFile %s with endpoints %v",
			certFile, keyFile, CAFile, endpoints)
		tlsCert, err := tlsutil.NewCert(certFile, keyFile, nil)
		if err != nil {
			return nil, err
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
		tlsCfg.ClientCAs, err = tlsutil.NewCertPool([]string{CAFile})
		if err != nil {
			return nil, err
		}
		tlsCfg.InsecureSkipVerify = true
		transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     tlsCfg,
		}
	} else {
		glog.V(5).Infof("TSLOG TSLOCK NewMutex setting without SSL with endpoints %v", endpoints)
		transport = client.DefaultTransport
	}
	cfg := client.Config{
		Endpoints:               endpoints,
		Transport:               transport,
		HeaderTimeoutPerRequest: time.Second,
	}
	if cl, err := client.New(cfg); err != nil {
		return nil, err
	} else {
		return &Mutex{cl: cl, kapi: client.NewKeysAPI(cl)}, nil
	}
}

// acquire lock (within Etcd folder)
func (m *Mutex) Acquire(key string, descr string, ttl uint64) (*Lock, error) {
	defer clock.ExecTime(time.Now(), "Acquire", key+"/"+descr)
	glog.V(5).Infof("TSLOG TSLOCK acquire for key %s", key)
	key = EtcdPrefix + key
	m.cl.Sync(context.Background())
	if lock, err := m.kapi.CreateInOrder(context.Background(), key, descr, &client.CreateInOrderOptions{}); err != nil {
		return nil, err
	} else {
		// wait for the lock by checking if our file index is the lowest
		for {
			if res, err := m.kapi.Get(context.Background(), key, &client.GetOptions{Recursive: true, Sort: true}); err != nil {
				return nil, err
			} else {
				if len(res.Node.Nodes) > 1 {
					sort.Sort(res.Node.Nodes)
					if res.Node.Nodes[0].CreatedIndex != lock.Node.CreatedIndex {
						if err = m.wait(lock.Node.Key); err != nil {
							return nil, err
						}
					} else {
						break
					}
				} else {
					break
				}
			}
		}

		// set description and ttl
		if _, err = m.kapi.Set(context.Background(), lock.Node.Key, lock.Node.Value,
			&client.SetOptions{TTL: time.Duration(ttl) * time.Second}); err != nil {
			return nil, err
		} else {
			glog.V(5).Infof("TSLOG TSLOCK got lock for key %s with %s", key, lock.Node.Key)
			return &Lock{m.kapi, lock.Node.Key, lock.Node.CreatedIndex}, nil
		}
	}
}

// wait to get the lock (i.e., lowest index matching our index)
func (m *Mutex) wait(key string) error {
	for {
		if res, err := m.kapi.Get(context.Background(), key, nil); err != nil {
			etcdErr, ok := err.(*client.Error)
			if ok && etcdErr.Code == client.ErrorCodeKeyNotFound {
				break
			} else {
				return err
			}
		} else {
			if len(res.Node.Nodes) == 0 {
				break
			} else {
				sort.Sort(res.Node.Nodes)
				currentLock := res.Node.Nodes[0]
				n := m.kapi.Watcher(currentLock.Key, &client.WatcherOptions{})
				if _, err = n.Next(context.Background()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// release the lock
func (l *Lock) Release() error {
	defer clock.ExecTime(time.Now(), "Release", l.key)
	glog.V(5).Infof("TSLOG TSLOCK release for key %s", l.key)
	if _, err := l.kapi.Delete(context.Background(), l.key, &client.DeleteOptions{}); err != nil {
		return err
	} else {
		return nil
	}
}
