/*
Copyright 2024.

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

package controller

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"k8s.io/api/core/v1"
	errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	dnsv1alpha1 "github.com/delta10/dns-resolution-operator/api/v1alpha1"
)

type DNSResolverReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type ipMapOptions struct {
	CreateDomainIPMapping bool
}

var Config struct {
	EnableIPv6     bool
	IPExpiration   time.Duration
	MaxRequeueTime uint32
	DNS            *dns.ClientConfig
	DNSProtocol    string
	DNSEnvironment string
}

var IPCache IPCacheT

func init() {
	Config.EnableIPv6 = false
	if s := os.Getenv("DNS_ENABLE_IPV6"); s == "1" {
		Config.EnableIPv6 = true
	}

	Config.DNSEnvironment = os.Getenv("DNS_ENVIRONMENT")
	Config.DNS = new(dns.ClientConfig)
	switch os.Getenv("DNS_ENVIRONMENT") {
	case "resolv.conf-tcp":
		Config.DNSProtocol = "tcp"
		var err error
		Config.DNS, err = dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			panic("Could not open /etc/resolv.conf")
		}
	case "resolv.conf":
		Config.DNSProtocol = "udp"
		var err error
		Config.DNS, err = dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			panic("Could not open /etc/resolv.conf")
		}
	default:
		Config.DNSProtocol = "udp"
		Config.DNS.Port = "53"
		Config.DNSEnvironment = "kubernetes"
		// We add the servers at the beginning of every Reconcile
	}
	duration, err := time.ParseDuration(os.Getenv("IP_EXPIRATION"))
	if err == nil {
		Config.IPExpiration = duration
	} else {
		Config.IPExpiration = time.Hour * 12
	}
	mr, err := strconv.Atoi(os.Getenv("MAX_REQUEUE_TIME"))
	if err == nil {
		Config.MaxRequeueTime = uint32(mr)
	} else {
		Config.MaxRequeueTime = 3600
	}
}

//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers,verbs=get;list;watch
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers/finalizers,verbs=update
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=ipmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=ipmaps/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch

// Reconcile makes sure that each DNSResolver has an associated IPMap.
// It gets triggered by changes in DNSResolvers
func (r *DNSResolverReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	default_result_obj := ctrl.Result{
		RequeueAfter: time.Second * 10,
	}

	if Config.DNSEnvironment == "kubernetes" {
		Config.DNS.Servers = make([]string, 0, 2)
		// Obtain the pod IPs of kube-dns
		kube_dns_name := types.NamespacedName{
			Namespace: "kube-system",
			Name:      "kube-dns",
		}
		dns_ep := new(v1.Endpoints)
		err := r.Get(ctx, kube_dns_name, dns_ep)
		if err != nil {
			log.Error(err, "unable to fetch kube-dns Endpoints")
			return default_result_obj, err
		}
		for i := range dns_ep.Subsets {
			for _, addr := range dns_ep.Subsets[i].Addresses {
				if addr.IP != "" {
					Config.DNS.Servers = append(Config.DNS.Servers, addr.IP)
				}
			}
		}
	}

	// Obtain the current DNSResolver from the cluster
	var resolver dnsv1alpha1.DNSResolver
	if err := r.Get(ctx, req.NamespacedName, &resolver); err != nil {
		if errors.IsNotFound(err) {
			// any IPMaps should be deleted by Kubernetes. We still need to clear the cache
			IPCache.Delete(req.NamespacedName, "")
			log.Info("Removed IPMap from cache", "IPMap.Namespace", req.Namespace, "IPMap.Name", req.Name)
		} else {
			log.Error(err, "unable to fetch DNSResolver")
		}
		return default_result_obj, client.IgnoreNotFound(err)
	}

	options := &ipMapOptions{
		CreateDomainIPMapping: resolver.Spec.CreateDomainIPMapping,
	}

	// Create an empty IPMap to populate later
	ip_map := new(dnsv1alpha1.IPMap)
	ip_map.Name = req.Name
	ip_map.Namespace = req.Namespace

	// First, check if `resolver` has an associated IPMap already
	get_err := r.Get(ctx, req.NamespacedName, ip_map)

	// Make sure the ownerRef on `resolver` is set to the IPMap we are working on
	// This will fail if IPMap is already owned by another resource
	if err := controllerutil.SetControllerReference(&resolver, ip_map, r.Scheme); err != nil {
		return default_result_obj, err
	}

	if get_err != nil && errors.IsNotFound(get_err) {

		// There is no IPMap matching `resolver`, so we create one

		log.Info("Creating IPMap", "IPMap.Namespace", req.Namespace, "IPMap.Name", req.Name)

		_, minttl, err := ipmapUpdate(ip_map, resolver.Spec.DomainList, options)
		if err != nil {
			log.Error(err, "failed to generate IPMap Data")
			return default_result_obj, err
		}
		if err := r.Create(ctx, ip_map); err != nil {
			log.Error(err, "failed to create IPMap resource")
			return default_result_obj, err
		}

		requeue := time.Second * time.Duration(minttl+1)
		log.Info("Requeueing DNSResolver", "RequeueAfter", requeue)
		return ctrl.Result{RequeueAfter: requeue}, nil

	} else if get_err != nil {

		log.Error(get_err, "failed to get IPMap")
		return default_result_obj, get_err

	} else {

		// The IPMap matching `resolver` exists, so we update it

		updated, minttl, err := ipmapUpdate(ip_map, resolver.Spec.DomainList, options)
		if err != nil {
			log.Error(err, "failed to generate IPMap Data (update)")
			return default_result_obj, err
		}
		if updated {
			log.Info("Updating IPMap", "IPMap.Namespace", req.Namespace, "IPMap.Name", req.Name)
			if err := r.Update(ctx, ip_map); err != nil {
				log.Error(err, "failed to update IPMap resource")
				return default_result_obj, err
			}
		}

		requeue := time.Second * time.Duration(minttl+1)
		log.Info("Requeueing DNSResolver", "RequeueAfter", requeue)
		return ctrl.Result{RequeueAfter: requeue}, nil
	}
}

func (r *DNSResolverReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dnsv1alpha1.DNSResolver{}).
		Complete(r)
}
