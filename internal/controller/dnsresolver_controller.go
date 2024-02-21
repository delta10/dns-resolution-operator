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
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/miekg/dns"
	"k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

type resolverOptions struct {
	GenerateType          string
}

var Config struct {
	EnableIPv6         bool
	IPExpiration       time.Duration
	MaxRequeueTime     uint32
	DNS                *dns.ClientConfig
	DNSProtocol        string
	DNSEnvironment     string
	UpstreamDNSService string
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
		s := os.Getenv("DNS_UPSTREAM_SERVICE")
		if s == "" {
			Config.UpstreamDNSService = "kube-dns"
		} else {
			Config.UpstreamDNSService = s
		}
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

func logRequeue(start time.Time, requeue time.Duration, log *logr.Logger) {
	log.Info("Requeueing DNSResolver", "RequeueAfter", requeue, "Reconcile duration", time.Since(start).String())
}

//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers,verbs=get;list;watch
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers/finalizers,verbs=update
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=ipmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=ipmaps/finalizers,verbs=update
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=endpoints,verbs=get;list;watch

// Reconcile makes sure that each DNSResolver has an associated IPMap.
// It gets triggered by changes in DNSResolvers
func (r *DNSResolverReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start_time := time.Now()
	log := log.FromContext(ctx)
	// result object used for errors
	default_result_obj := ctrl.Result{}

	if Config.DNSEnvironment == "kubernetes" {
		Config.DNS.Servers = make([]string, 0, 2)

		// Obtain the pod IPs of kube-dns
		kube_dns_name := types.NamespacedName{
			Namespace: "kube-system",
			Name:      Config.UpstreamDNSService,
		}
		dns_ep := new(v1.Endpoints)
		err := r.Get(ctx, kube_dns_name, dns_ep)
		if err != nil {
			return default_result_obj, fmt.Errorf("unable to fetch kube-dns Endpoints: %w", err)
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
			err = fmt.Errorf("unable to fetch DNSResolver: %w", err)
		}
		return default_result_obj, client.IgnoreNotFound(err)
	}

	options := &resolverOptions{
		GenerateType: resolver.Spec.GenerateType,
	}

	// Create an empty IPMap to populate later
	ip_map := new(dnsv1alpha1.IPMap)
	ip_map.Name = req.Name
	ip_map.Namespace = req.Namespace

	// First, check if `resolver` has an associated IPMap already
	get_err := r.Get(ctx, req.NamespacedName, ip_map)
	ip_map.ObjectMeta.Labels = resolver.ObjectMeta.Labels

	// Make sure the ownerRef on to the IPMap we are working on is set to resolver
	// This will fail if IPMap is already owned by another resource
	if err := controllerutil.SetControllerReference(&resolver, ip_map, r.Scheme); err != nil {
		return default_result_obj, err
	}

	if get_err != nil && errors.IsNotFound(get_err) {

		// There is no IPMap matching `resolver`, so we create an IPMap and NetworkPolicy

		_, minttl, err := ipmapUpdate(ip_map, resolver.Spec.DomainList, options)
		if err != nil {
			return default_result_obj, fmt.Errorf("failed to generate IPMap Data: %w", err)
		}

		if options.GenerateType == "NetworkPolicy" {
			if err := r.NPReconcile(ctx, ip_map); err != nil {
				// We return so the IPMap does not get updated. This ensure we take the same code path next time
				return default_result_obj, fmt.Errorf("failed to create NetworkPolicy: %w", err)
			}
		}

		log.Info("Creating IPMap", "IPMap.Namespace", req.Namespace, "IPMap.Name", req.Name)
		if err := r.Create(ctx, ip_map); err != nil {
			return default_result_obj, fmt.Errorf("failed to create IPMap resource: %w", err)
		}

		requeue := time.Second * time.Duration(minttl+1)
		logRequeue(start_time, requeue, &log)
		return ctrl.Result{RequeueAfter: requeue}, nil

	} else if get_err == nil {

		// The IPMap matching `resolver` exists, so we update it and the NetworkPolicy

		updated, minttl, err := ipmapUpdate(ip_map, resolver.Spec.DomainList, options)
		if err != nil {
			return default_result_obj, fmt.Errorf("failed to generate IPMap Data (update): %w", err)
		}

		if updated {
			if options.GenerateType == "NetworkPolicy" {
				if err := r.NPReconcile(ctx, ip_map); err != nil {
					// We return so the IPMap does not get updated. This ensure we take the same code path next time
					return default_result_obj, fmt.Errorf("failed to update NetworkPolicy: %w", err)
				}
			}
			log.Info("Updating IPMap", "IPMap.Namespace", req.Namespace, "IPMap.Name", req.Name)
			if err := r.Update(ctx, ip_map); err != nil {
				return default_result_obj, fmt.Errorf("failed to update IPMap resource: %w", err)
			}
		} else {
			if options.GenerateType == "NetworkPolicy" {
				// Note that if a NetworkPolicy exists we assume it is synced with the IPMap already. We still
				// want to check if it exists in the no-update scenario, in case it was inadvertently deleted
				np := new(networking.NetworkPolicy)
				name := types.NamespacedName{Name: ip_map.Name, Namespace: ip_map.Namespace}
				if err := r.Get(ctx, name, np); err != nil {
					if err := r.NPReconcile(ctx, ip_map); err != nil {
						return default_result_obj, fmt.Errorf("failed to create NetworkPolicy: %w", err)
					}
				}
			}
		}

		requeue := time.Second * time.Duration(minttl+1)
		logRequeue(start_time, requeue, &log)
		return ctrl.Result{RequeueAfter: requeue}, nil
	} else {
		return default_result_obj, fmt.Errorf("failed to get IPMap: %w", get_err)	
	}
}

func (r *DNSResolverReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dnsv1alpha1.DNSResolver{}).
		Complete(r)
}
