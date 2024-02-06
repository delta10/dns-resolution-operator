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
	"time"

	errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	dnsv1alpha1 "github.com/delta10/dns-resolution-operator/api/v1alpha1"
	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DNSResolverReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

var Config struct {
	EnableIPv6     bool
	DNSEnvironment string
}

func init() {
	Config.EnableIPv6 = false
	if s := os.Getenv("DNS_ENABLE_IPV6"); s == "1" {
		Config.EnableIPv6 = true
	}

	Config.DNSEnvironment = os.Getenv("DNS_ENVIRONMENT")
}

//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers,verbs=get;list;watch
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=dnsresolvers/finalizers,verbs=update
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=ipmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dns.k8s.delta10.nl,resources=ipmaps/finalizers,verbs=update

// Reconcile makes sure that each DNSResolver has an associated IPMap.
// It gets triggered by changes in DNSResolvers and their owned IPMaps
func (r *DNSResolverReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	default_result_obj := ctrl.Result{
		RequeueAfter: time.Minute * 10,
	}

	// Obtain the current DNSResolver from the cluster
	var resolver dnsv1alpha1.DNSResolver
	if err := r.Get(ctx, req.NamespacedName, &resolver); err != nil {
		log.Error(err, "unable to fetch DNSResolver")
		return default_result_obj, client.IgnoreNotFound(err)
	}

	options := &ipMapOptions{
		CreateDomainIPMapping: resolver.Spec.CreateDomainIPMapping,
	}

	// Create an empty IPMap to populate later
	ipMap := new(dnsv1alpha1.IPMap)
	ipMap.Name = req.Name
	ipMap.Namespace = req.Namespace

	// First, check if `resolver` has an associated IPMap already
	get_err := r.Get(ctx, req.NamespacedName, ipMap)

	// Make sure the ownerRef on `resolver` is set to the IPMap we are working on
	// This will fail if IPMap is already owned by another resource
	if err := controllerutil.SetControllerReference(&resolver, ipMap, r.Scheme); err != nil {
		return default_result_obj, err
	}

	if get_err != nil && errors.IsNotFound(get_err) {

		// There is no IPMap matching `resolver`, so we create one

		log.Info("Creating IPMap", "IPMap.Namespace", req.Namespace, "IPMap.Name", req.Name)

		_, minttl, err := ipmapUpdate(ipMap, resolver.Spec.DomainList, options)
		if err != nil {
			log.Error(err, "failed to generate IPMap Data")
			return default_result_obj, err
		}
		if err := r.Create(ctx, ipMap); err != nil {
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

		updated, minttl, err := ipmapUpdate(ipMap, resolver.Spec.DomainList, options)
		if err != nil {
			log.Error(err, "failed to generate IPMap Data (update)")
			return default_result_obj, err
		}
		if updated {
			log.Info("Updating IPMap", "IPMap.Namespace", req.Namespace, "IPMap.Name", req.Name)
			if err := r.Update(ctx, ipMap); err != nil {
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
