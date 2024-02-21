package controller

import (
	"context"

	dnsv1alpha1 "github.com/delta10/dns-resolution-operator/api/v1alpha1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func NPGenerate(ip_map *dnsv1alpha1.IPMap) (np *networking.NetworkPolicy) {
	tolist := make([]networking.NetworkPolicyPeer, 0, 10)

	for _, domain := range ip_map.Data.Domains {
		for _, ip := range domain.IPs {
			to := networking.NetworkPolicyPeer{
				IPBlock: &networking.IPBlock{
					CIDR: ip,
				},
			}
			tolist = append(tolist, to)
		}
	}

	np = &networking.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: ip_map.Name,
			Namespace: ip_map.Namespace,
			Labels: ip_map.Labels,
			OwnerReferences: ip_map.OwnerReferences,
		},
		Spec: networking.NetworkPolicySpec{
			Egress: []networking.NetworkPolicyEgressRule{
				{To: tolist},
			},
		},
	}

	return
}

// Create or update the NetworkPolicy associated with ip_map
func (r DNSResolverReconciler) NPReconcile(ctx context.Context, ip_map *dnsv1alpha1.IPMap) error {
	log := log.FromContext(ctx)
	old_np := new(networking.NetworkPolicy)
	name := types.NamespacedName{Name: ip_map.Name, Namespace: ip_map.Namespace}
	err := r.Get(ctx, name, old_np)

	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating NetworkPolicy")

		np := NPGenerate(ip_map)
		if err := r.Create(ctx, np); err != nil {
			return err
		}
	} else if err == nil {
		log.Info("Updating NetworkPolicy")

		np := NPGenerate(ip_map)
		np.ObjectMeta = old_np.ObjectMeta
		if err := r.Update(ctx, np); err != nil {
			return err
		}
	} else {
		return err
	}
	return nil
}
