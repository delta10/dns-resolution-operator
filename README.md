# dns-resolution-operator

<!--toc:start-->
- [dns-resolution-operator](#dns-resolution-operator)
  - [Project description](#project-description)
    - [Why this project is needed](#why-this-project-is-needed)
    - [How it works](#how-it-works)
    - [Internals](#internals)
    - [Potential instability](#potential-instability)
    - [Alternative solutions](#alternative-solutions)
  - [Deployment](#deployment)
    - [Helm](#helm)
    - [Local testing](#local-testing)
  - [Configuration](#configuration)
    - [Environment variables](#environment-variables)
    - [CoreDNS](#coredns)
    - [RBAC](#rbac)
  - [Roadmap](#roadmap)
<!--toc:end-->

## Project description

dns-resolution-operator is a Kubernetes operator that creates NetworkPolicies in which egress traffic to a list of domain names is allowed. The operator takes care of resolving the domain names to a list of IP addresses. This project is in early development with a fully functional alpha release.

This operator is best used in combination with the [k8s_cache plugin](https://github.com/delta10/k8s_cache) for CoreDNS. This allows the operator to update NetworkPolicies before the Cluster's DNS cache expires. Without the plugin, a small percentage of requests to domains with dynamic DNS responses will fail ([see below](#potential-instability)).


### Why this project is needed 

Kubernetes [NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) can be used to allow or block ingress and egress traffic to parts of the cluster. While NetworkPolicies support allowing and blocking IP ranges, there is no support for hostnames. Such a feature is particularly useful for those who want to block all egress traffic except for a couple of whitelisted hostnames.

Existing solutions all have their [limitations](#alternative-solutions). There is a need for a simple solution based on DNS, that does not require a proxy nor altering DNS records and that works for any type of traffic (not just HTTPS). This solution should also be stable for domains with dynamic DNS reponses.

dns-resolution-operator is this simple solution. All it does is resolve FQDNs, store them in "IPMap" custom resources, and update NetworkPolicies with the resolved IP addresses.

### How it works

The operator allows you to create DNSResolvers like the following:

```yaml
apiVersion: dns.k8s.delta10.nl/v1alpha1
kind: DNSResolver
metadata:
  name: whitelist-google
  namespace: default
spec:
  domainList:
  - google.com
  - www.google.com
```

It will then create NetworkPolicies like the following:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: whitelist-google
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 142.250.179.132/32
  - to:
    - ipBlock:
        cidr: 172.217.23.196/32
```

To keep track of the mapping between domain name and policy, the operator also creates custom resources called IPMaps. Administrators who want to generate customized NetworkPolicies can do so on the basis of the IPMaps (using another operator such as Kyverno). To disable the generation of NetworkPolicies, set `spec.generateType` to "IPMap".

### Internals 

The controller pod of dns-resolution-operator watches API resources of kind DNSResolver, which contain lists of domain names. The controller looks up the IP addresses of all domain names and appends them to a custom resource of kind IPMap and a NetworkPolicy, both with the same name and namespace as the DNSResolver.

On each reconciliation of a DNSResolver, the controller first queries the API server for endpoints of the DNS service (by default kube-dns in namespace kube-system). It adds each endpoint to its list of DNS servers (but not the service ClusterIP). It then queries each DNS server for A records for each of the domains in the DNSResolver. (It is necessary to query all servers, since each server has its own internal cache.)

The IP addressess are then appended to an IPMap and NetworkPolicy with the same name. An internal cache in the controller is also updated with the last time that each IP address was encountered. Finally, IP addresses that have not been seen for a certain amount of time (`IP_EXPIRATION`) are deleted.

The DNSResolver is requeued for reconciliation when the earliest cache expires in the full list of records it received (based on the TTL response).

### Potential instability

Whenever a DNS server clears it cache, there is a period of about 2 seconds when NetworkPolicies are not yet updated with the new IP addresses. This means that connection attempts to these hostnames might fail for about 2 seconds. This problem is best resolved by using the [k8s_cache plugin](https://github.com/delta10/k8s_cache).

Without the plugin, a small percentage of requests to hosts with dynamic DNS responses may fail. In my testing with `IP_EXPIRATION` set to "12h", requests to www.google.com eventually have a failure rate close to 0% and similar to a pod without egress policies. However, in the first 10 minutes, the failure rate is about 1%.

There are a few things you can do to reduce the amount of connection failures:
- Ensure that all pods in the cluster use a caching DNS server. The instances of this server should be endpoints of a Kubernetes service. dns-resolution-operator should be configured to use this service ([see below](#environment-variables)).
- Make sure that the DNS server sends the remaining cache duration as TTL, which is the default in CoreDNS (see the `keepttl` option [in CoreDNS](https://coredns.io/plugins/cache/)).
- Increase the cache duration of the DNS server ([see below](#coredns)).
- Set a higher IPExpiration (see [Environment variables](#environment-variables)). This is the amount of time that IPs are remembered since they were last seen in a DNS response.

### Alternative solutions
- [egress-operator](https://github.com/monzo/egress-operator) by Monzo. A very smart solution that runs a Layer 4 proxy for each whitelisted domain name. However, you need to run a proxy pod for each whitelisted domain, and you need to install a CoreDNS plugin to redirect traffic to the proxies. See also their [blog post](https://github.com/monzo/egress-operator).
- [FQDNNetworkPolicies](https://github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang). The GKE project is no longer maintained, but [there is a fork here](https://github.com/nais/fqdn-policy). The GKE project is quite similar to ours, but doesn't work well with hosts that dynamically return different A records. This project aims to have better stability in those sitations ([see above](#potential-instability)).
- Service meshes such as Istio ([see docs](https://istio.io/latest/docs/tasks/traffic-management/egress/egress-control)) can be used to create an HTTPS egress proxy that only allows traffic to certain hostnames. Such a solution does not use DNS at all but TLS SNI (Server Name Indication). However, it can only be used for HTTPS traffic.
- Some network plugins have a DNS-based solution, like CiliumNetworkPolicies ([see docs](https://docs.cilium.io/en/stable/security/policy/language/#dns-based)).
- There is a [proposal](https://github.com/kubernetes-sigs/network-policy-api/blob/main/npeps/npep-133.md) to extend the NetworkPolicy API with an FQDN selector.

## Deployment
### Helm
To install the operator with Helm:
```sh
helm install --create-namespace --namespace dns-resolution-operator dns-resolution-operator --repo https://delta10.github.io/dns-resolution-operator dns-resolution-operator
```
This should install the CRDs and controller. After installation, check the logs of the controller running in the `dns-resolution-operator` namespace.

### Local testing

To run the controller locally, set the environment variable `DNS_ENVIRONMENT` to `resolv.conf` or `resolv.conf-tcp`. It will use the DNS servers in `/etc/resolv.conf`. Make sure you have a kubeconfig set up to access the cluster API server.

To install the CRDs one the cluster, compile and run the controller, just execute
```bash
make run
```

If you want the local controller to use the cluster's dns servers, forward each pod to a local IP as follows:
```bash
kubectl -n kube-system port-forward pod/coredns-xxx --address=127.0.0.1 53:53
kubectl -n kube-system port-forward pod/coredns-yyy --address=127.0.0.2 53:53
# etc
```
Then replace `/etc/resolv.conf` with the following:
```resolv
options use-vc
nameserver 127.0.0.1
nameserver 127.0.0.2
# etc
```
And run:
```bash
export DNS_ENVIRONMENT=resolv.conf-tcp
make run
```

## Configuration

### Environment variables

The following environment variable control the behaviour of the controller.

| Name    | Description    | Default    |
|---------------- | --------------- | --------------- |
| DNS_ENABLE_IPV6    | Set to `1` to do AAAA lookups    | `0`    |
| DNS_ENVIRONMENT    | `kubernetes`: use kube-dns pods as DNS servers<br>`resolv.conf`: use all DNS servers from `/etc/resolv.conf`<br>`resolv.conf-tcp`: same as `resolv.conf` but use TCP instead of UDP | `kubernetes`    |
| DNS_UPSTREAM_SERVICE    | Name of the cluster DNS service in namespace kube-system    | `kube-dns`    |
|  IP_EXPIRATION  | How long to keep IPs that have not been seen in IPMaps (uses [ParseDuration](https://pkg.go.dev/time#ParseDuration))   | `1h`   |
| MAX_REQUEUE_TIME   | The maximum seconds to wait to reconcile a DNSResolver after a successful reconciliation   | `3600`   |


### CoreDNS

It is best to setup CoreDNS with k8s_cache instead of cache. For instructions see [k8s_cache](https://github.com/delta10/k8s_cache).

If you are not using k8s_cache, stability might improve if you increase the cache for external domains. For example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
    ...
        cache 3600
    ...
    }
    cluster.local:53 {
    ...
        cache 30
    ...
    }
```

### RBAC

The operator comes with two custom resources: `dnsresolvers.dns.k8s.delta10.nl` and `ipmaps.dns.k8s.delta10.nl`. When installed with Helm or OLM, the controller has the necessary permissions to these resources. It is advisable that cluster administrators restrict access to other accounts.

## Roadmap

Plans for the future:
- Create a custom resource to have more control over the resulting NetworkPolicy, similar to [FQDNNetworkPolicies](https://github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang).
- Create a custom reconciliation queue for a specific combinations of IPMap, DNS server and domain. This will greatly reduce the number of lookups.
