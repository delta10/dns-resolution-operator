# dns-resolution-operator

<!--toc:start-->
- [dns-resolution-operator](#dns-resolution-operator)
  - [Project description](#project-description)
    - [Why this project is needed](#why-this-project-is-needed)
    - [How it works](#how-it-works)
    - [Internals](#internals)
    - [WARNING: potential instability](#warning-potential-instability)
    - [Alternative solutions](#alternative-solutions)
  - [Deployment](#deployment)
    - [Helm](#helm)
    - [Local testing](#local-testing)
  - [Configuration](#configuration)
    - [Environment variables](#environment-variables)
    - [Set up an egress firewall using Kyverno](#set-up-an-egress-firewall-using-kyverno)
    - [CoreDNS](#coredns)
    - [RBAC](#rbac)
  - [Roadmap](#roadmap)
<!--toc:end-->

## Project description

dns-resolution-operator is a Kubernetes operator that creates API resources with the resolved IP addresses of domains. This project is in early development with a fully functional alpha release.

This operator allows users to create an egress or ingress firewall in which certain hostnames (FQDNs) are whitelisted or blocked. Another operator, such as Kyverno, can be combined with dns-resolution-operator to create NetworkPolicies containing the resolved IP addresses of a list of hostnames. 

The operator does its best to update resources immediately after the DNS server's cache expires. However, creating NetworkPolicies with this method may still cause instability ([see below](#warning-potential-instability)). This project is only the first step towards creating a stable long-term solution. The next step will be to create a CoreDNS plugin that delivers new uncached records to the operator a few seconds before it refreshes the cache for other clients. Once this is done, the road is free to implement FQDN resolution in native Kubernetes NetworkPolicies.


### Why this project is needed 

Kubernetes [NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) can be used to allow or block ingress and egress traffic to parts of the cluster. While NetworkPolicies support allowing and blocking IP ranges, there is no support for hostnames. Such a feature is particularly useful for those who want to block all egress traffic except for a couple of whitelisted hostnames.

[Existing solutions](#alternative-solutions) all have their limitations. There is a need for a simple solution based on DNS, that does not require a proxy nor altering DNS records and that works for any type of traffic (not just HTTPS).

dns-resolution-operator is this simple solution. All it does is resolve FQDNs and store them in "IPMap" API resources. Another operator such as Kyverno can be used to generate native Kubernetes NetworkPolicies using these IP addresses. [See the instructions below.](#set-up-an-egress-firewall-using-kyverno)

### How it works

The operator allows you to create DNSResolvers like the following:

```yaml
apiVersion: dns.k8s.delta10.nl/v1alpha1
kind: DNSResolver
metadata:
  name: whitelist-google
  namespace: default
spec:
  createDomainIPMapping: true # whether to keep the association between domain and IP in the resulting IPMap
  domainList:
  - google.com
  - www.google.com
```

It will then create IPMaps like the following:

```
apiVersion: dns.k8s.delta10.nl/v1alpha1
kind: IPMap
metadata:
  name: whitelist-google
  namespace: default
data:
  domains:
  - ips:
    - 142.250.179.142/32
    - 142.251.39.110/32
    name: google.com
  - ips:
    - 142.251.36.36/32
    - 142.250.179.164/32
    name: www.google.com
```

For creating NetworkPolicies [see below](#set-up-an-egress-firewall-using-kyverno).

### Internals 

The controller pod of dns-resolution-operator watches API resources of kind DNSResolver, which contain lists of domain names. The controller looks up the IP addresses of all domain names and appends them to an API resource of kind IPMap.

On each reconciliation of a DNSResolver, the controller first queries the API server for kube-dns endpoints. It adds each endpoint to its list of DNS servers (the kube-dns service is bypassed). It then queries each DNS server for A records for each of the domains in the DNSResolver. It is necessary to query all servers, since each server has its own internal cache.

The IP addressess are then appended to an IPMap with the same name, if they are not already in that IPMap. An internal cache in the controller is also updated with the last time that each IP address was encountered. Finally, IP addresses in the IPMap that have not been seen for a certain amount of time are deleted.

The DNSResolver is requeued for reconciliation when the earliest cache expires in the full list of records it received (based on the TTL response).

The user is responsible for generating NetworkPolicies on the basis of IPMaps. I recommend to use Kyverno ([see below](#set-up-an-egress-firewall-using-kyverno)).

### WARNING: potential instability

Whenever a DNS server clears it cache, there is a period of about 2 seconds when any NetworkPolicies are not yet updated with the new IP addresses. If the intention is to whitelist hostnames for egress traffic, this means that connection attempts to these hostnames might fail for about 2 seconds.

To solve this completely, a CoreDNS plugin needs to be written that delivers new records to our controller a few seconds before it refreshes the cache for other clients.

As long as this plugin does not exist, there are a few things you can do to reduce the amount of connection failures:
- Ensure that all pods in the cluster use kube-dns for DNS resolution.
- Make sure that the DNS service sends the remaining cache duration as TTL, which is the default in CoreDNS (see the `keepttl` option [in CoreDNS](https://coredns.io/plugins/cache/)).
- Increase the cache duration of the DNS service ([see below](#coredns)).
- Set a higher IPExpiration (see [Environment variables](#environment-variables)). This is the amount of time that IPs are stored in an IPMap since they were last seen in a DNS response.

### Alternative solutions
- [egress-operator](https://github.com/monzo/egress-operator) by Monzo. A very smart solution that runs a Layer 4 proxy for each whitelisted domain name. However, you need to run a proxy pod for each whitelisted domain, and you need to install a CoreDNS plugin to redirect traffic to the proxies. See also their [blog post](https://github.com/monzo/egress-operator).
- [FQDNNetworkPolicies](https://github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang). The GKE project is no longer maintained, but [there is a fork here](https://github.com/nais/fqdn-policy). The GKE project is quite similar to ours, but doesn't work well with hosts that dynamically return different A records. This project aims to have better stability in those sitations ([see above](#warning-potential-instability)).
- Service meshes such as Istio ([see docs](https://istio.io/latest/docs/tasks/traffic-management/egress/egress-control)) can be used to create an HTTPS egress proxy that only allows traffic to certain hostnames. Such a solution does not use DNS at all but TLS SNI (Server Name Indication). However, it can only be used for HTTPS traffic.
- Some network plugins have a DNS-based solution, like CiliumNetworkPolicies ([see docs](https://docs.cilium.io/en/stable/security/policy/language/#dns-based)).

## Deployment
### Helm
To install the operator with Helm:
```sh
helm install -n dns-resolution-operator dns-resolution-operator --repo https://delta10.github.io/dns-resolution-operator dns-resolution-operator
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
|  IP_EXPIRATION  | How long to keep IPs that have not been seen in IPMaps (uses [ParseDuration](https://pkg.go.dev/time#ParseDuration))   | `12h`   |
| MAX_REQUEUE_TIME   | How many seconds to wait until reconciling a DNSResolver after a reconciliation   | `3600`   |


### Set up an egress firewall using Kyverno

Kyverno can be used to generate NetworkPolicies to your liking with IPMaps as input. For example. the following Kyverno ClusterPolicy will create an egress whitelist for every IPMap, with the same name and namespace.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: ip-whitelist
spec:
  generateExisting: true
  rules:
  - name: generate-whitelists
    match:
      any:
      - resources:
          kinds:
          - dns.k8s.delta10.nl/v1alpha1/IPMap
    generate:
      apiVersion: networking.k8s.io/v1
      kind: NetworkPolicy
      name: "{{request.object.metadata.name}}"
      namespace: "{{request.object.metadata.namespace}}"
      synchronize: true
      data:
        spec:
          # select all pods in the namespace
          podSelector: {}
          policyTypes:
            - Egress
          egress:
            - to: "{{ (request.object.data.domains[].ips)[] | map(&{cidr: @}, @) | items(@, 'foo', 'ipBlock') }}"
            # the above is a workaround. the below doesn't work; see https://github.com/kyverno/kyverno/issues/9668
            # - to: "{{(request.object.data.domains[].ips)[] | map(&{ipBlock: {cidr: @} }, @)}}"
```

### CoreDNS

When `dns-resolution-operator` is used to create a NetworkPolicy firewall, it is advisable to increase the default cache duration for external domains. Below is a suggested configuration.

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
- Create a CoreDNS plugin to completely get rid of instability
- Add a method to directly create NetworkPolicies instead of IPMaps
- Create a custom reconciliation queue for a specific combinations of IPMap, DNS server and domain. This will greatly reduce the number of lookups.
