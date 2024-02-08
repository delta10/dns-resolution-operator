# dns-resolution-operator
The dns-resolution-operator is a Kubernetes operator that creates API resources with the resolved IP addresses of domains. 

The use case for having such an operator is to create an egress or ingress firewall in which certain hostnames are whitelisted or blocked. Another operator, such as Kyverno, can be combined with dns-resolution-operator to create NetworkPolicies containing the resolved IP addresses of a list of hostnames. 

# Installation
## Helm
To install the operator with Helm:
```sh
helm install -n dns-resolution-operator dns-resolution-operator --repo https://delta10.github.io/dns-resolution-operator dns-resolution-operator
```
