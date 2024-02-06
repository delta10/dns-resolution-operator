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
	"errors"
	"fmt"
	"net"

	dnsv1alpha1 "github.com/delta10/dns-resolution-operator/api/v1alpha1"
	"github.com/miekg/dns"
)

// Look up IPv4 and IPv6 addresses, return as an IP slice and return smallest TTL received
func lookupDomain(domain string) ([]net.IP, uint32, error) {
	var ips []net.IP
	ttl := uint32(3600)

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to read /etc/resolv.conf")
	}

	c := new(dns.Client)
	if Config.DNSEnvironment == "local-tcp" {
		config.Servers = []string{"127.0.0.1"}
		c.Net = "tcp"
	}

	m4 := new(dns.Msg)
	m4.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	var r4, r6 *dns.Msg
	for _, server := range config.Servers {
		r4, _, err = c.Exchange(m4, server+":"+config.Port)
		if err == nil && r4.Rcode == dns.RcodeSuccess {
			break
		}
	}
	if err != nil {
		return nil, 0, err
	}
	if r4.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("DNS A query for %v failed with response code: %d", domain, r4.Rcode)
	}

	// Loop through the answers to extract the TTL and A record
	for _, ans := range r4.Answer {
		if rec, ok := ans.(*dns.A); ok {
			ips = append(ips, rec.A)
			ttl = min(ttl, rec.Hdr.Ttl)
		}
	}

	if Config.EnableIPv6 {
		m6 := new(dns.Msg)
		m6.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
		for _, server := range config.Servers {
			r6, _, err = c.Exchange(m6, server+":53")
			if err == nil && r6.Rcode == dns.RcodeSuccess {
				break
			}
		}
		if err != nil {
			return nil, 0, err
		}
		if r6.Rcode != dns.RcodeSuccess {
			return nil, 0, fmt.Errorf("DNS AAAA query for %v failed with response code: %d", domain, r6.Rcode)
		}

		// Loop through the answers to extract the TTL and AAAA record
		for _, ans := range r6.Answer {
			if rec, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, rec.AAAA)
				ttl = min(ttl, rec.Hdr.Ttl)
			}
		}
	}

	return ips, ttl, nil
}

func appendIfMissing(slice []string, str string) (bool, []string) {
	for _, v := range slice {
		if v == str {
			return false, slice
		}
	}
	slice = append(slice, str)
	return true, slice
}

func getIpMapDomainOrCreate(ipMap *dnsv1alpha1.IPMap, domain string) (int, bool) {
	for i, ipList := range ipMap.Data.Domains {
		if ipList.Domain == domain {
			return i, false
		}
	}
	ipMap.Data.Domains = append(ipMap.Data.Domains, dnsv1alpha1.IPList{Domain: domain})
	return len(ipMap.Data.Domains) - 1, true
}

type ipMapOptions struct {
	CreateDomainIPMapping bool
}

// Update an IPMap with a list of IP addresses (CIDR notation) for each domain in domainList.
// Return true if ipMap.Data was updated.
// The second return value is the minimum TTL of all TTLs received in DNS lookups
func ipmapUpdate(ipMap *dnsv1alpha1.IPMap, domainList []string, options *ipMapOptions) (bool, uint32, error) {
	updated := false
	minttl := uint32(3600)

	if ipMap.Data == nil {
		ipMap.Data = new(dnsv1alpha1.IPMapData)
		updated = true
	}

	if options.CreateDomainIPMapping {
		// Remove domains that are no longer requested
	OUTER:
		for i, old_domain := range ipMap.Data.Domains {
			for _, domain := range domainList {
				if domain == old_domain.Domain {
					continue OUTER
				}
			}
			// not found in requested domains
			newlen := len(ipMap.Data.Domains) - 1
			ipMap.Data.Domains[i] = ipMap.Data.Domains[newlen]
			ipMap.Data.Domains = ipMap.Data.Domains[:newlen]
			updated = true
		}
	} else {
		// Make sure there is only a domain "" in the ipMap Data
		if len(ipMap.Data.Domains) > 1 {
			ipMap.Data = new(dnsv1alpha1.IPMapData)
			_, _ = getIpMapDomainOrCreate(ipMap, "")
			updated = true
		} else if len(ipMap.Data.Domains) == 0 {
			_, _ = getIpMapDomainOrCreate(ipMap, "")
			updated = true
		} else if ipMap.Data.Domains[0].Domain != "" {
			ipMap.Data = new(dnsv1alpha1.IPMapData)
			_, _ = getIpMapDomainOrCreate(ipMap, "")
			updated = true
		}
	}

	for _, domain := range domainList {
		var ipList *dnsv1alpha1.IPList
		if options.CreateDomainIPMapping {
			var created bool
			var index int
			index, created = getIpMapDomainOrCreate(ipMap, domain)
			ipList = &ipMap.Data.Domains[index]
			if created {
				updated = true
			}
		} else {
			ipList = &ipMap.Data.Domains[0]
		}
		ips, ttl, err := lookupDomain(domain)
		minttl = min(minttl, ttl)
		if err != nil {
			return updated, 0, err
		}
		for _, ip := range ips {
			ip_net := new(net.IPNet)
			if ip.To4() != nil {
				ip_net = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else if ip.To16() != nil {
				ip_net = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			} else {
				return updated, 0, errors.New("Failed to parse IP address in DNS response")
			}
			var appended bool
			appended, ipList.IPs = appendIfMissing(ipList.IPs, ip_net.String())
			if appended {
				updated = true
			}
		}
	}
	return updated, minttl, nil
}
