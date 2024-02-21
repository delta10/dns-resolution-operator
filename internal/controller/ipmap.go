/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
see the license for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"
	"net"
	"time"

	dnsv1alpha1 "github.com/delta10/dns-resolution-operator/api/v1alpha1"
	"github.com/miekg/dns"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func dnsConns() (conns []*dns.Conn, err error) {
	c := new(dns.Client)
	c.Net = Config.DNSProtocol
	config := Config.DNS
	for _, server := range config.Servers {
		conn, err := c.Dial(server + ":" + config.Port)
		if err != nil {
			return conns, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func closeConns(conns []*dns.Conn) (err error) {
	for _, conn := range conns {
		err = conn.Close()
	}
	return err
}

// Look up IPv4 and IPv6 addresses, return as an IP slice and return smallest TTL received
func lookupDomain(domain string, conns []*dns.Conn) (ips []net.IP, ttl uint32, err error) {
	ttl = uint32(Config.MaxRequeueTime)
	ips = make([]net.IP, 0, 10)

	m4 := new(dns.Msg)
	m4.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	var success bool
	for _, conn := range conns {
		conn.WriteMsg(m4)
		res, err := conn.ReadMsg()
		if err == nil && res.Rcode == dns.RcodeSuccess {
			success = true
			// Loop through the answer to extract the TTL and A records
			for _, ans := range res.Answer {
				if rec, ok := ans.(*dns.A); ok {
					ips = append(ips, rec.A)
					ttl = min(ttl, rec.Hdr.Ttl)
				}
			}
		}
	}
	if !success {
		return nil, 0, fmt.Errorf("No DNS servers could be queried successfully for A records")
	}

	if Config.EnableIPv6 {
		success = false
		m6 := new(dns.Msg)
		m6.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
		for _, conn := range conns {
			conn.WriteMsg(m6)
			res, err := conn.ReadMsg()
			if err == nil && res.Rcode == dns.RcodeSuccess {
				success = true
			}
			// Loop through the answer to extract the TTL and AAAA records
			for _, ans := range res.Answer {
				if rec, ok := ans.(*dns.AAAA); ok {
					ips = append(ips, rec.AAAA)
					ttl = min(ttl, rec.Hdr.Ttl)
				}
			}
		}
		if !success {
			return nil, 0, fmt.Errorf("No DNS servers could be queried successfully for AAAA records")
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

func getIpMapDomainOrCreate(ip_map *dnsv1alpha1.IPMap, domain string) (int, bool) {
	for i, ip_list := range ip_map.Data.Domains {
		if ip_list.Domain == domain {
			return i, false
		}
	}
	ip_map.Data.Domains = append(ip_map.Data.Domains, dnsv1alpha1.IPList{Domain: domain})
	return len(ip_map.Data.Domains) - 1, true
}

// Remove expired IPs from ip_map. Then clean the cache
func purgeExpired(ip_map *dnsv1alpha1.IPMap) bool {
	ipmap_name := types.NamespacedName{
		Namespace: ip_map.GetNamespace(),
		Name:      ip_map.GetName(),
	}
	var updated bool

	if !IPCache.NameExists(ipmap_name) {
		return updated
	}

	for i := range ip_map.Data.Domains {
		domain := &ip_map.Data.Domains[i]
		ips_new := make([]string, 0, len(domain.IPs))
		for _, ip := range domain.IPs {
			expiration := IPCache.Get(ipmap_name, ip)
			if expiration.Before(time.Now()) {
				IPCache.Delete(ipmap_name, ip)
				updated = true
			} else {
				ips_new = append(ips_new, ip)
			}
		}
		domain.IPs = ips_new
	}

	IPCache.CleanUp(ipmap_name)
	return updated
}

// Update an IPMap with a list of IP addresses (CIDR notation) for each domain in domainList.
// Return updated = true if ip_map.Data was updated.
// minttl is the minimum TTL of all TTLs received in DNS lookups
func ipmapUpdate(
	ip_map *dnsv1alpha1.IPMap,
	domainList []string,
	options *resolverOptions,
) (updated bool, minttl uint32, err error) {
	debug := ctrl.Log.V(1)
	minttl = uint32(Config.MaxRequeueTime)
	ipmap_name := types.NamespacedName{
		Namespace: ip_map.GetNamespace(),
		Name:      ip_map.GetName(),
	}

	if ip_map.Data == nil {
		ip_map.Data = new(dnsv1alpha1.IPMapData)
		updated = true
	}

	// Remove domains that are no longer requested
OUTER:
	for i, old_domain := range ip_map.Data.Domains {
		for _, domain := range domainList {
			if domain == old_domain.Domain {
				continue OUTER
			}
		}
		// not found in requested domains
		newlen := len(ip_map.Data.Domains) - 1
		ip_map.Data.Domains[i] = ip_map.Data.Domains[newlen]
		ip_map.Data.Domains = ip_map.Data.Domains[:newlen]
		updated = true
	}

	start_time := time.Now()
	conns, err := dnsConns()
	defer closeConns(conns)
	if err != nil {
		return updated, 0, err
	}

	for _, domain := range domainList {
		var ip_list *dnsv1alpha1.IPList
		index, created := getIpMapDomainOrCreate(ip_map, domain)
		ip_list = &ip_map.Data.Domains[index]
		if created {
			updated = true
		}

		ips, ttl, err := lookupDomain(domain, conns)
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
				return updated, 0, fmt.Errorf("Failed to parse IP address in DNS response")
			}

			// Add IP to IPMap
			ip_str := ip_net.String()
			var appended bool
			appended, ip_list.IPs = appendIfMissing(ip_list.IPs, ip_str)
			if appended {
				updated = true
			}

			// Add expiration time to the IP cache
			IPCache.Set(ipmap_name, ip_str, time.Now().Add(Config.IPExpiration))
		}
	}
	debug.Info("IPMap Refresh logic completed", "duration", time.Since(start_time))

	if purgeExpired(ip_map) {
		updated = true
	}

	return updated, minttl, nil
}
