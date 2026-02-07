package recon

import (
	"net"
)

// get the domain name ip
func ResolveIP(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", nil
	}
	return ips[0].String(), nil
}
