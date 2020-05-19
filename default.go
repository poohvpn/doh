package doh

import (
	"context"
	"net"
)

// LookupA looks up host using the local resolver.
// It returns a slice of that host's IPv4 addresses.
func LookupA(host string) ([]net.IP, error) {
	return DefaultResolver.LookupA(context.Background(), host)
}

// LookupAAAA looks up host using the local resolver.
// It returns a slice of that host's IPv6 addresses.
func LookupAAAA(host string) ([]net.IP, error) {
	return DefaultResolver.LookupAAAA(context.Background(), host)
}

// LookupIP looks up host using the local resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func LookupIP(host string) ([]net.IP, error) {
	return DefaultResolver.LookupIP(context.Background(), host)
}

// LookupCNAME returns the canonical name for the given host.
// Callers that do not care about the canonical name can call
// LookupHost or LookupIP directly; both take care of resolving
// the canonical name as part of the lookup.
//
// A canonical name is the final name after following zero
// or more CNAME records.
func LookupCNAME(host string) (cname string, err error) {
	return DefaultResolver.LookupCNAME(context.Background(), host)
}

// LookupNS returns the DNS NS records for the given domain name.
func LookupNS(name string) ([]*net.NS, error) {
	return DefaultResolver.LookupNS(context.Background(), name)
}

// LookupTXT returns the DNS TXT records for the given domain name.
func LookupTXT(name string) ([]string, error) {
	return DefaultResolver.LookupTXT(context.Background(), name)
}

// LookupAddr performs a reverse lookup for the given address, returning a list
// of names mapping to that address.
func LookupAddr(addr string) (names []string, err error) {
	return DefaultResolver.LookupAddr(context.Background(), addr)
}

// LookupSRV tries to resolve an SRV query of the given service,
// protocol, and domain name. The proto is "tcp" or "udp".
// The returned records are sorted by priority and randomized
// by weight within a priority.
//
// LookupSRV constructs the DNS name to look up following RFC 2782.
// That is, it looks up _service._proto.name. To accommodate services
// publishing SRV records under non-standard names, if both service
// and proto are empty strings, LookupSRV looks up name directly.
func LookupSRV(service, proto, name string) (cname string, addrs []*net.SRV, err error) {
	return DefaultResolver.LookupSRV(context.Background(), service, proto, name)
}

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
func LookupMX(name string) ([]*net.MX, error) {
	return DefaultResolver.LookupMX(context.Background(), name)
}
