package doh

import (
	"github.com/miekg/dns"
)

// copied from https://github.com/sensepost/goDoH/blob/master/dnsclient/structs.go

type question struct {
	Name string   `json:"name"` // FQDN with trailing dot
	Type dns.Type `json:"type"` // Standard DNS RR type
}

// response contains the response from a DNS query.
// Both Google and Cloudflare seem to share a scheme here. As in:
//	https://tools.ietf.org/id/draft-bortzmeyer-dns-json-01.html
//
// https://developers.google.com/speed/public-dns/docs/dns-over-https#dns_response_in_json
// https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
type response struct {
	Status   int        `json:"Status"` // 0=NOERROR, 2=SERVFAIL - Standard DNS response code (32 bit integer)
	TC       bool       `json:"TC"`     // Whether the response is truncated
	RD       bool       `json:"RD"`     // Always true for Google Public DNS
	RA       bool       `json:"RA"`     // Always true for Google Public DNS
	AD       bool       `json:"AD"`     // Whether all response data was validated with DNSSEC
	CD       bool       `json:"CD"`     // Whether the client asked to disable DNSSEC
	Question []question `json:"Question"`
	Answer   []struct {
		Name string   `json:"name"` // Always matches name in the Question section
		Type dns.Type `json:"type"` // Standard DNS RR type
		TTL  int      `json:"TTL"`  // Record's time-to-live in seconds
		Data string   `json:"data"` // Data
	} `json:"Answer"`
	Additional       []interface{} `json:"Additional"`
	EDNSClientSubnet string        `json:"edns_client_subnet"` // IP address / scope prefix-length
	Comment          string        `json:"Comment"`            // Diagnostics information in case of an error
}
