package doh

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/miekg/dns"
)

var DefaultResolver = &Resolver{
	HTTPClient: &http.Client{
		Timeout: time.Second * 5,
	},
	Providers: []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/resolve",
		"https://dns.quad9.net:5053/dns-query",
	},
}

type Resolver struct {
	Providers  []string
	HTTPClient *http.Client
}

func (r *Resolver) singleQuery(url, domain string, t dns.Type) (*response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-json")
	params := req.URL.Query()
	params.Add("name", domain)
	params.Add("type", t.String())
	req.URL.RawQuery = params.Encode()

	httpResp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	dohResp := response{}
	err = json.NewDecoder(httpResp.Body).Decode(&dohResp)
	if err != nil {
		return nil, errors.Wrap(err, "json decode http response")
	}

	return &dohResp, nil
}

func (r *Resolver) Query(ctx context.Context, domain string, t dns.Type) ([]string, error) {
	pvdLen := len(r.Providers)
	if pvdLen == 0 {
		return nil, errors.New("no provider")
	}
	type result struct {
		*response
		error
	}
	resultC := make(chan result, pvdLen)
	for _, provider := range r.Providers {
		go func(url string) {
			dohResp, err := r.singleQuery(url, domain, t)
			resultC <- result{
				response: dohResp,
				error:    err,
			}
		}(provider)
	}

	errsString := make([]string, 0, pvdLen)
	for i := 0; i < pvdLen; i++ {
		select {
		case <-ctx.Done():
			return nil, &dohError{
				InnerError: ctx.Err(),
				Doamin:     domain,
				Type:       t,
			}
		case res := <-resultC:
			if res.error != nil {
				errsString = append(errsString, res.error.Error())
				continue
			}
			if res.Status != 0 {
				continue
			}
			datas := make([]string, 0, len(res.Answer))
			for _, ans := range res.Answer {
				if ans.Type != t || ans.TTL == 0 {
					continue
				}
				data := ans.Data
				if len(data) >= 2 && data[0] == '"' && data[len(data)-1] == '"' {
					// possibly is google or quad9
					data = data[1 : len(data)-1]
				}
				datas = append(datas, data)
			}
			if len(datas) == 0 {
				return nil, &dohError{
					InnerError: ErrNoAnswer,
					Doamin:     domain,
					Type:       t,
				}
			}
			return datas, nil
		}
	}
	return nil, &dohError{
		InnerError: errors.New(strings.Join(errsString, ", ")),
		Doamin:     domain,
		Type:       t,
	}
}

func (r *Resolver) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	var (
		res  []net.IP
		errs []error
	)
	ipv4Res, ipv4Err := r.LookupA(ctx, name)
	if ipv4Err != nil {
		errs = append(errs, ipv4Err)
	} else {
		res = append(res, ipv4Res...)
	}
	ipv6Res, ipv6Err := r.LookupAAAA(ctx, name)
	if ipv6Err != nil {
		errs = append(errs, ipv6Err)
	} else {
		res = append(res, ipv6Res...)
	}

	if len(res) > 0 {
		return res, nil
	}
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return nil, nil
}

func (r *Resolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	datas, err := r.Query(ctx, name, dns.Type(dns.TypeTXT))
	if err != nil {
		return "", err
	}
	return datas[0], nil
}

func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	datas, err := r.Query(ctx, name, dns.Type(dns.TypeTXT))
	if err != nil {
		return nil, err
	}
	res := make([]*net.NS, 0, len(datas))
	for _, data := range datas {
		res = append(res, &net.NS{Host: data})
	}
	return res, nil
}

func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.Query(ctx, name, dns.Type(dns.TypeTXT))
}

func (r *Resolver) LookupA(ctx context.Context, name string) ([]net.IP, error) {
	return parseIPs(r.Query(ctx, name, dns.Type(dns.TypeA)))
}

func (r *Resolver) LookupAAAA(ctx context.Context, name string) ([]net.IP, error) {
	return parseIPs(r.Query(ctx, name, dns.Type(dns.TypeAAAA)))
}

func (r *Resolver) LookupAddr(ctx context.Context, name string) ([]string, error) {
	return r.Query(ctx, name, dns.Type(dns.TypePTR))
}

func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	var target string
	if service == "" && proto == "" {
		target = name
	} else {
		target = "_" + service + "._" + proto + "." + name
	}
	datas, err := r.Query(ctx, target, dns.Type(dns.TypeSRV))
	if err != nil {
		return "", nil, err
	}

	res := make([]*net.SRV, 0, len(datas))
	for _, data := range datas {
		values := strings.Fields(data)
		if len(values) < 4 {
			continue
		}
		priority, err := strconv.Atoi(values[0])
		if err != nil {
			continue
		}
		weight, err := strconv.Atoi(values[1])
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(values[2])
		if err != nil {
			continue
		}

		res = append(res, &net.SRV{
			Target:   values[3],
			Port:     uint16(port),
			Priority: uint16(priority),
			Weight:   uint16(weight),
		})
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].Priority < res[j].Priority || (res[i].Priority == res[j].Priority && res[i].Weight < res[j].Weight)
	})
	return target + ".", res, nil
}

func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	datas, err := r.Query(ctx, name, dns.Type(dns.TypeTXT))
	if err != nil {
		return nil, err
	}

	res := make([]*net.MX, 0, len(datas))
	for _, data := range datas {
		values := strings.Fields(data)
		if len(values) < 2 {
			continue
		}
		pref, err := strconv.Atoi(values[0])
		if err != nil {
			continue
		}

		res = append(res, &net.MX{
			Host: values[1],
			Pref: uint16(pref),
		})
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].Pref < res[j].Pref
	})
	return res, nil
}

func parseIPs(datas []string, err error) ([]net.IP, error) {
	if err != nil {
		return nil, err
	}
	res := make([]net.IP, 0, len(datas))
	for _, data := range datas {
		res = append(res, net.ParseIP(data))
	}
	return res, nil
}
