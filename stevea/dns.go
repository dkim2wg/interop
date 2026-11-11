package dkim2

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"codeberg.org/miekg/dns/dnsutil"
)

var ResolveConf = "/etc/resolv.conf"

type DnsResolver struct {
	Client     *dns.Client
	Nameserver string
}

var _ KeyResolver = DnsResolver{}

func (d DnsResolver) Resolve(ctx context.Context, selector string, domain string) ([]string, error) {
	hostname := HostnameForKey(selector, domain)
	m := dns.NewMsg(hostname, dns.TypeTXT)
	if m == nil {
		return nil, errors.New("dns.NewMsg returned nil for type TXT; this shouldn't happen")
	}
	m.UDPSize = dns.DefaultMsgSize
	r, _, err := d.Client.Exchange(ctx, m, "udp", d.Nameserver)
	if err != nil {
		return nil, err
	}
	if r.Rcode == dns.RcodeSuccess {
		// NOERROR
		response := []string{}
		for _, a := range r.Answer {
			if x, ok := a.(*dns.TXT); ok {
				if dns.EqualName(hostname, x.Header().Name) {
					response = append(response, strings.Join(x.Txt, ""))
				}
				return response, nil
			}
		}
	}
	if r.Rcode == dns.RcodeNameError {
		// NXDOMAIN
		return []string{}, nil
	}
	return nil, fmt.Errorf("failed to resolve %s, got response %s", hostname, dns.RcodeToString[r.Rcode])
}

// NewDnsResolver returns a KeyResolver that queries DNS. If the provided
// nameserver (hostname:port) is empty then /etc/resolv.conf will be read
// to find a default nameserver.
func NewDnsResolver(nameserver string) (*DnsResolver, error) {
	if nameserver == "" {
		conf, err := dnsconf.FromFile(ResolveConf)
		if err != nil {
			return nil, err
		}
		if len(conf.Servers) == 0 {
			return nil, fmt.Errorf("no nameservers found in %s", ResolveConf)
		}
		nameserver = conf.Servers[0]
		if conf.Port == "" {
			nameserver = nameserver + ":53"
		} else {
			nameserver = nameserver + ":" + conf.Port
		}
	}
	return &DnsResolver{
		Client:     new(dns.Client),
		Nameserver: nameserver,
	}, nil
}

var _ KeyResolver = DnsResolver{}

//TODO(steve): Use net.LookupTXT()

func HostnameForKey(selector, domain string) string {
	var builder strings.Builder
	builder.WriteString(selector)
	builder.WriteString("._domainkey.")
	builder.WriteString(domain)
	return dnsutil.Canonical(builder.String())
}
