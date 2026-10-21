package dkim2

import (
	"context"
	"crypto"
	"errors"
	"net"
	"sync"
	"time"
)

// keyPrefetchTimeout is how long after a prefetch lookup is sent its answer
// is waited for; past that the key is looked up the ordinary way.
var keyPrefetchTimeout = 5 * time.Second

// keyPrefetcher is a NetKeyFetcher whose lookups (up to PrefetchMax) were
// started in the background as soon as the header fields were read and
// checked.  FetchPublicKey takes
// a prefetched answer only when it settles the key -- TXT records, or a
// definitive "no such name / no TXT" -- and redoes the lookup the ordinary,
// synchronous way otherwise (no answer within keyPrefetchTimeout of
// sending, a SERVFAIL or other temporary failure, any transport error), so
// every verdict, TEMPERROR texts included, is what the ordinary lookup
// gives.  Each name's outcome is kept: it is looked up once per message.
type keyPrefetcher struct {
	base    *NetKeyFetcher
	lookups map[string]*keyLookup // by selector._domainkey.domain
}

type keyLookup struct {
	sent time.Time
	done chan struct{} // closed when txts/err are set
	txts []string
	err  error

	once sync.Once // the answer FetchPublicKey settles on
	key  crypto.PublicKey
	alg  string
	ferr error
}

// PrefetchMax is the most key lookups prefetchKeys starts for one message.
// Any key it leaves out is looked up the ordinary way if it is ever needed.
const PrefetchMax = 8

// prefetchKeys starts a background TXT lookup for each distinct key name
// the DKIM2-Signatures sigs (in ascending i= order, the structure checked)
// name with an algorithm this build implements -- the top signature's
// first, and at most PrefetchMax in all -- and returns the KeyFetcher that
// uses the answers.  Only real DNS (*NetKeyFetcher) is prefetched: any
// other KeyFetcher -- dns.json, a caller's override -- and opts'
// NoKeyPrefetch return fetcher unchanged.
func prefetchKeys(sigs []string, fetcher KeyFetcher, opts ...VerifyOptions) KeyFetcher {
	nf, ok := fetcher.(*NetKeyFetcher)
	if !ok || nf == nil || (len(opts) > 0 && opts[0].NoKeyPrefetch) {
		return fetcher
	}
	pf := &keyPrefetcher{base: nf, lookups: map[string]*keyLookup{}}
	res := nf.resolver()
	for k := len(sigs) - 1; k >= 0 && len(pf.lookups) < PrefetchMax; k-- {
		sig, err := parseSig(sigs[k])
		if err != nil {
			continue
		}
		for _, item := range sig.Sigs {
			if len(pf.lookups) == PrefetchMax {
				break
			}
			if !KnownSigAlg(item.Algorithm) {
				continue
			}
			fqdn := item.Selector + "._domainkey." + sig.Domain
			if pf.lookups[fqdn] != nil {
				continue
			}
			l := &keyLookup{sent: time.Now(), done: make(chan struct{})}
			pf.lookups[fqdn] = l
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), keyPrefetchTimeout)
				defer cancel()
				l.txts, l.err = res.LookupTXT(ctx, fqdn)
				close(l.done)
			}()
		}
	}
	return pf
}

func (pf *keyPrefetcher) FetchPublicKey(selector, domain string) (crypto.PublicKey, string, error) {
	fqdn := selector + "._domainkey." + domain
	l := pf.lookups[fqdn]
	if l == nil {
		return pf.base.FetchPublicKey(selector, domain)
	}
	l.once.Do(func() {
		wait := time.NewTimer(time.Until(l.sent.Add(keyPrefetchTimeout)))
		defer wait.Stop()
		select {
		case <-l.done:
			if settled(l.err) {
				l.key, l.alg, l.ferr = keyFromLookup(fqdn, l.txts, l.err)
				return
			}
		case <-wait.C:
		}
		l.key, l.alg, l.ferr = pf.base.FetchPublicKey(selector, domain)
	})
	return l.key, l.alg, l.ferr
}

// settled reports whether a lookup's outcome is definitive: an answer, or
// the name (or its TXT records) not existing.
func settled(err error) bool {
	var dnsErr *net.DNSError
	return err == nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound)
}
