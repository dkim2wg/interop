// Command dkim2dsn propagates a received DKIM2 DSN upstream (draft-06 §12.1.1),
// or with -authenticate checks an inbound one first (draft-06 §12.1.2).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/dkim2wg/interop/go/dkim2"
)

func main() {
	fwd := flag.String("forwarder-domain", "", "the Forwarder's own domain")
	domain := flag.String("domain", "", "signing domain for the propagated DSN (required)")
	selector := flag.String("selector", "", "DKIM2 selector (required)")
	keyFile := flag.String("key", "", "PKCS#8 PEM private key (required)")
	auth := flag.Bool("authenticate", false, "§12.1.2: check the returned original instead of propagating")
	dnsFile := flag.String("dns", "", "Path to dns.json key file (required with -authenticate)")
	ignoreTS := flag.Bool("ignore-timestamps", false, "Disable the §10.3 timestamp (14-day/future) check")
	flag.Parse()

	if *auth {
		authenticate(*dnsFile, *ignoreTS)
		return
	}

	if *domain == "" || *selector == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "usage: dkim2dsn -domain DOM -selector SEL -key KEY.pem [-forwarder-domain FWD] < dsn")
		fmt.Fprintln(os.Stderr, "       dkim2dsn -authenticate -dns DNS.json [-ignore-timestamps] < dsn")
		os.Exit(1)
	}
	pem, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading key: %v\n", err)
		os.Exit(1)
	}
	key, err := dkim2.LoadPrivateKey(pem)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: parsing key: %v\n", err)
		os.Exit(1)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading stdin: %v\n", err)
		os.Exit(1)
	}
	out, upstream, err := dkim2.Propagate(raw, dkim2.PropagateOptions{
		ForwarderDomain: *fwd, Key: key, Selector: *selector, Domain: *domain,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "upstream: %s\n", upstream)
	os.Stdout.Write(out)
}

// authenticate reports whether the DSN on stdin returns a message that
// verifies (§12.1.2). It prints the top signature's d= and mf= so the caller
// can apply point 2 -- deciding whether that signature is one of its own --
// which only the system receiving the DSN can do.
func authenticate(dnsFile string, ignoreTS bool) {
	if dnsFile == "" {
		fmt.Fprintln(os.Stderr, "usage: dkim2dsn -authenticate -dns DNS.json [-ignore-timestamps] < dsn")
		os.Exit(1)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading stdin: %v\n", err)
		os.Exit(1)
	}
	res, err := dkim2.Authenticate(raw, &dkim2.JSONKeyFetcher{Path: dnsFile},
		dkim2.VerifyOptions{SkipTimestampCheck: ignoreTS})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	if res.HeadersOnly {
		fmt.Fprintln(os.Stderr, "returned original: header fields only")
	}
	if res.Top != nil {
		fmt.Fprintf(os.Stderr, "top signature: i=%d d=%s mf=%s\n",
			res.Top.Sequence, res.Top.Domain, res.Top.MailFrom)
	}
	if !res.OK {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", res.Reason)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "PASS: returned original verified")
}
