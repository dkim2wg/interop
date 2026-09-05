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
	dnsFile := flag.String("dns", "", "Path to dns.json key file (required to authenticate)")
	skipAuth := flag.Bool("skip-authentication", false,
		"Propagate without the §12.1.2 check (already done by the caller)")
	ignoreTS := flag.Bool("ignore-timestamps", false, "Disable the §10.3 timestamp (14-day/future) check")
	flag.Parse()

	if *auth {
		authenticate(*dnsFile, *ignoreTS)
		return
	}

	if *domain == "" || *selector == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "usage: dkim2dsn -domain DOM -selector SEL -key KEY.pem -dns DNS.json [-forwarder-domain FWD] < dsn")
		fmt.Fprintln(os.Stderr, "       dkim2dsn -authenticate -dns DNS.json [-ignore-timestamps] < dsn")
		os.Exit(1)
	}
	if *dnsFile == "" && !*skipAuth {
		fmt.Fprintln(os.Stderr, "ERROR: propagating requires -dns to authenticate the DSN "+
			"(§12.1.2), or -skip-authentication")
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
	var fetcher dkim2.KeyFetcher
	if *dnsFile != "" {
		fetcher = &dkim2.JSONKeyFetcher{Path: *dnsFile}
	}
	out, upstream, err := dkim2.Propagate(raw, dkim2.PropagateOptions{
		ForwarderDomain: *fwd, Key: key, Selector: *selector, Domain: *domain,
		Fetcher:            fetcher,
		SkipAuthentication: *skipAuth,
		SkipTimestampCheck: *ignoreTS,
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
	switch {
	case res.DSNSig == nil:
		fmt.Fprintln(os.Stderr, "DSN's own signature: none")
	case res.DSNError != nil:
		fmt.Fprintf(os.Stderr, "DSN's own signature: fail (i=%d d=%s): %v\n",
			res.DSNSig.Sequence, res.DSNSig.Domain, res.DSNError)
	default:
		fmt.Fprintf(os.Stderr, "DSN's own signature: pass (i=%d d=%s)\n",
			res.DSNSig.Sequence, res.DSNSig.Domain)
	}
	fmt.Fprintf(os.Stderr, "alignment: %s - %s\n", res.Alignment, res.AlignDetail)
	if !res.OK {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", res.Reason)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "PASS: returned original verified")
}
