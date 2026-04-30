package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dkim2wg/interop/go/dkim2"
)

func main() {
	dnsFile := flag.String("dns", "", "Path to dns.json key file (required)")
	flag.Parse()

	if *dnsFile == "" {
		fmt.Fprintln(os.Stderr, "usage: dkim2verify -dns DNS.json < message")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fetcher := &dkim2.JSONKeyFetcher{Path: *dnsFile}
	results, err := dkim2.Verify(os.Stdin, fetcher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	allPass := true
	for _, r := range results {
		if r.Error != nil {
			fmt.Fprintf(os.Stderr, "FAIL i=%d d=%s: %v\n", r.Sequence, r.Domain, r.Error)
			allPass = false
		} else {
			fmt.Fprintf(os.Stderr, "PASS i=%d d=%s\n", r.Sequence, r.Domain)
		}
	}

	if allPass {
		fmt.Fprintln(os.Stdout, "PASS: all signatures verified")
	} else {
		os.Exit(1)
	}
}
