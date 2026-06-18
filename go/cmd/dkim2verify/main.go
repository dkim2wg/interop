package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dkim2wg/interop/go/dkim2"
)

func main() {
	dnsFile := flag.String("dns", "", "Path to dns.json key file (required)")
	mailFrom := flag.String("mail-from", "", "SMTP MAIL FROM for §10.4 envelope check (optional)")
	rcptToStr := flag.String("rcpt-to", "", "Comma-separated SMTP RCPT TO for §10.4 envelope check (optional)")
	ignoreTS := flag.Bool("ignore-timestamps", false, "Disable the §10.3 timestamp (14-day/future) check")
	flag.Bool("full-chain", false, "Accepted for compatibility; full-chain validation is the default")
	flag.Parse()

	if *dnsFile == "" {
		fmt.Fprintln(os.Stderr, "usage: dkim2verify -dns DNS.json [-ignore-timestamps] [-mail-from ADDR] [-rcpt-to ADDR,...] < message")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var rcptTo []string
	for _, r := range strings.Split(*rcptToStr, ",") {
		if r = strings.TrimSpace(r); r != "" {
			rcptTo = append(rcptTo, r)
		}
	}
	opt := dkim2.VerifyOptions{MailFrom: *mailFrom, RcptTo: rcptTo, SkipTimestampCheck: *ignoreTS}

	fetcher := &dkim2.JSONKeyFetcher{Path: *dnsFile}
	results, err := dkim2.VerifyFull(os.Stdin, fetcher, opt)
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
