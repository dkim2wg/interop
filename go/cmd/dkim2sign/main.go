package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dkim2wg/interop/go/dkim2"
)

func main() {
	selector := flag.String("selector", "", "DKIM2 selector (required)")
	domain := flag.String("domain", "", "Signing domain (required)")
	mailFrom := flag.String("mail-from", "", "MAIL FROM address")
	rcptToStr := flag.String("rcpt-to", "", "Comma-separated RCPT TO addresses")
	keyFile := flag.String("key", "", "Path to PKCS#8 PEM private key file (required)")
	timestamp := flag.Int64("timestamp", 0, "Signature timestamp (0 = now)")
	nextDomain := flag.String("nd", "", "nd= next-domain for an imaginary forwarding hop (draft-03 §9.3); omits mf=/rt=")
	flag.Parse()

	if *selector == "" || *domain == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "usage: dkim2sign -selector SEL -domain DOM -key KEY.pem [flags] < message")
		flag.PrintDefaults()
		os.Exit(1)
	}

	pemData, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading key: %v\n", err)
		os.Exit(1)
	}
	key, err := dkim2.LoadPrivateKey(pemData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: parsing key: %v\n", err)
		os.Exit(1)
	}

	ts := *timestamp
	if ts == 0 {
		ts = time.Now().Unix()
	}

	var rcptTo []string
	if *rcptToStr != "" {
		for _, r := range strings.Split(*rcptToStr, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				rcptTo = append(rcptTo, r)
			}
		}
	}

	opts := dkim2.SignOptions{
		Selector:   *selector,
		Domain:     *domain,
		MailFrom:   *mailFrom,
		RcptTo:     rcptTo,
		NextDomain: *nextDomain,
		Timestamp:  ts,
	}

	if err := dkim2.Sign(os.Stdin, os.Stdout, key, opts); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}
