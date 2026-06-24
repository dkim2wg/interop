// Command dkim2dsn propagates a received DKIM2 DSN upstream (draft-03 §12.1.1).
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
	flag.Parse()

	if *domain == "" || *selector == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "usage: dkim2dsn -domain DOM -selector SEL -key KEY.pem [-forwarder-domain FWD] < dsn")
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
