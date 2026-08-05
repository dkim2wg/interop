package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dkim2wg/interop/go/dkim2"
)

func main() {
	targetVersion := flag.Int("target-version", -1,
		"MI version to reconstruct back to (-1 = highest-1, 0 = original pre-signing state)")
	verbose := flag.Bool("v", false, "Print progress to stderr")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: dkim2undo [flags] <message-file | ->")
		flag.PrintDefaults()
		os.Exit(1)
	}

	path := flag.Arg(0)
	var in *os.File
	if path == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		in = f
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "target version: %d\n", *targetVersion)
	}

	if err := dkim2.Undo(in, os.Stdout, *targetVersion); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}
