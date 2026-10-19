# util/xbench — cross-implementation verify benchmark

`util/xbench.sh` runs each verifier in-process over the same messages with
keys from dns.json, so it compares verification code only (no DNS, no
process start-up). See the header of `util/xbench.sh` for the sets and
knobs. One harness per implementation here; Go's is the in-package test
`go/dkim2/xbench_test.go` (it needs the package's key-record parser).
C is built at -O2 from the `c/` sources.
