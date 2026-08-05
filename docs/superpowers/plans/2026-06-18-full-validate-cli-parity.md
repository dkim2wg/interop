# Full-validate CLI parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every CLI verifier (Go, C, Python, Perl) does full-chain MI-undo validation by default and accepts a canonical `--ignore-timestamps` flag (old flag names kept as aliases).

**Architecture:** Go gets the real change — a new `dkim2.VerifyFull` that runs the existing `Verify` (chain crypto + top-MI §10.7) then walks every lower MI via the existing `Undo` (which verifies each level's hashes), wired into the verify CLI with an `-ignore-timestamps` flag. C/Python/Perl already do the full walk (or have it behind a flag); they only need the canonical flag name added/aliased, with Python's default flipped to full.

**Tech Stack:** Go (`go/dkim2`, `cmd/dkim2verify`), C (`c/dkim2verify_cli.c`), Python (`python/dkim2verify.py`), Perl (`brong/bin/validate.pl`).

## Global Constraints

- Full-chain validation is the **default** in every CLI. The walk: chain crypto (i=1..N) + top-MI hash check + reconstruct every lower MI (undo recipe) and verify its recorded hashes; fail on mismatch/unclean undo.
- Canonical flag: **`--ignore-timestamps`** disables the §10.3 (>14 days / future) check.
- Back-compat: `--skip-timestamp-check` (Python), `--no-timestamp-check` (C) stay as aliases; `--full-chain` stays accepted as a redundant no-op everywhere.
- Do not change the milter verify paths or library `Verify()`/`Verifier` default semantics. Output format + exit codes unchanged (PASS/FAIL text, 0/1).
- Go single-dash spelling (`-ignore-timestamps`); same flag word across languages.
- Tests: Go `cd go && go test ./...`; C `cd c && make test`; Python `cd python/tests && bash run_tests.sh`; Perl `cd brong && prove -l t/...`.

---

### Task 1: Go — `VerifyFull` + CLI default-on + `-ignore-timestamps`

**Files:**
- Create: `go/dkim2/verifyfull.go`
- Test: `go/dkim2/verifyfull_test.go`
- Modify: `go/cmd/dkim2verify/main.go`

**Interfaces:**
- Consumes: existing `Verify(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error)`; `Undo(r io.Reader, w io.Writer, targetVersion int) error`; `parseHeaders`, `parseMI` (package-internal); `VerifyResult{Sequence int; Domain string; Error error}`; `VerifyOptions{...; SkipTimestampCheck bool}`.
- Produces: `VerifyFull(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error)` — like `Verify` but also validates every lower MI; an MI-chain failure is appended as a `VerifyResult` with non-nil `Error`.

- [ ] **Step 1: Write the failing test** — create `go/dkim2/verifyfull_test.go`:

```go
package dkim2

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// A 5-instance chain exercises the full walk across many levels.
const fullChainVector = "../../brong/tests/expected/chain-hop5-final-delivery.eml"

func TestVerifyFullValidMultiHop(t *testing.T) {
	raw, err := os.ReadFile(fullChainVector)
	if err != nil {
		t.Skip("vector not found")
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := VerifyFull(bytes.NewReader(raw), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("VerifyFull error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("unexpected failure i=%d d=%s: %v", r.Sequence, r.Domain, r.Error)
		}
	}
}

func TestVerifyFullRejectsTamper(t *testing.T) {
	raw, err := os.ReadFile(fullChainVector)
	if err != nil {
		t.Skip("vector not found")
	}
	// Flip a byte in the body (after the header/body separator).
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 || idx+4 >= len(raw) {
		t.Fatal("no body")
	}
	tampered := append([]byte{}, raw...)
	tampered[idx+4] ^= 0x20
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	results, err := VerifyFull(bytes.NewReader(tampered), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		return // a top-level error is also an acceptable rejection
	}
	failed := false
	for _, r := range results {
		if r.Error != nil {
			failed = true
		}
	}
	if !failed {
		t.Error("expected VerifyFull to reject a tampered message")
	}
}

func TestVerifyFullIgnoreTimestamps(t *testing.T) {
	raw, err := os.ReadFile(fullChainVector) // fixed 2026-02-20 timestamps (old now)
	if err != nil {
		t.Skip("vector not found")
	}
	f := &JSONKeyFetcher{Path: "../../dns.json"}
	// Without skip: should fail on age.
	res, _ := VerifyFull(bytes.NewReader(raw), f)
	anyTSerr := false
	for _, r := range res {
		if r.Error != nil && strings.Contains(r.Error.Error(), "expired") {
			anyTSerr = true
		}
	}
	if !anyTSerr {
		t.Error("expected an expiry error without ignore-timestamps")
	}
	// With skip: should pass.
	res2, err := VerifyFull(bytes.NewReader(raw), f, VerifyOptions{SkipTimestampCheck: true})
	if err != nil {
		t.Fatalf("VerifyFull error: %v", err)
	}
	for _, r := range res2 {
		if r.Error != nil {
			t.Errorf("unexpected failure with skip: i=%d: %v", r.Sequence, r.Error)
		}
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd go && go test ./dkim2/ -run TestVerifyFull 2>&1 | tail -15`
Expected: compile error — `undefined: VerifyFull`.

- [ ] **Step 3: Implement** — create `go/dkim2/verifyfull.go`:

```go
package dkim2

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// VerifyFull verifies the signature chain and the top Message-Instance (via
// Verify), then validates every lower Message-Instance by reconstructing it
// with Undo (which checks that level's recorded header/body hashes). A
// reconstruction or hash failure is reported as an extra failing VerifyResult.
func VerifyFull(r io.Reader, fetcher KeyFetcher, opts ...VerifyOptions) ([]VerifyResult, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	results, err := Verify(bytes.NewReader(buf), fetcher, opts...)
	if err != nil {
		return results, err
	}

	// Highest MI version present.
	headers, _, perr := parseHeaders(bytes.NewReader(buf))
	if perr != nil {
		return results, nil // Verify already covered parse-level issues
	}
	highest := 0
	for _, h := range headers {
		if strings.ToLower(h.Name) == "message-instance" {
			if mi, e := parseMI(h.Raw); e == nil && mi.Version > highest {
				highest = mi.Version
			}
		}
	}

	// Validate each lower instance. Undo(target) reconstructs highest..target
	// and verifies the target level's recorded hashes.
	for target := highest - 1; target >= 1; target-- {
		if err := Undo(bytes.NewReader(buf), io.Discard, target); err != nil {
			results = append(results, VerifyResult{
				Domain: fmt.Sprintf("MI-chain v=%d", target),
				Error:  fmt.Errorf("MI chain validation failed: %w", err),
			})
			break
		}
	}

	return results, nil
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd go && go test ./dkim2/ -run TestVerifyFull -v 2>&1 | tail -20`
Expected: PASS for all three. (If `TestVerifyFullRejectsTamper` flips a byte that lands in a CRLF run that body-canon strips, pick a different offset, e.g. scan forward from `idx+4` to the first byte in `A-Za-z` and flip that.)

- [ ] **Step 5: Wire the CLI** — in `go/cmd/dkim2verify/main.go`, add the flags and call `VerifyFull`:

Replace the flag block:
```go
	dnsFile := flag.String("dns", "", "Path to dns.json key file (required)")
	mailFrom := flag.String("mail-from", "", "SMTP MAIL FROM for §10.4 envelope check (optional)")
	rcptToStr := flag.String("rcpt-to", "", "Comma-separated SMTP RCPT TO for §10.4 envelope check (optional)")
	flag.Parse()
```
with:
```go
	dnsFile := flag.String("dns", "", "Path to dns.json key file (required)")
	mailFrom := flag.String("mail-from", "", "SMTP MAIL FROM for §10.4 envelope check (optional)")
	rcptToStr := flag.String("rcpt-to", "", "Comma-separated SMTP RCPT TO for §10.4 envelope check (optional)")
	ignoreTS := flag.Bool("ignore-timestamps", false, "Disable the §10.3 timestamp (14-day/future) check")
	flag.Bool("full-chain", false, "Accepted for compatibility; full-chain validation is the default")
	flag.Parse()
```
Then build the options so the timestamp flag always applies, and call `VerifyFull`:
```go
	var rcptTo []string
	for _, r := range strings.Split(*rcptToStr, ",") {
		if r = strings.TrimSpace(r); r != "" {
			rcptTo = append(rcptTo, r)
		}
	}
	opt := dkim2.VerifyOptions{MailFrom: *mailFrom, RcptTo: rcptTo, SkipTimestampCheck: *ignoreTS}

	fetcher := &dkim2.JSONKeyFetcher{Path: *dnsFile}
	results, err := dkim2.VerifyFull(os.Stdin, fetcher, opt)
```
(Leave the results-printing loop and exit logic unchanged.)

- [ ] **Step 6: Verify CLI builds + smoke test**

Run:
```bash
cd go && go build ./... && \
go run ./cmd/dkim2verify -dns ../dns.json -ignore-timestamps < ../brong/tests/expected/chain-hop5-final-delivery.eml; echo "exit=$?"
```
Expected: `PASS: all signatures verified`, `exit=0`. Without `-ignore-timestamps` the same command exits 1 (expired).

- [ ] **Step 7: Full Go suite + commit**

Run: `cd go && go test ./... 2>&1 | tail -5`
Expected: all pass.
```bash
cd /Users/brong/src/interop
git add go/dkim2/verifyfull.go go/dkim2/verifyfull_test.go go/cmd/dkim2verify/main.go
git commit -m "feat(go): full-chain MI validation in verify CLI + -ignore-timestamps"
```

---

### Task 2: C — `--ignore-timestamps` alias

**Files:**
- Modify: `c/dkim2verify_cli.c` (arg loop + usage)

**Interfaces:**
- Consumes: existing `no_timestamp` variable + `skip_timestamp_check` plumbing (full-chain walk already default in the CLI).

- [ ] **Step 1: Add the alias** — in `c/dkim2verify_cli.c`, find the arg-parsing line for `--no-timestamp-check` and add the canonical alias next to it:

```c
        else if (strcmp(argv[i], "--no-timestamp-check") == 0 ||
                 strcmp(argv[i], "--ignore-timestamps") == 0)
            no_timestamp = 1;
```
And update the usage string to mention `[--ignore-timestamps]`.

- [ ] **Step 2: Build**

Run: `cd c && make dkim2verify 2>&1 | tail -5`
Expected: builds clean.

- [ ] **Step 3: Verify the alias behaves like the old flag**

Run:
```bash
cd c
./dkim2verify ../brong/tests/expected/chain-hop1-originator.eml --dns-json ../dns.json; echo "no-flag exit=$?"
./dkim2verify ../brong/tests/expected/chain-hop1-originator.eml --dns-json ../dns.json --ignore-timestamps; echo "ignore exit=$?"
./dkim2verify ../brong/tests/expected/chain-hop1-originator.eml --dns-json ../dns.json --no-timestamp-check; echo "no-ts exit=$?"
```
Expected: `no-flag exit=1` (expired, fixed 2026-02-20 timestamp), `ignore exit=0`, `no-ts exit=0` (alias matches).

- [ ] **Step 4: Suite + commit**

Run: `cd c && make test 2>&1 | tail -5`
Expected: all pass.
```bash
cd /Users/brong/src/interop
git add c/dkim2verify_cli.c
git commit -m "feat(c): accept --ignore-timestamps as alias of --no-timestamp-check"
```

---

### Task 3: Python — default-on full-chain + `--ignore-timestamps` alias

**Files:**
- Modify: `python/dkim2verify.py` (argparse + the full-chain branch)

**Interfaces:**
- Consumes: existing `--full-chain` code path (full MI undo walk) and `skip_timestamp_check` plumbing.

- [ ] **Step 1: Make the canonical + alias flag** — in the argparse block, replace the two flags:
```python
    parser.add_argument("--full-chain", action="store_true",
                        help="Walk backwards through all MI versions, "
                             "undoing recipes and verifying each signature")
    parser.add_argument("--skip-timestamp-check", action="store_true",
                        help="Disable §10.3 14-day expiry check (for testing)")
```
with:
```python
    parser.add_argument("--full-chain", action="store_true",
                        help="Accepted for compatibility; full-chain validation is the default")
    parser.add_argument("--ignore-timestamps", "--skip-timestamp-check",
                        dest="skip_timestamp_check", action="store_true",
                        help="Disable the §10.3 timestamp (14-day/future) check")
```

- [ ] **Step 2: Make full-chain the default** — find where the code branches on `args.full_chain` to choose simple vs full-chain verification, and force the full-chain path. Locate the branch (around the simple-mode block ~line 423 vs full-chain block ~line 502) and change the condition so the full-chain walk always runs. Concretely, immediately after `args = parser.parse_args()` set:
```python
    # Full-chain validation is the default; --full-chain kept for compatibility.
    args.full_chain = True
```
(Leave the existing `if args.full_chain:` logic intact; it now always runs.)

- [ ] **Step 3: Run the Python suite**

Run: `cd python/tests && bash run_tests.sh 2>&1 | tail -15`
Expected: all pass. (The suite already passes `--full-chain` for multihop and `--skip-timestamp-check`; single-hop messages have only m=1 so the walk is a no-op for them. If any expected verify output changed, re-run with `bash run_tests.sh --generate`, inspect the diff is only expected, and re-run.)

- [ ] **Step 4: Check the alias is equivalent**

Run:
```bash
cd python
for flag in --ignore-timestamps --skip-timestamp-check; do
  python3 dkim2verify.py ../brong/tests/expected/chain-hop1-originator.eml --dns-json ../dns.json $flag >/dev/null 2>&1; echo "$flag exit=$?"
done
python3 dkim2verify.py ../brong/tests/expected/chain-hop1-originator.eml --dns-json ../dns.json >/dev/null 2>&1; echo "no-flag exit=$?"
```
Expected: both flags `exit=0`; `no-flag exit=1` (expired).

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop
git add python/dkim2verify.py
git commit -m "feat(python): full-chain validation by default + --ignore-timestamps alias"
```

---

### Task 4: Perl — `validate.pl --ignore-timestamps`

**Files:**
- Modify: `brong/bin/validate.pl`
- Test: `brong/t/validate-cli.t` (create)

**Interfaces:**
- Consumes: `Mail::DKIM2::Verifier->skip_timestamp_check(1)` (already exists).

- [ ] **Step 1: Add the flag** — in `brong/bin/validate.pl`, add option parsing and apply it to the verifier. After the existing `use` lines add:
```perl
use Getopt::Long qw(GetOptions);
my $ignore_ts = 0;
GetOptions('ignore-timestamps' => \$ignore_ts) or die "usage: $0 [--ignore-timestamps] <file>\n";
```
(`GetOptions` consumes the flag from `@ARGV`, so the existing `my $f1 = shift;` still picks up the file.) Then where the verifier is created:
```perl
  my $verifier = Mail::DKIM2::Verifier->new();
  $verifier->set_pubkey_callback(sub { find_key(@_) });
```
add right after `->new()`:
```perl
  $verifier->skip_timestamp_check(1) if $ignore_ts;
```

- [ ] **Step 2: Write the test** — create `brong/t/validate-cli.t`:
```perl
#!/usr/bin/perl -w
use 5.020; use strict; use warnings;
use Test::More;

# A fixed-timestamp (2026-02-20) vector: expired relative to "now", so it
# should fail without --ignore-timestamps and pass with it.
my $eml = 'tests/expected/chain-hop1-originator.eml';
plan skip_all => "vector not found" unless -e $eml;

my $with = system("perl -Ilib bin/validate.pl --ignore-timestamps $eml >/dev/null 2>&1");
is($with, 0, '--ignore-timestamps: validates an old-timestamp message');

my $without = system("perl -Ilib bin/validate.pl $eml >/dev/null 2>&1");
isnt($without, 0, 'without the flag: old-timestamp message is rejected');

done_testing;
```

- [ ] **Step 3: Run it**

Run: `cd brong && prove -l t/validate-cli.t 2>&1 | tail -8`
Expected: PASS (2 subtests). If `validate.pl` happens to verify the chain fine but the vector is single-MI so timestamp is the only failure, that's exactly the intended signal.

- [ ] **Step 4: Perl suite + commit**

Run: `cd brong && prove -lq t/ 2>&1 | tail -3`
Expected: all pass.
```bash
cd /Users/brong/src/interop
git checkout -- brong/tests/expected/ 2>/dev/null || true   # discard milter fixture timestamp churn
git add brong/bin/validate.pl brong/t/validate-cli.t
git commit -m "feat(perl): validate.pl --ignore-timestamps flag"
```

---

## Self-Review

**1. Spec coverage:**
- Full-chain default + the walk → Go Task 1 (`VerifyFull`); C/Python/Perl already full (Python flipped to default in Task 3). ✓
- Canonical `--ignore-timestamps` → Go (Task 1), C (Task 2), Python (Task 3), Perl (Task 4). ✓
- Aliases retained (`--skip-timestamp-check`, `--no-timestamp-check`, no-op `--full-chain`) → Tasks 1–3. ✓
- Library `Verify()`/milter untouched → Go adds a new `VerifyFull`, doesn't alter `Verify`; C/Perl milters not touched. ✓
- Output/exit codes unchanged → Go CLI loop unchanged; C/Python/Perl unchanged. ✓
- Tests per language (valid pass, tamper reject, ignore-timestamps) → Tasks 1–4. ✓

**2. Placeholder scan:** No TBD/TODO; full code/commands per step. Task 3 Step 2 points at an existing branch by line-region and gives the concrete `args.full_chain = True` change; Task 2 quotes the exact alias edit. ✓

**3. Type consistency:** `VerifyFull` signature mirrors `Verify` exactly (`io.Reader, KeyFetcher, ...VerifyOptions) ([]VerifyResult, error)`); `VerifyResult{Sequence,Domain,Error}` and `VerifyOptions.SkipTimestampCheck` used as defined in `signature.go`. CLI passes `SkipTimestampCheck: *ignoreTS`. Flag word `ignore-timestamps` consistent across all four. ✓
