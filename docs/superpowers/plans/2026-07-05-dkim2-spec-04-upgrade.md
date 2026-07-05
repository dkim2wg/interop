# DKIM2 draft-04 Spec Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring all six DKIM2 codebases (C, Go, Python, Perl, Mailman, Sympa) into conformance with `draft-ietf-dkim-dkim2-spec-04`, bump every embedded version string to `-04`, and deploy the Perl stack.

**Architecture:** Six independent codebases share one spec. The deployed signing/verification path is the **Perl** `Mail::DKIM2` library (backs the milter, reflector, validator, and is Sympa's dependency). C/Go/Python are interop reference code. Mailman ships its own embedded Python Message-Instance code. Work is organized in **tiers by change-type** (not per-codebase) so a given change lands consistently across languages: version strings → `nd=` chain semantics → canonical error strings → Python/DSN functional items → tests + deploy.

**Tech Stack:** C (cJSON, OpenSSL, libmilter), Go (stdlib), Python 3.13 (stdlib `email`, `cryptography`), Perl (Mail::DKIM2 dist, CryptX), GNU Mailman 3.3.x, Sympa 6.2.x.

**Design doc:** `docs/superpowers/specs/2026-07-05-dkim2-spec-04-upgrade-design.md`. **Supersedes** `docs/superpowers/plans/2026-06-24-dkim2-spec-03-upgrade.md`.

## Global Constraints

- **Target spec:** `draft-ietf-dkim-dkim2-spec-04` (docname `draft-ietf-dkim-dkim2-spec-04`, v04 dated **2026-07-05**). Authoritative source: `/Users/brong/src/spec/draft-ietf-dkim-dkim2-spec.mkd`.
- **Version-string form:** the constant value is `ietf-dkim-dkim2-spec-04`; the full draft name is `draft-ietf-dkim-dkim2-spec-04`. `DKIM2_DATE` = `2026-07-05`.
- **Hash/crypto unchanged:** SHA256 only; RSA-SHA256 (pubexp 65537) and Ed25519-SHA256.
- **Already conformant everywhere (do NOT touch behavior):** `delivered-to` in the ignore list; null header recipe rejected (body `b:null` still allowed); `feedhere`/`f=` flags round-trip with no enforcement; Authentication-Results excluded from the hash (not a modification). These are verified done in all codebases; only their version comments change.
- **`nd=` local policy (stricter than spec-04):** our verifiers MUST **reject** a message whose highest-`i=` DKIM2-Signature carries `nd=` (spec-04 SHOULD-tolerates it via out-of-band arrangements; we do not). The only legitimate `nd=` producer is our reflector-brand-nd path, which always emits the `nd=` signature together with its matching higher-`i=` signature. Verifiers MUST still correctly verify/undo **across** one or more consecutive `nd=` imaginary hops.
- **Error strings are matched to spec-04 byte-for-byte**, including the spec typo `DKIM2-Signature i=<x> MAIL nd= does not match` (the leading `MAIL` is a copy-paste artifact; reproduce it verbatim, fix when draft-05 does). Canonical set (from spec-04 §"Ensure … Valid" and §"Check the Chain-of-Custody"):
  ```
  DKIM2-Signature i=<x> tag=<y> missing
  DKIM2-Signature i=<x> tag=<y> was unexpected
  DKIM2-Signature i=<x> MAIL FROM <value> did not match
  DKIM2-Signature i=<x> RCPT TO <value> did not match
  DKIM2-Signature i=<x> MAIL FROM and d= do not match
  DKIM2-Signature i=<x> MAIL nd= does not match
  DKIM2-Signature i=<x> unexpected nd= tag
  ```
  `tag=<y> was unexpected` applies to **disallowed tag combinations** (e.g. `nd=` alongside `mf=`/`rt=`), NOT to unknown extension tags — unknown tags MUST still be silently ignored.
- **Test commands (per codebase):**
  - Go: `cd /Users/brong/src/interop/go && go test ./...`
  - Python: `cd /Users/brong/src/interop/python && ./tests/run_tests.sh`
  - Perl: `cd /Users/brong/src/interop/brong && perl Makefile.PL >/dev/null && make test`
  - C: `cd /Users/brong/src/interop/c && make && make test` (falls back to `make` if no `test` target)
  - Mailman: `cd /Users/brong/src/mailman && tox -e py3-nocov -- mailman.handlers.tests.test_message_instance`
- **Commit discipline:** one commit per task (or per logically-complete step group). The interop repo work happens on branch `dkim2-spec-04-upgrade`. Mailman and Sympa are separate repos (`/Users/brong/src/mailman`, `/Users/brong/src/sympa`) — commit there on their own branches.
- **Sign your commits:** end each commit message with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

## Phase 0: Baseline

### Task 0: Record the green baseline

**Files:** none (read-only)

- [ ] **Step 1: Run every suite and capture output**

```bash
cd /Users/brong/src/interop/go && go test ./... 2>&1 | tee /tmp/base-go.txt
cd /Users/brong/src/interop/python && ./tests/run_tests.sh 2>&1 | tee /tmp/base-py.txt
cd /Users/brong/src/interop/brong && perl Makefile.PL >/dev/null && make test 2>&1 | tee /tmp/base-perl.txt
cd /Users/brong/src/interop/c && make 2>&1 | tee /tmp/base-c.txt
cd /Users/brong/src/mailman && tox -e py3-nocov -- mailman.handlers.tests.test_message_instance 2>&1 | tee /tmp/base-mailman.txt
```

Expected: all currently green. Record any pre-existing failure so it is not blamed on this work. No commit.

---

## Tier 1 — Version strings

Single source of truth per codebase first (these are load-bearing / emitted at runtime), then cosmetic comments, then committed artifacts.

### Task 1.1: Perl — bump `DKIM2_DRAFT`/`DKIM2_DATE` and POD/comments

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Common.pm:41,43` (+ comment refs 45,60,83,301,343,416)
- Modify (comments/POD only): `brong/lib/Mail/DKIM2/Signature.pm` (29,97,305), `Signer.pm` (75,193), `Verifier.pm` (264,414,518), `MessageInstance.pm` (78,87,207,209,230,841), `Validate.pm` (322,374), `Reflector.pm` (143,261,285,546), `DSN.pm` (13,92,256), `TagValueList.pm` (5,71), `HeaderParser.pm:129`, `MessageStore.pm:129`, `lib/Mail/Milter/Authentication/Handler/DKIM2Sign.pm` (479,497), `DKIM2Verify.pm:349`, `bin/dkim2-milter.pl:721`, `bin/dkim2-reflector.pl:66`
- Modify: `brong/CLAUDE.md` (title line references spec-02)

- [ ] **Step 1: Write the failing test**

Add to `brong/t/version.t` (create it):

```perl
use strict; use warnings;
use Test::More;
use Mail::DKIM2::Common qw(DKIM2_DRAFT DKIM2_DATE);
is(DKIM2_DRAFT, 'ietf-dkim-dkim2-spec-04', 'draft constant is -04');
is(DKIM2_DATE, '2026-07-05', 'draft date is the -04 date');
done_testing;
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/version.t`
Expected: FAIL (`got 'ietf-dkim-dkim2-spec-03'`).

- [ ] **Step 3: Bump the constants**

In `Common.pm`, set:
```perl
use constant DKIM2_DRAFT => 'ietf-dkim-dkim2-spec-04';
use constant DKIM2_DATE  => '2026-07-05';
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/version.t` → PASS.

- [ ] **Step 5: Sweep the cosmetic references**

Replace every `spec-02` / `spec-03` / `draft-03` / `draft-02` substring in the files listed above (POD, comments, the `MessageInstance.pm:207` die string `"...not permitted under draft-03 §5.1"`, and `CLAUDE.md`'s title) with the `-04` equivalent. Verify none remain in `lib/` or `bin/`:

Run: `cd /Users/brong/src/interop/brong && grep -rIn -e 'spec-0[123]' -e 'draft-0[123]' lib bin CLAUDE.md`
Expected: no output.

- [ ] **Step 6: Full suite + commit**

Run: `cd /Users/brong/src/interop/brong && perl Makefile.PL >/dev/null && make test` → all pass.
```bash
git add brong && git commit -m "perl: bump Mail::DKIM2 to draft-ietf-dkim-dkim2-spec-04

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 1.2: Mailman — bump `DKIM2_DRAFT`/`DKIM2_DATE`/docstring

**Files:**
- Modify: `/Users/brong/src/mailman/src/mailman/handlers/message_instance.py:49,51,21`
- Modify (cosmetic): `/Users/brong/src/mailman/src/mailman/handlers/tests/test_mi_null_recipe.py:10`

- [ ] **Step 1: Write the failing test**

Add to `test_message_instance.py`:
```python
def test_draft_version_is_04(self):
    from mailman.handlers.message_instance import DKIM2_DRAFT, DKIM2_DATE
    self.assertEqual(DKIM2_DRAFT, 'ietf-dkim-dkim2-spec-04')
    self.assertEqual(DKIM2_DATE, '2026-07-05')
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd /Users/brong/src/mailman && tox -e py3-nocov -- mailman.handlers.tests.test_message_instance -k test_draft_version_is_04`
Expected: FAIL.

- [ ] **Step 3: Bump**

`message_instance.py:49` → `DKIM2_DRAFT = 'ietf-dkim-dkim2-spec-04'`; `:51` → `DKIM2_DATE = '2026-07-05'`; `:21` docstring `spec-02` → `spec-04`; `test_mi_null_recipe.py:10` comment `draft-03` → `draft-04`.

- [ ] **Step 4: Run it, verify it passes** → PASS.

- [ ] **Step 5: Commit** (in the mailman repo, on a branch)
```bash
cd /Users/brong/src/mailman && git checkout -b dkim2-spec-04 2>/dev/null || git checkout dkim2-spec-04
git add src/mailman/handlers && git commit -m "dkim2: advance Message-Instance handler to spec-04

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 1.3: Sympa — bump `DKIM2_DRAFT`/`DKIM2_DATE`

**Files:**
- Modify: `/Users/brong/src/sympa/src/lib/Sympa/Message.pm:463,465`

- [ ] **Step 1: Write the failing test**

Sympa has no unit harness for this constant; use an inline check as the gate:

Run: `cd /Users/brong/src/sympa && perl -Isrc/lib -MSympa::Message -e 'print Sympa::Message::DKIM2_DRAFT()'`
Expected now: `ietf-dkim-dkim2-spec-03` (this is the "failing" baseline).

- [ ] **Step 2: Bump**

`Message.pm:463` → `use constant DKIM2_DRAFT => 'ietf-dkim-dkim2-spec-04';`; `:465` `DKIM2_DATE` → `'2026-07-05'`.

- [ ] **Step 3: Verify**

Run the same one-liner → `ietf-dkim-dkim2-spec-04`. Also confirm no other stale refs:
`cd /Users/brong/src/sympa && grep -rIn -e 'spec-0[123]' src/lib/Sympa/Message.pm` → no output.

- [ ] **Step 4: Commit** (sympa repo, on a branch)
```bash
cd /Users/brong/src/sympa && git checkout -b dkim2-spec-04 2>/dev/null || git checkout dkim2-spec-04
git add src/lib/Sympa/Message.pm && git commit -m "dkim2: advance X-DKIM2-Info to spec-04

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 1.4: Python — bump all version strings

**Files:**
- Modify: `python/dkim2sign.py` (3,310,482), `dkim2verify.py` (3,87,533,679), `dkim2undo.py` (3,440), `dkim2dsn.py:2`, plus stale `draft-03 §N` comments in each.

- [ ] **Step 1: Write the failing test**

Add `python/tests/test_version.py`:
```python
from pathlib import Path
SRC = Path(__file__).resolve().parent.parent
def test_no_stale_spec_versions():
    stale = []
    for f in ("dkim2sign.py", "dkim2verify.py", "dkim2undo.py", "dkim2dsn.py"):
        text = (SRC / f).read_text()
        for token in ("spec-01", "spec-02", "spec-03", "draft-01", "draft-02", "draft-03"):
            if token in text:
                stale.append(f"{f}:{token}")
    assert not stale, f"stale version strings: {stale}"
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd /Users/brong/src/interop/python && python3 -m pytest tests/test_version.py -q`
Expected: FAIL listing the stale tokens.

- [ ] **Step 3: Replace**

Change every `spec-01`/`spec-02`/`spec-03` and `draft-01/02/03` occurrence in the four files to the `-04` equivalent (docstrings, argparse `description=` strings at `dkim2sign.py:482`, `dkim2verify.py:679`, `dkim2undo.py:440`, and section comments).

- [ ] **Step 4: Run it, verify it passes** → PASS.

- [ ] **Step 5: Full suite + commit**

Run: `cd /Users/brong/src/interop/python && ./tests/run_tests.sh` → pass.
```bash
git add python && git commit -m "python: bump DKIM2 tools to draft-ietf-dkim-dkim2-spec-04

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 1.5: Go — bump version strings incl. the user-visible error

**Files:**
- Modify: `go/dkim2/recipe.go:21,26` (`:26` is a runtime error string), `signature.go` (17,50,146,186,198,237), `verify.go:412`, `dsn.go:22`, `cmd/dkim2dsn/main.go:1`, tests `canon_test.go:7`, `recipe_test.go:6,8`.

- [ ] **Step 1: Write the failing test**

Add `go/dkim2/version_test.go`:
```go
package dkim2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoStaleSpecVersion(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "version_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, tok := range []string{"draft-01", "draft-02", "draft-03"} {
			if strings.Contains(string(b), tok) {
				t.Errorf("%s contains stale %q", f, tok)
			}
		}
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd /Users/brong/src/interop/go && go test ./dkim2/ -run TestNoStaleSpecVersion`
Expected: FAIL.

- [ ] **Step 3: Replace** every `draft-03` (and any `draft-01/02`) with `draft-04` across the files above, including the runtime error string at `recipe.go:26`.

- [ ] **Step 4: Run it, verify it passes** → PASS.

- [ ] **Step 5: Full suite + commit**

Run: `cd /Users/brong/src/interop/go && go test ./...` → pass.
```bash
git add go && git commit -m "go: bump DKIM2 references to draft-04 (incl. user-visible recipe error)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 1.6: C — bump comments and the bundled spec copy

**Files:**
- Modify (comments): `c/dkim2_header.c`, `c/dkim2_hash.c`, `c/dkim2_verify.c` (`draft-03`/`§` refs), `c/TODO-dsn.md:1`, `c/INTEROP-NOTES.md:381`
- Replace: `c/dkim2-spec.txt` (currently an entire `-01` copy)

- [ ] **Step 1: Refresh the bundled spec text**

```bash
cp /Users/brong/src/spec/draft-ietf-dkim-dkim2-spec.txt /Users/brong/src/interop/c/dkim2-spec.txt
```
(If `.txt` is not built in the spec repo, run `make` there first, or export from the `.mkd`.)

- [ ] **Step 2: Sweep comments**

Replace `draft-03`/`draft-01`/`spec-01` in the `.c` files, `TODO-dsn.md`, and `INTEROP-NOTES.md:381` with `draft-04`.

Run: `cd /Users/brong/src/interop/c && grep -rIn -e 'draft-0[123]' -e 'spec-0[123]' *.c *.h TODO-dsn.md INTEROP-NOTES.md`
Expected: no output (the refreshed `dkim2-spec.txt` legitimately contains `-04`).

- [ ] **Step 3: Rebuild + commit**

Run: `cd /Users/brong/src/interop/c && make` → builds clean.
```bash
git add c && git commit -m "c: refresh bundled spec to -04 and update section comments

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 1.7: interop repo — refresh committed spec artifact + docs

**Files:**
- Create: `spec/draft-ietf-dkim-dkim2-spec-04.txt` (copy from `/Users/brong/src/spec`)
- Modify: `docs/dkim2-operator-guide.md`, `docs/dkim2-implementer-guide.md`, `docs/dkim2-wg-interop-status.md`, `deploy/SERVER.md`, `DKIM2-PORTING-PLAN.md`, `README.md`, `hs/README.md` — update `spec-0X` references to `-04`.

- [ ] **Step 1: Add the -04 spec copy**

```bash
cp /Users/brong/src/spec/draft-ietf-dkim-dkim2-spec.txt /Users/brong/src/interop/spec/draft-ietf-dkim-dkim2-spec-04.txt
```

- [ ] **Step 2: Update doc references**

Replace stale `draft-ietf-dkim-dkim2-spec-0[123]` references in the docs above with `-04` (leave historical plan/spec docs under `docs/superpowers/` untouched — they are dated records).

Run: `cd /Users/brong/src/interop && grep -rIn 'dkim2-spec-0[123]' docs deploy README.md DKIM2-PORTING-PLAN.md hs/README.md | grep -v 'docs/superpowers/'`
Expected: no output.

- [ ] **Step 3: Commit**
```bash
git add spec docs deploy README.md DKIM2-PORTING-PLAN.md hs/README.md
git commit -m "docs: add -04 spec copy and update references

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Tier 2 — `nd=` chain semantics

Reject `nd=` on the highest signature; verify/undo correctly across `nd=` imaginary hops (including consecutive runs); add Perl's missing required-tag completeness check.

### Task 2.1: Perl verifier — reject top `nd=`, require `i,m,t,d,s`, keep nd= undo

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Verifier.pm` (`finish_body` around :97-108; `_verify_signature` :266-278)
- Test: `brong/t/nd-chain.t` (create)

**Interfaces:**
- Consumes: `Mail::DKIM2::Signature->next_domain`, `->get_tag`, `->sequence` (existing).
- Produces: no new public API; behavioral change only.

- [ ] **Step 1: Write failing tests**

Create `brong/t/nd-chain.t`. Use the existing test helpers (see `t/full-chain.t` for how messages are signed with the dns.json/keys fixtures). Three cases:
1. A chain `i=1 mf/rt`, `i=2 nd=<matches i=3 d>`, `i=3 nd=<matches ... >` … ending in a top sig **with** `mf/rt` verifies `pass` (single and doubled `nd=` run — reflector-brand-nd shape).
2. A message whose **highest** signature carries `nd=` → result `permerror`, detail matches `qr/DKIM2-Signature i=\d+ unexpected nd= tag/`.
3. A signature missing `t=` → result `permerror`, detail matches `qr/DKIM2-Signature i=\d+ tag=t missing/`.

```perl
# sketch of case 2 assertion once $v has verified the top-nd message:
is($v->result, 'permerror', 'top nd= rejected');
like($v->result_detail, qr/DKIM2-Signature i=\d+ unexpected nd= tag/, 'correct detail');
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib -It t/nd-chain.t`
Expected: FAIL — case 2 currently yields `fail (missing MAIL FROM ...)`, case 3 currently yields the non-canonical "missing required" wording.

- [ ] **Step 3: Reject top `nd=` in `finish_body`**

In `Verifier.pm`, immediately after `$signature` for `$max_i` is resolved (after line 99, before the chain-completeness loop), add:

```perl
    # Local policy (stricter than spec-04 §"Check the Chain-of-Custody"): the
    # highest-numbered DKIM2-Signature MUST NOT carry nd=. The only legitimate
    # nd= producer is reflector-brand-nd, which always emits the matching
    # higher-i= signature too, so nd= never appears on top.
    if (defined $signature->next_domain && length $signature->next_domain) {
        $self->{result}  = 'permerror';
        $self->{details} = "DKIM2-Signature i=$max_i unexpected nd= tag";
        return;
    }
```

- [ ] **Step 4: Add `i,m,t,d,s` completeness in `_verify_signature`**

In `Verifier.pm`, before the existing nd/mf/rt block at :266, add a presence check that emits the canonical `tag=<y> missing` string (first missing tag, in `i,m,t,d,s` order):

```perl
    for my $t (qw(i m t d s)) {
        my $present = $t eq 'i' ? defined($signature->sequence)
                    : $t eq 'm' ? defined($signature->version)
                    : $t eq 't' ? defined($signature->timestamp)
                    : $t eq 'd' ? (defined($signature->domain) && length $signature->domain)
                    :             ($signature->sig_count ? 1 : 0);  # s=
        unless ($present) {
            $self->{result}  = 'permerror';
            $self->{details} = "DKIM2-Signature i=$i tag=$t missing";
            return 0;
        }
    }
```

(Confirm the accessor names against `Signature.pm`; adjust if `version`/`timestamp` return 0 legitimately — use `defined` on the parsed tag via `$signature->get_tag('m')` etc. if the accessor coerces.)

- [ ] **Step 5: Run it, verify it passes**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib -It t/nd-chain.t` → PASS (all three cases). Confirm the existing `_verify_chain` nd= adjacency handling (:416-425) still lets case 1 pass unchanged.

- [ ] **Step 6: Full suite + commit**

Run: `make test` → all pass.
```bash
git add brong/lib/Mail/DKIM2/Verifier.pm brong/t/nd-chain.t
git commit -m "perl: reject top nd=, require i/m/t/d/s, keep nd= undo (spec-04)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.2: C verifier — reject top `nd=`

**Files:**
- Modify: `c/dkim2_verify.c` (chain-of-custody area ~:536-548; the top signature is `latest`, envelope checks at :406/:427)
- Test: `c/tests/test_verify.c` (add a case; follow existing test style)

- [ ] **Step 1: Write the failing test**

Add a test that verifies a message whose highest DKIM2-Signature has `nd=` returns a failure whose message contains `unexpected nd= tag`. Reuse an existing fixture-construction helper in `tests/`; if none builds a top-nd message, craft the header block inline as the other `test_verify.c` cases do.

- [ ] **Step 2: Run it, verify it fails**

Run: `cd /Users/brong/src/interop/c && make test` (or the specific test binary) → FAIL (top nd= currently tolerated / wrong message).

- [ ] **Step 3: Implement rejection**

In `dkim2_verify.c`, after the highest signature (`latest`) is identified and before/at the chain-of-custody envelope checks, add: if `latest->nd` is non-NULL/non-empty, set the error to `"DKIM2-Signature i=%d unexpected nd= tag"` (with `latest->i`) and fail. Keep the existing adjacency match at :542-547 for non-top `nd=` sigs.

- [ ] **Step 4: Run it, verify it passes** → PASS.

- [ ] **Step 5: Rebuild full + commit**

Run: `cd /Users/brong/src/interop/c && make && make test` → pass.
```bash
git add c && git commit -m "c: reject top nd= DKIM2-Signature (spec-04 local policy)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.3: Go verifier — reject top `nd=`

**Files:**
- Modify: `go/dkim2/verify.go` (in `Verify`/`checkChainOfCustody`, ~:411-417 handles adjacency; add a top-sig guard where the highest sig is known)
- Test: `go/dkim2/verify_nd_test.go` (create) or extend `signature_nd_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestTopNdRejected(t *testing.T) {
	// build/sign a message whose highest DKIM2-Signature carries nd=
	// (reuse the signing helpers used by signature_nd_test.go / dsn_test.go)
	_, err := Verify(msg, keyLookup)
	if err == nil || !strings.Contains(err.Error(), "unexpected nd= tag") {
		t.Fatalf("want unexpected nd= tag, got %v", err)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd /Users/brong/src/interop/go && go test ./dkim2/ -run TestTopNdRejected` → FAIL.

- [ ] **Step 3: Implement rejection**

In `verify.go`, once the highest-`i=` signature is selected, return `fmt.Errorf("DKIM2-Signature i=%d unexpected nd= tag", top.I)` if `top.ND != ""`. Leave `checkChainOfCustody`'s adjacency logic (which already `next`s over `nd=` hops) intact so consecutive `nd=` runs still verify.

- [ ] **Step 4: Run it, verify it passes** → PASS.

- [ ] **Step 5: Full suite + commit**

Run: `go test ./...` → pass.
```bash
git add go && git commit -m "go: reject top nd= DKIM2-Signature (spec-04 local policy)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.4: Python verifier — reject top `nd=`

**Files:**
- Modify: `python/dkim2verify.py` `verify_message` (after `top_sig` is resolved, ~:535)
- Test: `python/tests/test_nd_chain.py` (create)

- [ ] **Step 1: Write the failing test**

```python
def test_top_nd_rejected(...):
    # sign a message whose highest DKIM2-Signature carries nd= (use dkim2sign helpers)
    result = verify_message(raw, dns_data, full_chain=True, skip_timestamp_check=True)
    assert result.status == 'permerror'
    assert 'unexpected nd= tag' in result.message
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd /Users/brong/src/interop/python && python3 -m pytest tests/test_nd_chain.py -q` → FAIL.

- [ ] **Step 3: Implement rejection**

In `verify_message`, after `top_sig`/`top_sig_value` are computed (~:536) and before the MI-coverage check, add:

```python
    if _extract_tag(top_sig_value, "nd"):
        top_i = _get_seq_from_sig(top_sig)
        msg = f"DKIM2-Signature i={top_sig_seq} unexpected nd= tag"
        return VerifyResult(ok=False, status='permerror', failing_i=top_i,
                            domain=_extract_tag(top_sig_value, 'd') or '',
                            message=msg, errors=[msg])
```

- [ ] **Step 4: Run it, verify it passes** → PASS. Confirm `_chain_custody_errors` still passes a non-top `nd=` run.

- [ ] **Step 5: Full suite + commit**

Run: `./tests/run_tests.sh` → pass.
```bash
git add python && git commit -m "python: reject top nd= DKIM2-Signature (spec-04 local policy)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 2.5: Perl validator — reject top `nd=` in `Validate.pm`

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Validate.pm` (nd= handling ~:321-327; add top-sig check)
- Test: `brong/t/validate.t` (extend if present, else add a focused test)

- [ ] **Step 1: Write the failing test**

Feed the validator a top-`nd=` message and assert it reports a failing level whose message matches `qr/unexpected nd= tag/`. Follow the existing `Validate.pm` result-object shape (the web validator consumes it).

- [ ] **Step 2: Run it, verify it fails** → FAIL.

- [ ] **Step 3: Implement** the same top-`nd=` rejection in the validator's chain analysis, emitting `"DKIM2-Signature i=$i unexpected nd= tag"` at the appropriate severity used for other PERMERROR-class findings.

- [ ] **Step 4: Run it, verify it passes** → PASS.

- [ ] **Step 5: Commit**
```bash
git add brong/lib/Mail/DKIM2/Validate.pm brong/t/validate.t
git commit -m "validator: flag top nd= DKIM2-Signature as invalid (spec-04)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Tier 3 — Canonical error strings

Rewrite verifier/validator custody + `nd=` messages to the exact spec-04 forms (see Global Constraints for the canonical set, including the verbatim `MAIL nd=` typo). Unknown extension tags stay ignored.

### Task 3.1: Perl verifier error strings

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Verifier.pm` (:271, :276, :330, :421, :433, :438, :454)
- Test: `brong/t/error-strings.t` (create)

**Current → target:**
- `:271` `"DKIM2-Signature i=$i tag=nd was unexpected"` → **keep** (already canonical form for the disallowed combination).
- `:276` `"DKIM2-Signature i=$i missing chain tags (nd= or mf=+rt=)"` → this is a required-combination failure; use `"DKIM2-Signature i=$i tag=mf missing"` (mf is the representative missing tag when neither nd nor mf/rt present). Keep the meaning; adopt canonical `tag=<y> missing` shape.
- `:330` `"d=$sig_domain does not match mf domain $mf_domain at i=$i"` → `"DKIM2-Signature i=$i MAIL FROM and d= do not match"`.
- `:421` `"DKIM2-Signature i=$prev_i nd= does not match d= of i=$cur_i"` → `"DKIM2-Signature i=$prev_i MAIL nd= does not match"` (verbatim `MAIL` typo).
- `:433` `"missing MAIL FROM at i=$cur_i"` → `"DKIM2-Signature i=$cur_i MAIL FROM <> did not match"` (a missing/empty mf on a non-nd hop is a custody-match failure; include the `<value>` slot).
- `:438` `"missing RCPT TO at i=$prev_i"` → `"DKIM2-Signature i=$prev_i RCPT TO <> did not match"`.
- `:454` `"chain of custody break at i=$cur_i"` → `"DKIM2-Signature i=$cur_i MAIL FROM $cur_mf did not match"` (`$cur_mf` is the offending value).

- [ ] **Step 1: Write failing tests** in `t/error-strings.t` asserting each canonical string via `like($v->result_detail, qr/…/)` for a purpose-built failing message per case.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Apply the string edits above.**
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5:** `make test` → pass; commit:
```bash
git add brong/lib/Mail/DKIM2/Verifier.pm brong/t/error-strings.t
git commit -m "perl: canonical spec-04 verifier error strings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 3.2: C verifier error strings

**Files:**
- Modify: `c/dkim2_verify.c` (:422-423, :433-435, :478-480, and the nd= message :544-546)
- Test: `c/tests/test_verify.c`

**Current → target:**
- `:422-423` MAIL FROM msg → `"DKIM2-Signature i=%d MAIL FROM %s did not match"` (`i`, offending mf value).
- `:433-435` RCPT TO msg → `"DKIM2-Signature i=%d RCPT TO %s did not match"`.
- `:478-480` d= vs mf msg → `"DKIM2-Signature i=%d MAIL FROM and d= do not match"`.
- `:544-546` nd= msg → `"DKIM2-Signature i=%d MAIL nd= does not match"` (verbatim `MAIL`).

- [ ] **Step 1:** Add/extend tests asserting the exact substrings. **Run → FAIL.**
- [ ] **Step 2:** Apply the edits. **Run → PASS.**
- [ ] **Step 3:** `make && make test`; commit:
```bash
git add c && git commit -m "c: canonical spec-04 verifier error strings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 3.3: Go verifier error strings

**Files:**
- Modify: `go/dkim2/verify.go` (custody/mf/rt/d/nd messages), `signature.go` (parse-time messages missing `i=` prefix at :72,80,87,94,152,155)
- Test: `go/dkim2/verify_errstrings_test.go` (create)

- [ ] **Step 1:** Table-test asserting each canonical spec-04 form (incl. `MAIL nd= does not match`) and that parse errors carry `DKIM2-Signature i=<x>` where an `i=` is known. **Run → FAIL.**
- [ ] **Step 2:** Rewrite the messages to the canonical set; add the `i=` prefix to `signature.go:72,80,87,94,152,155` where the sequence is available (use `tag=<y> missing`/`tag=<y> syntax error` shapes). **Run → PASS.**
- [ ] **Step 3:** `go test ./...`; commit:
```bash
git add go && git commit -m "go: canonical spec-04 verifier error strings + i= prefixes

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 3.4: Python verifier error strings

**Files:**
- Modify: `python/dkim2verify.py` (:173, :180-181, :191-194, :349-350, :352-353, :355-356)
- Test: `python/tests/test_error_strings.py` (create)

**Current → target:**
- `:173` nd= mismatch → `f"DKIM2-Signature i={prev_i} MAIL nd= does not match"`.
- `:191-194` custody break → `f"DKIM2-Signature i={cur_i} MAIL FROM {cur_mf} did not match"`.
- `:180-181` "missing mf= or rt= for chain custody" → split: emit `f"DKIM2-Signature i={cur_i} MAIL FROM <> did not match"` when mf missing / `f"DKIM2-Signature i={prev_i} RCPT TO <> did not match"` when rt missing.
- `:349-350` missing required tag(s) → `f"DKIM2-Signature i={i_val} tag={first_missing} missing"` (compute first missing of i,m,t,d,s).
- `:352-353` nd+mf/rt → `f"DKIM2-Signature i={i_val} tag=nd was unexpected"`.
- `:355-356` neither nd nor mf/rt → `f"DKIM2-Signature i={i_val} tag=mf missing"`.

- [ ] **Step 1:** Assert each form. **Run → FAIL.**
- [ ] **Step 2:** Apply edits (note `_classify_status` keys on substrings like `did not match`→`fail`; keep that mapping working — `did not match` contains no `failed`/`mismatch`/`break`, so add `'did not match'` to the `fail` keyword set in `_classify_status` at :474). **Run → PASS.**
- [ ] **Step 3:** `./tests/run_tests.sh`; commit:
```bash
git add python && git commit -m "python: canonical spec-04 verifier error strings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 3.5: Validator error strings + UI labels

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Validate.pm` (:327 nd= message and custody messages), plus any validator UI template that echoes them.
- Test: extend `brong/t/validate.t`.

- [ ] **Step 1:** Assert the validator surfaces the canonical strings. **Run → FAIL.**
- [ ] **Step 2:** Align `Validate.pm` messages with Task 3.1's set. **Run → PASS.**
- [ ] **Step 3:** commit:
```bash
git add brong/lib/Mail/DKIM2/Validate.pm brong/t/validate.t
git commit -m "validator: canonical spec-04 error strings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Tier 4 — Python functional gap + DSN grounding

### Task 4.1: Python verifier — envelope checks + relaxed d↔mf + null-`h` reject

**Files:**
- Modify: `python/dkim2verify.py` (`verify_dkim2_signature` add relaxed d↔mf; `verify_message` add optional envelope check on top sig; `:640-641` reject present-null `h`)
- Modify: `python/dkim2verify.py` `main()` — add `--mail-from`, `--rcpt-to` (repeatable) args
- Test: `python/tests/test_envelope.py` (create)

**Interfaces:**
- Produces: `verify_message(..., mail_from: str | None = None, rcpt_to: list[str] | None = None)` — new optional params, threaded from `main()`.

- [ ] **Step 1: Write failing tests**
  1. Top sig `mf=` domain not matching its own `d=` (relaxed) → `MAIL FROM and d= do not match`.
  2. With `mail_from` supplied that isn't the top sig's `mf=` value → `DKIM2-Signature i=<x> MAIL FROM <value> did not match`.
  3. With `rcpt_to` supplied whose value isn't in the top sig's `rt=` set → `RCPT TO <value> did not match`.
  4. A recipe with JSON `"h": null` in full-chain mode → an error (not silently skipped).

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement**
  - In `verify_dkim2_signature`, after the tag checks, add the relaxed d↔mf match (mirrors Perl `Verifier.pm:326-333`): if `mf_val` present and decoded ≠ `<>`, require `_relaxed_domain_match(_domain_from_addr(decoded_mf), d_val)` else append `f"DKIM2-Signature i={i_val} MAIL FROM and d= do not match"`.
  - Add `mail_from`/`rcpt_to` params to `verify_message`; when provided, compare (exact, domains lowercased per spec §"Check the Chain-of-Custody") against the **top** sig's decoded `mf=`/`rt=` and emit the canonical `MAIL FROM <value>` / `RCPT TO <value>` errors.
  - At `:640-641`, change the silent skip so a present `h` that is JSON `null` raises the canonical error (match `dkim2undo.py:325-329`): `if "h" in recipes and recipes["h"] is None: all_errors.append(f"v={version}: header recipe is null: not permitted")`.
  - In `main()`, add `parser.add_argument("--mail-from")` and `parser.add_argument("--rcpt-to", action="append")`, and pass them through.

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5:** `./tests/run_tests.sh`; commit:
```bash
git add python && git commit -m "python: envelope MAIL FROM/RCPT TO + relaxed d<->mf checks; reject null h

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 4.2: Python signer — expose `--next-domain` and `--flag`

**Files:**
- Modify: `python/dkim2sign.py` (`sign_message` ~:425-467 to accept `next_domain`/`flags`; `main` ~:480-509 to add the args and pass through to `build_dkim2_signature` at :353)
- Test: `python/tests/test_sign_cli.py` (create)

- [ ] **Step 1: Write failing tests** — signing with `--next-domain example.org` emits `nd=example.org` and no `mf=`/`rt=`; signing with `--flag feedhere` emits `f=feedhere`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the param threading (`build_dkim2_signature` already supports `next_domain=`/`flags=` at :353/:365-367; just wire them through `sign_message` and `main`).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5:** commit:
```bash
git add python && git commit -m "python: wire --next-domain and --flag through the sign CLI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 4.3: Perl DSN — RFC 3462 grounding + strict 3-part validation

**Files:**
- Modify: `brong/lib/Mail/DKIM2/DSN.pm` (:13,92,256 references; `propagate` part-count check ~:180)
- Test: `brong/t/dsn.t` (extend if present, else create)

- [ ] **Step 1: Write failing tests** — `propagate` rejects a `multipart/report` DSN that lacks a `message/delivery-status` part (currently only `@parts >= 3` is checked); accepts a valid 3-part DSN.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — replace the bare count check with structural validation: part[0] is human-readable text (`text/plain`), one part is `message/delivery-status`, and one part is `message/rfc822` OR `text/rfc822-headers`; update comments to cite **RFC 3462** instead of "draft-03 §12.1.1".
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5:** `make test`; commit:
```bash
git add brong/lib/Mail/DKIM2/DSN.pm brong/t/dsn.t
git commit -m "perl: DSN validates 3-part RFC3462 structure

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 4.4: Python DSN — RFC 3462 + structure validation

**Files:**
- Modify: `python/dkim2dsn.py` (:2 reference; `propagate` :71-84)
- Test: `python/tests/test_dsn.py` (extend if present, else create)

- [ ] **Step 1: Write failing test** — a `multipart/report` missing `message/delivery-status` is rejected.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — beyond `multipart/report` + `len(parts) >= 3`, require part[0] text/human-readable and a `message/delivery-status` part; update the docstring to cite RFC 3462.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5:** commit:
```bash
git add python && git commit -m "python: DSN validates 3-part RFC3462 structure

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 4.5: Go DSN — strict 3-part validation

**Files:**
- Modify: `go/dkim2/dsn.go` (:22 reference; `Propagate` :56-68)
- Test: `go/dkim2/dsn_test.go` (extend)

- [ ] **Step 1: Write failing test** — reject a `multipart/report` lacking `message/delivery-status`.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the structural check + RFC 3462 comment.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5:** `go test ./...`; commit:
```bash
git add go && git commit -m "go: DSN validates 3-part RFC3462 structure

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Tier 5 — Tests + deploy

### Task 5.1: Mailman — lock `Delivered-To` exclusion in tests

**Files:**
- Modify: `/Users/brong/src/mailman/src/mailman/handlers/tests/test_message_instance.py` (`test_excluded_headers` :78-82)

- [ ] **Step 1:** Add `Delivered-To` to the asserted-excluded set in `test_excluded_headers`.
- [ ] **Step 2:** Run `cd /Users/brong/src/mailman && tox -e py3-nocov -- mailman.handlers.tests.test_message_instance` → PASS (code already excludes it).
- [ ] **Step 3:** commit (mailman repo):
```bash
cd /Users/brong/src/mailman && git add src/mailman/handlers/tests/test_message_instance.py
git commit -m "test: assert Delivered-To is excluded from the header hash

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 5.2: Cross-implementation interop pass

**Files:** none (verification)

- [ ] **Step 1: Regenerate + cross-verify**

Run each impl's full suite (Global Constraints commands). Then run the interop cross-check the repo already has (Perl `t/interop.t` verifies Python-generated `../python/tests/expected/`; confirm C/Go/Python still verify the shared corpus after the error-string and `nd=` changes).

Run: `cd /Users/brong/src/interop/brong && make test` and re-run the go/python/c suites.
Expected: all green; error-string changes did not break any cross-impl string comparison.

- [ ] **Step 2:** If any interop fixture encodes an old error string, update the fixture (not the code) and note it. Commit any fixture updates:
```bash
git add -A && git commit -m "test: refresh interop fixtures for spec-04 error strings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task 5.3: Deploy the full stack (Perl + Mailman + Sympa) + live smoke test

**Files:** none (deploy) — follow `deploy/SERVER.md`.

Deploy ALL THREE deployed components to the demo box, not just the Perl milter/reflector: the Perl `Mail::DKIM2` stack, the **Mailman** handler, and the **Sympa** integration must all advertise `-04` on live mail.

- [ ] **Step 1 (Perl stack):** Merge `dkim2-spec-04-upgrade` to `master` locally (per project convention — finishing a dev branch here is always "merge locally"), then on the demo box `git pull` the interop repo and restart the milter/reflector services per `deploy/SERVER.md`.
- [ ] **Step 2 (Mailman):** Deploy the Mailman `dkim2` branch to the server's Mailman install (rsync/pull the `src/mailman/handlers/message_instance.py` change per `deploy/SERVER.md`'s Mailman procedure) and restart the Mailman service so the handler reloads.
- [ ] **Step 3 (Sympa):** Deploy the Sympa `dkim2` branch (`src/lib/Sympa/Message.pm`) to the server's Sympa install and restart the Sympa services so `X-DKIM2-Info` picks up `-04`.
- [ ] **Step 4 (smoke test):** Send a live test message through each path on `mail.dkim2.com` — direct milter, a Mailman list, and a Sympa list — and confirm each outbound message's `X-DKIM2-Info` header advertises `draft=ietf-dkim-dkim2-spec-04` and verifies (`dkim2-milter` logs `pass`).
- [ ] **Step 5:** Record the validation (all three paths) in `deploy/SERVER.md` or a short note commit.

> Note: Mailman and Sympa tests can't run in the local dev environment (no `tox`; Sympa deps). Their behavioral verification happens here, on the server, via the live smoke test.

---

## Self-Review notes (author)

- **Spec coverage:** every design §/tier maps to tasks — Tier 1→1.1-1.7, Tier 2→2.1-2.5, Tier 3→3.1-3.5, Tier 4→4.1-4.5, Tier 5→5.1-5.3. Items already-done (B/C/E/F) intentionally have no behavioral task, only version-comment sweeps.
- **`nd=` semantics** are captured as: reject-top (2.1-2.5), keep undo-across-runs (verified by 2.1 case 1 + existing adjacency logic), Perl completeness (2.1 step 4).
- **Error-string typo** (`MAIL nd=`) is reproduced verbatim per the agreed decision; called out in Global Constraints and Tasks 3.1-3.5.
- **Open confirmations for implementers:** (a) exact Perl `Signature` accessor coercion for the i/m/t/d/s presence check (Task 2.1 step 4 note); (b) whether `c/tests/` and `brong/t/` have a top-nd fixture helper or one must be crafted inline; (c) the validator UI template path echoing error strings (Task 3.5).
