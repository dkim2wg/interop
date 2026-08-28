# DKIM2 draft-06 Spec Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring all seven DKIM2 implementations into conformance with `draft-ietf-dkim-dkim2-spec-05` and deploy through to production acceptance.

**Architecture:** Three substantive changes plus a version sweep. (1) The §4 unsigned-header list gains eight names and a `Received-*` prefix rule while the `ARC-` prefix narrows to three exact names — this changes header hashes, so it lands first and forces a fixture regeneration. (2) Hash agility: each verifier parses `h=` into a list of `{alg, headerHash, bodyHash}` and dispatches through a per-language supported-algorithm registry, adding sha512; signers gain an opt-in `--hash` flag defaulting to sha256. (3) New duplicate/limit validation on `h=` and `s=` with four new PERMERROR strings.

**Tech Stack:** Perl (`Mail::DKIM2`, Test::More/prove), C (OpenSSL EVP, assert-based tests, make), Go (stdlib crypto, go test), Python 3 (hashlib, pytest), browser JS (WebCrypto, `node --test`), Mailman 3 (Python/unittest), Sympa (Perl, consumes `Mail::DKIM2`).

**Spec:** `docs/superpowers/specs/2026-08-25-dkim2-spec-05-upgrade-design.md`

## Global Constraints

- **Authoritative spec text:** `spec/draft-ietf-dkim-dkim2-spec-05.txt`. The `-05` markdown is **not in git** — do not try to regenerate it from `dkim2wg/spec`, whose `main` still says `docname: draft-ietf-dkim-dkim2-spec-04`.
- **Version strings:** `DKIM2_DRAFT` = `ietf-dkim-dkim2-spec-05` (no `draft-` prefix in the constant), `DKIM2_DATE` = `2026-08-25`.
- **Branches:** Mailman and Sympa work happens on their existing `dkim2` branches, **never** master/main. Interop work is on a branch off `master`.
- **Signer default is unchanged:** `--hash` defaults to `sha256`. No task may change default signer output. If a golden fixture changes for any reason other than Task 7's `Received-SPF` regeneration, stop and report.
- **The canonical §4 unsigned-header set** (used verbatim by Tasks 1–6):

  Exact names (lowercase): `apparently-to`, `arc-authentication-results`, `arc-message-signature`, `arc-seal`, `authentication-results`, `auto-submitted`, `delivered-to`, `dkim-signature`, `dkim2-signature`, `dl-expansion-history`, `message-instance`, `original-recipient`, `received`, `return-path`, `sio-label-history`, `vbr-info`, `x400-received`, `x400-trace`

  Prefixes: `x-`, `received-`

  Notes: `arc-` is **no longer** a prefix — only the three exact ARC names. `x400-received` and `x400-trace` do **not** match the `x-` prefix and need their own entries. `x400-received` does **not** match the `received-` prefix either. `message-instance` and `dkim2-signature` are not in the spec's §4.1 summary (they are excluded by §6.2 instead) but every implementation here carries them in the same list; keep them.

- **New PERMERROR strings, verbatim** (Tasks 8–17):
  - `PERMERROR Message-Instance m=<x> has a duplicate hash algorithm`
  - `PERMERROR Message-Instance m=<x> contains invalid JSON`
  - `PERMERROR DKIM2-Signature i=<x> has a duplicate selector`
  - `PERMERROR DKIM2-Signature i=<x> has too many signatures`
- **Hash verification semantics:** verify every hash-set whose algorithm is implemented; **all** must pass; if **none** names an implemented algorithm, fail closed. Skip hash-sets naming unimplemented algorithms per §3.4.
- **Case handling:** hash-name matching/dedup and Selector dedup are **case-insensitive** (RFC 5234 quoted strings; Selector is a DNS name).

---

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `python/dkim2sign.py` | exclusion list, MI `h=` construction, `--hash` flag | 1, 8 |
| `python/dkim2verify.py` | hash-set list parsing, sha512, dup checks | 8, 13 |
| `go/dkim2/canon.go` | exclusion list, digest registry | 2, 9 |
| `go/dkim2/mi.go` | hash-set list parsing | 9, 14 |
| `go/cmd/dkim2sign/main.go` | `-hash` flag | 9 |
| `perl/lib/Mail/DKIM2/Common.pm` | `should_skip`, version constants | 3, 19 |
| `perl/lib/Mail/DKIM2/MessageInstance.pm` | `h=` build/parse | 10 |
| `perl/lib/Mail/DKIM2/Verifier.pm` | hash-set verification, dup checks | 10, 15 |
| `c/dkim2_hash.h` / `.c` | algorithm registry, multi-alg hashers | 4, 11 |
| `c/dkim2_header.c` | `parse_hsets` dup detection | 11, 16 |
| `c/dkim2_verify.c` | per-alg hash comparison | 11, 16 |
| `deploy/www/verify/canon.js` | exclusion list | 5 |
| `deploy/www/verify/crypto.js` | sha512 helper | 12 |
| `deploy/www/verify/verify.js` | hash-set dispatch, dup checks | 12, 17 |
| `mailman/src/mailman/handlers/message_instance.py` | exclusion list, version constants | 6, 19 |
| `sympa/src/lib/Sympa/Message.pm` | version constants (inherits `should_skip`) | 19 |
| `util/hash-matrix.sh` | **new** — cross-implementation hash-agility matrix | 21 |

---

## Phase 1 — §4 unsigned header fields

These six tasks are the same change in six languages. They change header hashes, so they land before anything else and Task 7 repairs the fallout.

### Task 1: Python — §4 unsigned header list

**Files:**
- Modify: `python/dkim2sign.py:104-108`
- Test: `python/tests/test_exclusions.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `_should_exclude_header(name: bytes) -> bool` — unchanged signature, new behaviour.

- [ ] **Step 1: Write the failing tests**

Append to `python/tests/test_exclusions.py`:

```python
import pytest


# spec-05 §4: names added by the HDRMAINT survey
@pytest.mark.parametrize("name", [
    b"apparently-to", b"auto-submitted", b"dl-expansion-history",
    b"original-recipient", b"sio-label-history", b"vbr-info",
    b"x400-received", b"x400-trace",
])
def test_spec05_names_excluded(name):
    assert _should_exclude_header(name)


# spec-05 §4: any Received-* field is a trace field
def test_received_prefix_excluded():
    assert _should_exclude_header(b"received-spf")
    assert _should_exclude_header(b"received-anything")


# spec-05 §4: the ARC- prefix narrowed to exactly three names
def test_arc_narrowed_to_three_names():
    assert _should_exclude_header(b"arc-seal")
    assert _should_exclude_header(b"arc-message-signature")
    assert _should_exclude_header(b"arc-authentication-results")
    assert not _should_exclude_header(b"arc-something-else")


def test_x400_not_matched_by_x_prefix():
    # "x400-trace" must be excluded by its own entry, not by the "x-" prefix
    assert not b"x400-trace".startswith(b"x-")
    assert _should_exclude_header(b"x400-trace")
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd python && python3 -m pytest tests/test_exclusions.py -v`
Expected: FAIL — the `spec05_names`, `received_prefix` cases fail (not yet excluded) and `arc_narrowed` fails on `arc-something-else` (still excluded by the old prefix).

- [ ] **Step 3: Replace the lists**

In `python/dkim2sign.py`, replace lines 104–108:

```python
# Headers to exclude from the header hash (spec-05 §4, §4.1)
_EXCLUDED_PREFIXES = (b"x-", b"received-")
_EXCLUDED_NAMES = {
    b"apparently-to", b"arc-authentication-results",
    b"arc-message-signature", b"arc-seal", b"authentication-results",
    b"auto-submitted", b"delivered-to", b"dkim-signature",
    b"dkim2-signature", b"dl-expansion-history", b"message-instance",
    b"original-recipient", b"received", b"return-path",
    b"sio-label-history", b"vbr-info", b"x400-received", b"x400-trace",
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd python && python3 -m pytest tests/ -v`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add python/dkim2sign.py python/tests/test_exclusions.py
git commit -m "python: spec-05 §4 unsigned header list

Adds the eight HDRMAINT-survey names and the Received-* prefix rule;
narrows the ARC- prefix to the three RFC 8617 field names."
```

### Task 2: Go — §4 unsigned header list

**Files:**
- Modify: `go/dkim2/canon.go:51-57`
- Test: `go/dkim2/canon_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `shouldExcludeHeader(name string) bool` — unchanged signature.

- [ ] **Step 1: Write the failing tests**

Append to `go/dkim2/canon_test.go`:

```go
func TestSpec05ExcludedNames(t *testing.T) {
	for _, n := range []string{
		"apparently-to", "auto-submitted", "dl-expansion-history",
		"original-recipient", "sio-label-history", "vbr-info",
		"x400-received", "x400-trace",
	} {
		if !shouldExcludeHeader(n) {
			t.Errorf("%s must be excluded (spec-05 §4)", n)
		}
	}
}

func TestSpec05ReceivedPrefix(t *testing.T) {
	if !shouldExcludeHeader("Received-SPF") {
		t.Error("Received-SPF must be excluded (spec-05 §4)")
	}
	if !shouldExcludeHeader("received-anything") {
		t.Error("any Received-* must be excluded (spec-05 §4)")
	}
}

func TestSpec05ARCNarrowed(t *testing.T) {
	for _, n := range []string{"ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"} {
		if !shouldExcludeHeader(n) {
			t.Errorf("%s must be excluded (spec-05 §4)", n)
		}
	}
	if shouldExcludeHeader("ARC-Something-Else") {
		t.Error("the ARC- prefix match was removed in spec-05 §4; only the three RFC 8617 names are excluded")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd go && go test ./dkim2/ -run 'TestSpec05' -v`
Expected: FAIL on the new names, the `Received-` prefix, and `ARC-Something-Else`.

- [ ] **Step 3: Replace the lists**

In `go/dkim2/canon.go`, replace lines 51–57:

```go
// Unsigned header fields per spec-05 §4, §4.1.
var excludedHeaderNames = map[string]bool{
	"apparently-to": true, "arc-authentication-results": true,
	"arc-message-signature": true, "arc-seal": true,
	"authentication-results": true, "auto-submitted": true,
	"delivered-to": true, "dkim-signature": true,
	"dkim2-signature": true, "dl-expansion-history": true,
	"message-instance": true, "original-recipient": true,
	"received": true, "return-path": true, "sio-label-history": true,
	"vbr-info": true, "x400-received": true, "x400-trace": true,
}

// spec-05 §4 narrowed the ARC- prefix to three exact names (above) and added
// a Received-* prefix rule so future trace fields of that form need no change.
var excludedHeaderPrefixes = []string{"x-", "received-"}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd go && go test ./dkim2/ -count=1`
Expected: PASS (ok).

- [ ] **Step 5: Commit**

```bash
git add go/dkim2/canon.go go/dkim2/canon_test.go
git commit -m "go: spec-05 §4 unsigned header list"
```

### Task 3: Perl — §4 unsigned header list

Sympa consumes `Mail::DKIM2::Common::should_skip` and inherits this change with no edit of its own.

**Files:**
- Modify: `perl/lib/Mail/DKIM2/Common.pm:44-58`
- Test: `perl/t/common.t`

**Interfaces:**
- Consumes: nothing.
- Produces: `Mail::DKIM2::Common::should_skip($name) -> 0|1` — unchanged signature.

- [ ] **Step 1: Write the failing tests**

Append to `perl/t/common.t` (before any `done_testing`; if `done_testing()` is the last line, insert above it):

```perl
# spec-05 §4: names added by the HDRMAINT survey
for my $h (qw(Apparently-To Auto-Submitted DL-Expansion-History
              Original-Recipient SIO-Label-History VBR-Info
              X400-Received X400-Trace)) {
    ok(Mail::DKIM2::Common::should_skip($h), "spec-05 §4: $h is unsigned");
}

# spec-05 §4: any Received-* field is a trace field
ok(Mail::DKIM2::Common::should_skip('Received-SPF'), 'spec-05 §4: Received-SPF is unsigned');
ok(Mail::DKIM2::Common::should_skip('Received-Anything'), 'spec-05 §4: Received-* is unsigned');

# spec-05 §4: the ARC- prefix narrowed to exactly three names
ok(Mail::DKIM2::Common::should_skip('ARC-Seal'), 'spec-05 §4: ARC-Seal is unsigned');
ok(Mail::DKIM2::Common::should_skip('ARC-Message-Signature'), 'spec-05 §4: ARC-Message-Signature is unsigned');
ok(Mail::DKIM2::Common::should_skip('ARC-Authentication-Results'), 'spec-05 §4: ARC-Authentication-Results is unsigned');
ok(!Mail::DKIM2::Common::should_skip('ARC-Something-Else'), 'spec-05 §4: the ARC- prefix match is gone');
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd perl && prove -l t/common.t`
Expected: FAIL on the eight new names, both `Received-*` cases, and `ARC-Something-Else`.

- [ ] **Step 3: Replace `should_skip`**

In `perl/lib/Mail/DKIM2/Common.pm`, replace the comment and body of `should_skip` (lines 44–58):

```perl
# Headers excluded from hashing per draft-ietf-dkim-dkim2-spec-05 Section 4.
# spec-05 narrowed the old /^arc-/ prefix to the three RFC 8617 field names and
# added a /^received-/ prefix rule so future trace fields of that form need no
# change here.
my %SKIP_EXACT = map { $_ => 1 } qw(
    apparently-to arc-authentication-results arc-message-signature arc-seal
    authentication-results auto-submitted delivered-to dkim-signature
    dkim2-signature dl-expansion-history message-instance original-recipient
    received return-path sio-label-history vbr-info x400-received x400-trace
);

sub should_skip {
    my $hname = lc(shift);
    return 1 if $SKIP_EXACT{$hname};
    return 1 if $hname =~ m/^x-/;
    return 1 if $hname =~ m/^received-/;
    return 0;
}
```

- [ ] **Step 4: Run the full Perl suite**

Run: `cd perl && prove -l t/`
Expected: `t/common.t` PASSES. **`t/full-chain.t`, `t/interop.t`, `t/verifier_flags.t`, `t/validate-cli.t`, `t/fraud-detection.t` and `t/milter.t` are expected to FAIL** — their fixtures carry `Received-SPF`, whose hash contribution just changed. Task 7 repairs them. Record which tests fail so Task 7 can confirm it fixed exactly those.

- [ ] **Step 5: Commit**

```bash
git add perl/lib/Mail/DKIM2/Common.pm perl/t/common.t
git commit -m "perl: spec-05 §4 unsigned header list

Chain fixtures carry Received-SPF and now hash differently; regenerated
in the following commit."
```

### Task 4: C — §4 unsigned header list

**Files:**
- Modify: `c/dkim2_hash.c:124-140`
- Test: `c/tests/test_hash.c`

**Interfaces:**
- Consumes: nothing.
- Produces: `static int hdr_ignore(const char *lname, size_t nlen)` — unchanged signature, file-local.

- [ ] **Step 1: Write the failing test**

Insert into `c/tests/test_hash.c` before the final `printf`/`return 0` (the baseline `hb` from the existing test is still in scope):

```c
    /* spec-05 §4: HDRMAINT-survey names are unsigned */
    const char *hdrs_05[] = {
        "From: sender@example.com\r\n",
        "Subject: Test\r\n",
        "Apparently-To: a@example.com\r\n",
        "Auto-Submitted: auto-replied\r\n",
        "DL-Expansion-History: x\r\n",
        "Original-Recipient: rfc822;a@example.com\r\n",
        "SIO-Label-History: x\r\n",
        "VBR-Info: md=example.com\r\n",
        "X400-Received: x\r\n",
        "X400-Trace: x\r\n",
        "Received-SPF: pass\r\n",
        "Received-Anything: x\r\n",
    };
    char h05[64];
    assert(dkim2_header_hash(hdrs_05, 12, h05, sizeof h05) == 0);
    assert(strcmp(h05, hb) == 0);

    /* spec-05 §4: the ARC- prefix narrowed to three exact names */
    const char *hdrs_arc[] = {
        "From: sender@example.com\r\n",
        "Subject: Test\r\n",
        "ARC-Seal: i=1\r\n",
        "ARC-Message-Signature: i=1\r\n",
        "ARC-Authentication-Results: i=1\r\n",
    };
    char harc[64];
    assert(dkim2_header_hash(hdrs_arc, 5, harc, sizeof harc) == 0);
    assert(strcmp(harc, hb) == 0);

    /* ...but a non-RFC8617 ARC- field is now SIGNED, so the hash must differ */
    const char *hdrs_arcx[] = {
        "From: sender@example.com\r\n",
        "Subject: Test\r\n",
        "ARC-Something-Else: x\r\n",
    };
    char harcx[64];
    assert(dkim2_header_hash(hdrs_arcx, 3, harcx, sizeof harcx) == 0);
    assert(strcmp(harcx, hb) != 0);
```

- [ ] **Step 2: Run to verify it fails**

Run: `make -C c tests/test_hash && ./c/tests/test_hash`
Expected: FAIL — assertion failure on `strcmp(h05, hb) == 0`.

- [ ] **Step 3: Replace `hdr_ignore`**

In `c/dkim2_hash.c`, replace `hdr_ignore` (lines 124–140):

```c
/* Returns 1 if this lowercase header name is unsigned per spec-05 §4.
   spec-05 narrowed the old "arc-" prefix to the three RFC 8617 names and
   added a "received-" prefix rule. Note x400-received / x400-trace match
   neither the "x-" nor the "received-" prefix and need their own entries. */
static int hdr_ignore(const char *lname, size_t nlen) {
    static const struct { const char *s; size_t l; } skip[] = {
        {"apparently-to",              13},
        {"arc-authentication-results", 26},
        {"arc-message-signature",      21},
        {"arc-seal",                    8},
        {"authentication-results",     22},
        {"auto-submitted",             14},
        {"delivered-to",               12},
        {"dkim-signature",             14},
        {"dkim2-signature",            15},
        {"dl-expansion-history",       20},
        {"message-instance",           16},
        {"original-recipient",         18},
        {"received",                    8},
        {"return-path",                11},
        {"sio-label-history",          17},
        {"vbr-info",                    8},
        {"x400-received",              13},
        {"x400-trace",                 10},
    };
    for (size_t i = 0; i < sizeof skip / sizeof skip[0]; i++)
        if (nlen == skip[i].l && memcmp(lname, skip[i].s, nlen) == 0) return 1;
    if (nlen >= 2 && memcmp(lname, "x-", 2) == 0) return 1;
    if (nlen >= 9 && memcmp(lname, "received-", 9) == 0) return 1;
    return 0;
}
```

- [ ] **Step 4: Run the C suite**

Run: `make -C c check`
Expected: PASS, all test binaries.

- [ ] **Step 5: Commit**

```bash
git add c/dkim2_hash.c c/tests/test_hash.c
git commit -m "c: spec-05 §4 unsigned header list"
```

### Task 5: Browser JS — §4 unsigned header list

**Files:**
- Modify: `deploy/www/verify/canon.js:1-14`
- Test: `deploy/www/verify/tests/canon.test.mjs` (exists — append to it)

**Interfaces:**
- Consumes: nothing.
- Produces: `isUnsignedHeader(name: string) -> boolean` — unchanged signature.

- [ ] **Step 1: Write the failing test**

Append to the existing `deploy/www/verify/tests/canon.test.mjs` (it already imports
`isUnsignedHeader` from `../canon.js`; add the import only if missing):

```javascript
test('spec-05 §4: HDRMAINT-survey names are unsigned', () => {
  for (const n of ['Apparently-To', 'Auto-Submitted', 'DL-Expansion-History',
                   'Original-Recipient', 'SIO-Label-History', 'VBR-Info',
                   'X400-Received', 'X400-Trace']) {
    assert.ok(isUnsignedHeader(n), `${n} must be unsigned`);
  }
});

test('spec-05 §4: any Received-* is unsigned', () => {
  assert.ok(isUnsignedHeader('Received-SPF'));
  assert.ok(isUnsignedHeader('Received-Anything'));
});

test('spec-05 §4: the ARC- prefix narrowed to three names', () => {
  assert.ok(isUnsignedHeader('ARC-Seal'));
  assert.ok(isUnsignedHeader('ARC-Message-Signature'));
  assert.ok(isUnsignedHeader('ARC-Authentication-Results'));
  assert.ok(!isUnsignedHeader('ARC-Something-Else'));
});

test('MI and DKIM2-Signature are in the list for parity with the other five impls', () => {
  assert.ok(isUnsignedHeader('Message-Instance'));
  assert.ok(isUnsignedHeader('DKIM2-Signature'));
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd deploy/www/verify && node --test tests/canon.test.mjs`
Expected: FAIL on the survey names, `Received-*`, `ARC-Something-Else`, and the parity check.

- [ ] **Step 3: Replace the list**

In `deploy/www/verify/canon.js`, replace lines 1–14:

```javascript
// Canonicalization per draft-ietf-dkim-dkim2-spec-05 §6.1, §6.2, §9.6.

// Unsigned header fields per §4, §4.1. message-instance and dkim2-signature
// are also filtered upstream in signedFields(); they are listed here so this
// set matches the other five implementations.
const UNSIGNED_EXACT = new Set([
  'apparently-to', 'arc-authentication-results', 'arc-message-signature',
  'arc-seal', 'authentication-results', 'auto-submitted', 'delivered-to',
  'dkim-signature', 'dkim2-signature', 'dl-expansion-history',
  'message-instance', 'original-recipient', 'received', 'return-path',
  'sio-label-history', 'vbr-info', 'x400-received', 'x400-trace',
]);

export function isUnsignedHeader(name) {
  const n = name.toLowerCase();
  if (UNSIGNED_EXACT.has(n)) return true;
  // §4 narrowed the ARC- prefix to the three exact names above and added the
  // Received-* rule for future trace fields of that form.
  if (n.startsWith('x-')) return true;
  if (n.startsWith('received-')) return true;
  return false;
}
```

- [ ] **Step 4: Run the JS suite**

Run: `cd deploy/www/verify && node --test tests/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/canon.js deploy/www/verify/tests/canon.test.mjs
git commit -m "js: spec-05 §4 unsigned header list"
```

### Task 6: Mailman — §4 unsigned header list

Work on the `dkim2` branch of `/Users/brong/src/mailman`.

**Files:**
- Modify: `mailman/src/mailman/handlers/message_instance.py:125-132`, and the docstring at `:214`
- Test: `mailman/src/mailman/handlers/tests/test_message_instance.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `_should_exclude_header(name: str) -> bool` — unchanged signature.

- [ ] **Step 1: Confirm the branch**

Run: `cd ../mailman && git branch --show-current`
Expected: `dkim2`. If not, `git checkout dkim2` before proceeding.

- [ ] **Step 2: Write the failing test**

Append to the exclusion test class in `mailman/src/mailman/handlers/tests/test_message_instance.py`:

```python
    def test_spec05_excluded_names(self):
        # spec-05 §4: names added by the HDRMAINT survey
        for name in ('Apparently-To', 'Auto-Submitted', 'DL-Expansion-History',
                     'Original-Recipient', 'SIO-Label-History', 'VBR-Info',
                     'X400-Received', 'X400-Trace'):
            self.assertTrue(_should_exclude_header(name), name)

    def test_spec05_received_prefix(self):
        # spec-05 §4: any Received-* field is a trace field
        self.assertTrue(_should_exclude_header('Received-SPF'))
        self.assertTrue(_should_exclude_header('Received-Anything'))

    def test_spec05_arc_narrowed(self):
        # spec-05 §4: the ARC- prefix narrowed to the three RFC 8617 names
        self.assertTrue(_should_exclude_header('ARC-Seal'))
        self.assertTrue(_should_exclude_header('ARC-Message-Signature'))
        self.assertTrue(_should_exclude_header('ARC-Authentication-Results'))
        self.assertFalse(_should_exclude_header('ARC-Something-Else'))
```

Ensure `_should_exclude_header` is imported at the top of that file; add it to the existing `from mailman.handlers.message_instance import (...)` list if missing.

- [ ] **Step 3: Run to verify it fails**

Run: `cd ../mailman && python -m pytest src/mailman/handlers/tests/test_message_instance.py -v -k spec05`
Expected: FAIL on all three.

- [ ] **Step 4: Replace the lists**

In `mailman/src/mailman/handlers/message_instance.py`, replace lines 125–132:

```python
# Unsigned header fields per DKIM2 spec-05 §4, §4.1. spec-05 narrowed the old
# 'arc-' prefix to the three RFC 8617 field names and added a 'received-'
# prefix rule. x400-received / x400-trace match neither prefix.
_EXCLUDED_NAMES = frozenset({
    'apparently-to', 'arc-authentication-results', 'arc-message-signature',
    'arc-seal', 'authentication-results', 'auto-submitted', 'delivered-to',
    'dkim-signature', 'dkim2-signature', 'dl-expansion-history',
    'message-instance', 'original-recipient', 'received', 'return-path',
    'sio-label-history', 'vbr-info', 'x400-received', 'x400-trace',
})

_EXCLUDED_PREFIXES = ('x-', 'received-')
```

Then update the docstring at what is now roughly `:214` — replace the parenthetical `(Message-Instance, DKIM*-Signature, ARC-*, X-*, Authentication-Results)` with `(see _EXCLUDED_NAMES / _EXCLUDED_PREFIXES — spec-05 §4)`.

- [ ] **Step 5: Run the handler tests**

Run: `cd ../mailman && python -m pytest src/mailman/handlers/tests/test_message_instance.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd ../mailman
git add src/mailman/handlers/message_instance.py src/mailman/handlers/tests/test_message_instance.py
git commit -m "dkim2: spec-05 §4 unsigned header list"
```

### Task 7: Regenerate the Perl chain fixtures

`Received-SPF` moved from signed to unsigned in Task 3, so every hash in the committed chain fixtures is now wrong. `t/full-chain.t` *writes* these fixtures as a side effect of running, so regeneration is running it — but the regenerated output must be cross-verified by a second implementation, never trusted because the tool that produced it agrees with itself.

**Files:**
- Modify (regenerated): `perl/tests/expected/chain-hop1-originator.eml` … `chain-hop6-unchanged-re-sign.eml`
- Read-only inputs: `perl/tests/emails/*.eml`

**Interfaces:**
- Consumes: `Mail::DKIM2::Common::should_skip` from Task 3.
- Produces: regenerated golden fixtures consumed by Tasks 8–17 and the Turscar runners.

- [ ] **Step 1: Sweep every tree for other affected fixtures**

Run:
```bash
cd /Users/brong/src && grep -rlniE '^(Received-[A-Za-z0-9-]+|Apparently-To|Auto-Submitted|DL-Expansion-History|Original-Recipient|SIO-Label-History|VBR-Info|X400-Received|X400-Trace):' \
  interop/perl/tests interop/python/tests interop/go interop/c/tests \
  interop/deploy/www/verify/tests interop/dkim2tests interop/arobins \
  mailman/src sympa/src 2>/dev/null
```
Expected: the four known Perl files plus `interop/rnc1/mail-20251102-193051.txt` (third-party sample, not ours) and two Mailman bounce tests (which do not compute DKIM2 hashes). **If any file outside this set appears, stop and report** — the blast radius is wider than the design assumed.

- [ ] **Step 2: Confirm the fixtures are currently failing**

Run: `cd interop/perl && prove -l t/full-chain.t`
Expected: FAIL, with hash mismatches. This confirms Task 3 landed and the fixtures are stale.

- [ ] **Step 3: Regenerate**

Run: `cd interop/perl && prove -l t/full-chain.t; git -C /Users/brong/src/interop status --short perl/tests/expected/`
Expected: the run rewrites `perl/tests/expected/chain-hop*.eml`; `git status` shows them modified. The test may still report failures on its first pass — it verifies as it builds. Run it a second time and confirm it now passes end to end.

- [ ] **Step 4: Confirm the diff is only hashes and signatures**

Run: `cd /Users/brong/src/interop && git diff --stat perl/tests/expected/ && git diff perl/tests/expected/ | grep -E '^[-+]' | grep -viE '^[-+]{3}|^[-+](Message-Instance|DKIM2-Signature|\s)' | head`
Expected: the second command prints **nothing**. Only `Message-Instance`, `DKIM2-Signature` and their folded continuation lines may differ. Any other changed line means the regeneration altered message content — stop and investigate.

- [ ] **Step 5: Cross-verify with a second implementation**

The Python verifier has no §4 change pending (Task 1 landed) and is independent of Perl:

```bash
cd /Users/brong/src/interop
python3 python/dkim2verify.py --dns-json dns.json --ignore-timestamps \
    perl/tests/expected/chain-hop5-final-delivery.eml
```
Expected: a pass result. Repeat for `chain-hop6-unchanged-re-sign.eml`. **If Python disagrees with the freshly-regenerated Perl fixture, the fixture is wrong** — do not proceed.

- [ ] **Step 6: Run the full Perl suite**

Run: `cd perl && prove -l t/`
Expected: PASS — specifically the six tests recorded as failing in Task 3 Step 4 now pass, and nothing else regressed.

- [ ] **Step 7: Commit**

```bash
cd /Users/brong/src/interop
git add perl/tests/expected/
git commit -m "perl: regenerate chain fixtures for the spec-05 §4 list

Received-SPF became unsigned under the §4 Received-* rule, changing every
header hash in the chain. Regenerated via t/full-chain.t and cross-verified
with the Python verifier."
```

- [ ] **Step 8: Run the conformance vectors across all five verifiers**

Run: `./util/turscar-all.sh`
Expected: all five agree. If the Turscar vectors themselves encode -04 §4 behaviour, note which vectors disagree and report — upstream may need a -05 refresh. Do not edit the submodule.

---

## Phase 2 — Hash agility (§3, §3.1, §7.3)

Each task adds a supported-algorithm registry, list-based `h=` parsing, sha512 verification, and (for signers) a `--hash` flag defaulting to `sha256`.

### Task 8: Python — hash agility

**Files:**
- Modify: `python/dkim2sign.py:192-234` (digest helpers, MI construction), `:542-560` (CLI)
- Modify: `python/dkim2verify.py:317-346`
- Test: `python/tests/test_hash_agility.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `dkim2sign.HASH_ALGS: dict[str, Callable[[bytes], bytes]]` — `{"sha256": ..., "sha512": ...}`
  - `dkim2sign.compute_body_hash(body: bytes, alg: str = "sha256") -> bytes`
  - `dkim2sign.compute_header_hash(headers: list[bytes], alg: str = "sha256") -> bytes`
  - `dkim2verify.parse_hash_sets(h_tag: str) -> list[tuple[str, str, str]]` — list of `(alg_lowercase, header_hash_b64, body_hash_b64)`

- [ ] **Step 1: Write the failing tests**

Create `python/tests/test_hash_agility.py`:

```python
import base64
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2sign import HASH_ALGS, compute_body_hash  # noqa: E402
from dkim2verify import parse_hash_sets, verify_message_instance  # noqa: E402


def test_registry_has_both_algorithms():
    # spec-05 §3: Verifiers MUST implement all four algorithms
    assert set(HASH_ALGS) == {"sha256", "sha512"}


def test_parse_multiple_hash_sets():
    sets = parse_hash_sets("sha256:AAA:BBB,sha512:CCC:DDD")
    assert sets == [("sha256", "AAA", "BBB"), ("sha512", "CCC", "DDD")]


def test_parse_hash_name_is_case_insensitive():
    # RFC 5234 quoted strings are case-insensitive
    assert parse_hash_sets("SHA256:AAA:BBB")[0][0] == "sha256"


def test_body_hash_sha512_differs_and_is_64_bytes():
    b = b"Hello\r\n"
    assert len(compute_body_hash(b, "sha512")) == 64
    assert len(compute_body_hash(b, "sha256")) == 32
    assert compute_body_hash(b, "sha512") != compute_body_hash(b, "sha256")


def test_sha512_body_hash_matches_hashlib():
    # canonical body for "Hello\r\n" is unchanged (one trailing CRLF)
    assert compute_body_hash(b"Hello\r\n", "sha512") == hashlib.sha512(b"Hello\r\n").digest()


def _mi(h_tag):
    return f"Message-Instance: m=1; h={h_tag};"


def test_unknown_algorithm_alone_fails_closed(monkeypatch):
    # §3.4 says ignore unimplemented algorithms, but an MI with no implemented
    # hash-set cannot be verified and MUST NOT be left at pass.
    errs = verify_message_instance(_mi("x-whirlpool:AAA:BBB"), [b"From: a@b\r\n"], b"x\r\n")
    assert any("no supported hash algorithm" in e for e in errs)


def test_duplicate_algorithm_is_permerror():
    errs = verify_message_instance(_mi("sha256:AAA:BBB,sha256:CCC:DDD"),
                                   [b"From: a@b\r\n"], b"x\r\n")
    assert any("has a duplicate hash algorithm" in e for e in errs)


def test_duplicate_algorithm_detected_case_insensitively():
    errs = verify_message_instance(_mi("sha256:AAA:BBB,SHA256:CCC:DDD"),
                                   [b"From: a@b\r\n"], b"x\r\n")
    assert any("has a duplicate hash algorithm" in e for e in errs)
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd python && python3 -m pytest tests/test_hash_agility.py -v`
Expected: FAIL — `ImportError` on `HASH_ALGS` / `parse_hash_sets`.

- [ ] **Step 3: Add the registry and per-algorithm digests to `dkim2sign.py`**

Replace the two digest helpers around `dkim2sign.py:192` and `:216`:

```python
# spec-05 §3.1: two hashing algorithms are defined. Verifiers MUST implement
# both; Signers MAY implement either or both (we default to sha256).
HASH_ALGS = {
    "sha256": lambda data: hashlib.sha256(data).digest(),
    "sha512": lambda data: hashlib.sha512(data).digest(),
}


def _digest(data: bytes, alg: str = "sha256") -> bytes:
    try:
        return HASH_ALGS[alg](data)
    except KeyError:
        raise ValueError(f"unsupported hash algorithm: {alg}")
```

Give `compute_header_hash` and `compute_body_hash` an `alg: str = "sha256"` keyword and route their final digest call through `_digest(data, alg)`. Leave every existing call site alone — the default keeps them on sha256.

- [ ] **Step 4: Build multi-hash-set `h=` in the MI**

Replace `dkim2sign.py:232`:

```python
    # spec-05 §7.3: one hash-set per algorithm, comma separated. An algorithm
    # MUST NOT appear more than once, so `algs` must be de-duplicated by the
    # caller (the CLI does this).
    sets = ",".join(
        f"{alg}:{b64(compute_header_hash(headers, alg))}:{b64(compute_body_hash(body, alg))}"
        for alg in algs
    )
    value = f"m={version}; h={sets}"
```

Thread an `algs: list[str] = ["sha256"]` parameter through the MI-building function to this point.

- [ ] **Step 5: Add the `--hash` CLI flag**

After `dkim2sign.py:560`:

```python
    parser.add_argument("--hash", dest="hash_algs", default="sha256",
                        choices=["sha256", "sha512", "both"],
                        help="hash algorithm(s) for the Message-Instance h= tag "
                             "(spec-05 §3.1; default sha256)")
```

and where the MI is built, convert:

```python
    algs = ["sha256", "sha512"] if args.hash_algs == "both" else [args.hash_algs]
```

- [ ] **Step 6: Replace `h=` parsing in `dkim2verify.py`**

Replace `dkim2verify.py:317-346`:

```python
def parse_hash_sets(h_tag: str) -> list[tuple[str, str, str]]:
    """Parse a spec-05 §7.3 h= value into (alg, header_hash, body_hash) triples.

    Hash names are lowercased: RFC 5234 makes ABNF quoted strings
    case-insensitive, so "SHA256" is a syntactically valid hash-name.
    """
    sets = []
    for item in h_tag.split(","):
        parts = item.strip().split(":")
        if len(parts) != 3:
            continue
        sets.append((parts[0].strip().lower(), parts[1].strip(), parts[2].strip()))
    return sets
```

and rewrite the body of `verify_message_instance` between the `h_tag` lookup and the return:

```python
    sets = parse_hash_sets(h_tag)
    if not sets:
        return [f"Message-Instance: invalid h= format (got {h_tag!r})"]

    # spec-05 §7.3: an algorithm MUST NOT be present more than once.
    seen = set()
    for alg, _, _ in sets:
        if alg in seen:
            return [f"PERMERROR Message-Instance m={m_val} has a duplicate hash algorithm"]
        seen.add(alg)

    # §3.4: ignore hash-sets naming algorithms we do not implement, but an MI
    # with no implemented hash-set cannot be verified and must fail closed.
    usable = [s for s in sets if s[0] in HASH_ALGS]
    if not usable:
        return [f"Message-Instance m={m_val} no supported hash algorithm"]

    # All implemented hash-sets must pass (mirrors §11.6 for signatures).
    for alg, h_val, b_val in usable:
        expected = compute_header_hash(headers, alg)
        if expected != base64.b64decode(h_val):
            errors.append(
                f"Message-Instance: {alg} header hash mismatch\n"
                f"  expected: {b64(expected)}\n"
                f"  got:      {h_val}"
            )
        expected = compute_body_hash(body, alg)
        if expected != base64.b64decode(b_val):
            errors.append(
                f"Message-Instance: {alg} body hash mismatch\n"
                f"  expected: {b64(expected)}\n"
                f"  got:      {b_val}"
            )

    return errors
```

`m_val` comes from the MI's `m=` tag; extract it with the existing `_extract_tag(value, "m")` at the top of the function. Import `HASH_ALGS`, `compute_header_hash` and `compute_body_hash` from `dkim2sign` if not already imported.

- [ ] **Step 7: Run the Python suite**

Run: `cd python && python3 -m pytest tests/ -v`
Expected: PASS, all tests including the new file.

- [ ] **Step 8: Round-trip sha512 through sign and verify**

```bash
cd /Users/brong/src/interop
python3 python/dkim2sign.py perl/tests/emails/brong-orig.eml \
    -s sel1 -d test1.dkim2.com -k keys/sel1._domainkey.test1.dkim2.com.pem \
    --mailfrom '<brong@test1.dkim2.com>' --rcptto '<u@test2.dkim2.com>' \
    --hash both > /tmp/both.eml
grep -o 'h=sha256:[^;]*' /tmp/both.eml | head -1
python3 python/dkim2verify.py /tmp/both.eml --dns-json dns.json --ignore-timestamps
```
Expected: the `h=` value contains both `sha256:` and `sha512:`, and the verify passes.

- [ ] **Step 9: Commit**

```bash
git add python/dkim2sign.py python/dkim2verify.py python/tests/test_hash_agility.py
git commit -m "python: spec-05 hash agility (sha512, multi-hash-set h=)

Verifiers now parse h= as a list and check every implemented algorithm;
signers gain --hash sha256|sha512|both, defaulting to sha256."
```

### Task 9: Go — hash agility

**Files:**
- Modify: `go/dkim2/canon.go:1-20` (registry + digest selection), `go/dkim2/mi.go:38-53`
- Modify: `go/cmd/dkim2sign/main.go`
- Test: `go/dkim2/hash_agility_test.go` (create)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `dkim2.HashAlg(name string) (func() hash.Hash, bool)` — case-insensitive lookup
  - `dkim2.parseHashSets(h string) []HashSet` where `type HashSet struct { Alg, HeaderHash, BodyHash string }`
  - `MessageInstance.Hashes []HashSet` replacing the `HeaderHash`/`BodyHash` byte slices

- [ ] **Step 1: Write the failing test**

Create `go/dkim2/hash_agility_test.go`:

```go
package dkim2

import "testing"

func TestHashAlgRegistry(t *testing.T) {
	for _, n := range []string{"sha256", "sha512", "SHA256", "SHA512"} {
		if _, ok := HashAlg(n); !ok {
			t.Errorf("HashAlg(%q) must be supported (spec-05 §3)", n)
		}
	}
	if _, ok := HashAlg("x-whirlpool"); ok {
		t.Error("unknown algorithms must not resolve")
	}
}

func TestParseHashSets(t *testing.T) {
	got := parseHashSets("sha256:AAA:BBB,sha512:CCC:DDD")
	if len(got) != 2 {
		t.Fatalf("got %d hash-sets, want 2", len(got))
	}
	if got[0].Alg != "sha256" || got[0].HeaderHash != "AAA" || got[0].BodyHash != "BBB" {
		t.Errorf("first hash-set wrong: %+v", got[0])
	}
	if got[1].Alg != "sha512" {
		t.Errorf("second alg = %q, want sha512", got[1].Alg)
	}
}

func TestParseHashSetsLowercasesAlg(t *testing.T) {
	got := parseHashSets("SHA512:AAA:BBB")
	if got[0].Alg != "sha512" {
		t.Errorf("alg = %q, want sha512 (RFC 5234 quoted strings are case-insensitive)", got[0].Alg)
	}
}

func TestParseMIWithBothAlgorithms(t *testing.T) {
	raw := "Message-Instance: m=1; h=sha256:AAA:BBB,sha512:CCC:DDD;"
	mi, err := parseMI(raw)
	if err != nil {
		t.Fatalf("parseMI: %v", err)
	}
	if len(mi.Hashes) != 2 {
		t.Fatalf("got %d hash-sets, want 2", len(mi.Hashes))
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd go && go test ./dkim2/ -run 'HashAlg|ParseHashSets|ParseMIWithBoth' -v`
Expected: FAIL — undefined `HashAlg`, `parseHashSets`, `mi.Hashes`.

- [ ] **Step 3: Add the registry to `canon.go`**

At the top of `go/dkim2/canon.go`, after the imports (add `"crypto/sha512"` and `"hash"`):

```go
// spec-05 §3.1: two hashing algorithms are defined. Verifiers MUST implement
// both; Signers MAY implement either or both (we default to sha256).
var hashAlgs = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha512": sha512.New,
}

// HashAlg resolves a spec-05 §7.3 hash-name to its constructor. Matching is
// case-insensitive: RFC 5234 makes ABNF quoted strings case-insensitive.
func HashAlg(name string) (func() hash.Hash, bool) {
	f, ok := hashAlgs[strings.ToLower(name)]
	return f, ok
}
```

Give the two hashing functions in `canon.go` (at `:16` and `:138`) an `alg string` parameter, resolving via `HashAlg(alg)` instead of calling `sha256.New()` directly, and returning an error for an unknown name.

- [ ] **Step 4: Replace `h=` parsing in `mi.go`**

Add above `parseMI`:

```go
// HashSet is one spec-05 §7.3 hash-set: alg:header-hash:body-hash.
type HashSet struct {
	Alg        string // lowercased
	HeaderHash string // base64, FWS already stripped
	BodyHash   string // base64, FWS already stripped
}

func parseHashSets(h string) []HashSet {
	var out []HashSet
	for _, item := range strings.Split(h, ",") {
		parts := strings.Split(strings.TrimSpace(item), ":")
		if len(parts) != 3 {
			continue
		}
		out = append(out, HashSet{
			Alg:        strings.ToLower(strings.TrimSpace(parts[0])),
			HeaderHash: strings.TrimSpace(parts[1]),
			BodyHash:   strings.TrimSpace(parts[2]),
		})
	}
	return out
}
```

Replace `MessageInstance`'s `HeaderHash []byte` / `BodyHash []byte` fields with `Hashes []HashSet`, and replace `mi.go:38-53` with:

```go
	h := stripB64WSP(tvl.get("h"))
	hashes := parseHashSets(h)
	if len(hashes) == 0 {
		return nil, fmt.Errorf("invalid h= tag: %q", h)
	}
	mi := &MessageInstance{Version: m, Hashes: hashes}
```

Update `MessageInstance.String()` (`mi.go:75`) to emit every hash-set:

```go
	parts := make([]string, len(mi.Hashes))
	for i, hs := range mi.Hashes {
		parts[i] = hs.Alg + ":" + hs.HeaderHash + ":" + hs.BodyHash
	}
	s := fmt.Sprintf("Message-Instance: m=%d; h=%s;", mi.Version, strings.Join(parts, ","))
```

- [ ] **Step 5: Fix every consumer**

Run: `cd go && go build ./... 2>&1 | head -40`
Fix each reported use of the removed `HeaderHash`/`BodyHash` fields to iterate `mi.Hashes`, applying the Global Constraints verification semantics: skip unimplemented algorithms, require all implemented ones to match, fail closed when none is implemented with the message `Message-Instance m=<x> no supported hash algorithm`.

- [ ] **Step 6: Add the `-hash` flag**

In `go/cmd/dkim2sign/main.go`, beside the other flags:

```go
	hashAlgs := flag.String("hash", "sha256",
		"hash algorithm(s) for the Message-Instance h= tag: sha256, sha512 or both (spec-05 §3.1)")
```

and where the MI is built:

```go
	var algs []string
	switch *hashAlgs {
	case "sha256", "sha512":
		algs = []string{*hashAlgs}
	case "both":
		algs = []string{"sha256", "sha512"}
	default:
		fmt.Fprintf(os.Stderr, "invalid -hash %q: want sha256, sha512 or both\n", *hashAlgs)
		os.Exit(2)
	}
```

- [ ] **Step 7: Run the Go suite**

Run: `cd go && go build ./... && go test ./dkim2/ -count=1`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add go/
git commit -m "go: spec-05 hash agility (sha512, multi-hash-set h=)"
```

### Task 10: Perl — hash agility

**Files:**
- Modify: `perl/lib/Mail/DKIM2/MessageInstance.pm:94-190`
- Modify: `perl/lib/Mail/DKIM2/Verifier.pm:24-32`
- Modify: `perl/lib/Mail/DKIM2/Validate.pm:73-74`
- Test: `perl/t/hash-agility.t` (create)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Mail::DKIM2::MessageInstance::hash_algs()` → hashref `{ sha256 => \&sha256, sha512 => \&sha512 }`
  - `Mail::DKIM2::MessageInstance::parse_hash_sets($h_tag)` → arrayref of `[$alg, $hdr_b64, $body_b64]`, `$alg` lowercased
  - `Mail::DKIM2::Verifier::_extract_mi_hash_sets($raw)` → same arrayref, replacing `_extract_mi_hashes`

- [ ] **Step 1: Write the failing test**

Create `perl/t/hash-agility.t`:

```perl
#!/usr/bin/perl -w
use 5.020;
use strict;
use warnings;
use Test::More;
use lib 'lib', 't/lib';
use Mail::DKIM2::MessageInstance;

# spec-05 §3: both hashing algorithms must be implemented
my $algs = Mail::DKIM2::MessageInstance::hash_algs();
is_deeply([sort keys %$algs], ['sha256', 'sha512'], 'spec-05 §3: both hash algorithms present');

# spec-05 §7.3: h= is a comma-separated list of hash-sets
my $sets = Mail::DKIM2::MessageInstance::parse_hash_sets('sha256:AAA:BBB,sha512:CCC:DDD');
is(scalar @$sets, 2, 'two hash-sets parsed');
is_deeply($sets->[0], ['sha256', 'AAA', 'BBB'], 'first hash-set');
is_deeply($sets->[1], ['sha512', 'CCC', 'DDD'], 'second hash-set');

# RFC 5234: ABNF quoted strings are case-insensitive
my $upper = Mail::DKIM2::MessageInstance::parse_hash_sets('SHA512:AAA:BBB');
is($upper->[0][0], 'sha512', 'hash-name matched case-insensitively');

# FWS inside a folded h= must not corrupt the hash-set
my $folded = Mail::DKIM2::MessageInstance::parse_hash_sets("sha256:AA\r\n\tA:BBB");
is($folded->[0][1], 'AAA', 'FWS stripped from a folded header hash');

done_testing();
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd perl && prove -l t/hash-agility.t`
Expected: FAIL — `hash_algs`/`parse_hash_sets` undefined.

- [ ] **Step 3: Add the registry and parser to `MessageInstance.pm`**

Add near the top of `perl/lib/Mail/DKIM2/MessageInstance.pm` (adding `use Crypt::Digest::SHA512 qw(sha512 sha512_b64);` to the imports):

```perl
# spec-05 §3.1: two hashing algorithms are defined. Verifiers MUST implement
# both; Signers MAY implement either or both (we default to sha256).
my %HASH_ALGS = (
    sha256 => \&Crypt::Digest::SHA256::sha256,
    sha512 => \&Crypt::Digest::SHA512::sha512,
);

sub hash_algs { return { %HASH_ALGS } }

# spec-05 §7.3: h= is hash-set *("," hash-set), hash-set = alg ":" hh ":" bh.
# Hash names are lowercased -- RFC 5234 makes ABNF quoted strings
# case-insensitive. All FWS is stripped (§2.12).
sub parse_hash_sets {
    my ($h_tag) = @_;
    my @sets;
    for my $item (split /,/, $h_tag) {
        $item =~ s/[\s\r\n]//g;
        my @parts = split /:/, $item;
        next unless @parts == 3;
        push @sets, [lc $parts[0], $parts[1], $parts[2]];
    }
    return \@sets;
}
```

- [ ] **Step 4: Emit a hash-set list from `as_string`**

Replace `MessageInstance.pm:101-104` so the `h=` tag is built from an ordered `algs` list held on the instance (defaulting to `['sha256']`), joining `"$alg:$hh:$bh"` with commas. Store per-algorithm hashes as `$self->{bits}{hashes}{$alg} = [$hdr_b64, $body_b64]` rather than the flat `h1`/`b1` pair, and keep `h1`/`b1` as read-only aliases for the sha256 entry so existing callers (notably `Validate.pm`) keep working until Step 6.

- [ ] **Step 5: Parse the list in `parse`**

Replace `MessageInstance.pm:182-188`:

```perl
    # spec-05 §7.3: h= is a list of hash-sets
    if (exists $tags{h}) {
        my $sets = parse_hash_sets($tags{h});
        for my $s (@$sets) {
            $self->{bits}{hashes}{$s->[0]} = [$s->[1], $s->[2]];
        }
        # Back-compatible aliases for the sha256 hash-set
        if (my $sha256 = $self->{bits}{hashes}{sha256}) {
            @{$self->{bits}}{qw(h1 b1)} = @$sha256;
        }
    }
```

- [ ] **Step 6: Replace `_extract_mi_hashes` in `Verifier.pm`**

Replace `perl/lib/Mail/DKIM2/Verifier.pm:24-32`:

```perl
# spec-05 §7.3: return every hash-set in an MI as [[alg, hdr_b64, body_b64], ...]
sub _extract_mi_hash_sets {
    my ($raw) = @_;
    $raw =~ s/^[^:]+://;        # strip "Message-Instance:" field name
    $raw =~ s/\r?\n[ \t]/ /g;   # unfold continuation lines
    return [] unless $raw =~ /\bh=([^;]*)/;
    return Mail::DKIM2::MessageInstance::parse_hash_sets($1);
}
```

Update both call sites at `Verifier.pm:182-183` to iterate the returned sets, applying the Global Constraints semantics: skip algorithms absent from `hash_algs()`, require all present ones to match, and fail closed with `Message-Instance m=<x> no supported hash algorithm` when none is implemented.

- [ ] **Step 7: Un-hardcode the validator's displayed algorithm**

In `perl/lib/Mail/DKIM2/Validate.pm:73-74`, replace the literal `'sha256:'` prefixes so the report shows each hash-set's own algorithm name, iterating `$mi->{bits}{hashes}` rather than assuming sha256.

- [ ] **Step 8: Run the Perl suite**

Run: `cd perl && prove -l t/`
Expected: PASS, all tests.

- [ ] **Step 9: Commit**

```bash
git add perl/lib/Mail/DKIM2/ perl/t/hash-agility.t
git commit -m "perl: spec-05 hash agility (sha512, multi-hash-set h=)"
```

### Task 11: C — hash agility

The largest task. C currently loops hash-sets but never reads `alg`, decoding every one into a fixed 32-byte buffer — so a `sha256,sha512` message fails today. The body hash is computed streaming into `ctx->body_digest[32]`, so the hasher must carry one EVP context per algorithm and finalise all of them.

**Files:**
- Modify: `c/dkim2_hash.h` (all four function signatures + `DKIM2_MAX_HASH_LEN`)
- Modify: `c/dkim2_hash.c:8-120` (hasher, `sha256_buf`, body/header hash)
- Modify: `c/dkim2_internal.h:67` (`body_digest`)
- Modify: `c/eml_parse.h:15,21`, `c/eml_parse.c:9,103,109`
- Modify: `c/dkim2_verify.c:299-334`
- Modify: `c/dkim2_sign.c:136,165`
- Test: `c/tests/test_hash.c`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `#define DKIM2_MAX_HASH_LEN 64`
  - `#define DKIM2_N_HASH_ALGS 2`
  - `int dkim2_hash_alg_index(const char *name)` — case-insensitive; `-1` if unimplemented
  - `const char *dkim2_hash_alg_name(int idx)`; `size_t dkim2_hash_alg_len(int idx)`
  - `typedef struct { unsigned char d[DKIM2_N_HASH_ALGS][DKIM2_MAX_HASH_LEN]; } dkim2_digests_t;`
  - `int dkim2_body_hasher_final_all(dkim2_body_hasher_t *bh, dkim2_digests_t *out)`
  - `int dkim2_body_hash_raw_alg(const char *body, size_t len, int alg, unsigned char *digest)`
  - `int dkim2_header_hash_raw_alg(const char **headers, int n, int alg, unsigned char *digest)`

- [ ] **Step 1: Write the failing test**

Append to `c/tests/test_hash.c` before the final return:

```c
    /* spec-05 §3: both hashing algorithms are implemented */
    assert(dkim2_hash_alg_index("sha256") == 0);
    assert(dkim2_hash_alg_index("sha512") == 1);
    assert(dkim2_hash_alg_index("SHA512") == 1);   /* RFC 5234: case-insensitive */
    assert(dkim2_hash_alg_index("x-whirlpool") < 0);
    assert(dkim2_hash_alg_len(0) == 32);
    assert(dkim2_hash_alg_len(1) == 64);
    assert(strcmp(dkim2_hash_alg_name(1), "sha512") == 0);

    /* sha512 body hash is 64 bytes and differs from sha256 */
    unsigned char d256[DKIM2_MAX_HASH_LEN], d512[DKIM2_MAX_HASH_LEN];
    assert(dkim2_body_hash_raw_alg("Hello\r\n", 7, 0, d256) == 0);
    assert(dkim2_body_hash_raw_alg("Hello\r\n", 7, 1, d512) == 0);
    assert(memcmp(d256, d512, 32) != 0);

    /* the streaming hasher finalises every algorithm in one pass */
    dkim2_body_hasher_t *bh = dkim2_body_hasher_new();
    assert(bh != NULL);
    assert(dkim2_body_hasher_update(bh, "Hello\r\n", 7) == 0);
    dkim2_digests_t all;
    assert(dkim2_body_hasher_final_all(bh, &all) == 0);
    dkim2_body_hasher_free(bh);
    assert(memcmp(all.d[0], d256, 32) == 0);
    assert(memcmp(all.d[1], d512, 64) == 0);
```

- [ ] **Step 2: Run to verify it fails**

Run: `make -C c tests/test_hash 2>&1 | head`
Expected: FAIL to compile — undeclared `dkim2_hash_alg_index`, `DKIM2_MAX_HASH_LEN`, etc.

- [ ] **Step 3: Declare the registry in `dkim2_hash.h`**

Replace the top of `c/dkim2_hash.h`:

```c
#pragma once
#include <stddef.h>

#define DKIM2_HASH_LEN     32  /* SHA-256 output bytes (algorithm index 0) */
#define DKIM2_MAX_HASH_LEN 64  /* SHA-512 output bytes — sizes every buffer */
#define DKIM2_N_HASH_ALGS   2

/* spec-05 §3.1: sha256 (index 0) and sha512 (index 1). Verifiers MUST
   implement both. Lookup is case-insensitive per RFC 5234. */
int         dkim2_hash_alg_index(const char *name); /* -1 if unimplemented */
const char *dkim2_hash_alg_name(int idx);
size_t      dkim2_hash_alg_len(int idx);

/* Digests for every implemented algorithm, indexed as above. */
typedef struct {
    unsigned char d[DKIM2_N_HASH_ALGS][DKIM2_MAX_HASH_LEN];
} dkim2_digests_t;
```

Then add `_alg` variants of the body and header hash functions taking an `int alg` and writing into an `unsigned char *digest` of at least `DKIM2_MAX_HASH_LEN`, plus `dkim2_body_hasher_final_all`. Keep the existing sha256-only signatures as thin wrappers so untouched call sites keep compiling.

- [ ] **Step 4: Implement in `dkim2_hash.c`**

Add after the includes (adding `#include <strings.h>` for `strcasecmp`):

```c
static const struct {
    const char *name;
    const EVP_MD *(*md)(void);
    size_t len;
} HASH_ALGS[DKIM2_N_HASH_ALGS] = {
    { "sha256", EVP_sha256, 32 },
    { "sha512", EVP_sha512, 64 },
};

int dkim2_hash_alg_index(const char *name) {
    if (!name) return -1;
    for (int i = 0; i < DKIM2_N_HASH_ALGS; i++)
        if (strcasecmp(name, HASH_ALGS[i].name) == 0) return i;
    return -1;
}

const char *dkim2_hash_alg_name(int idx) {
    return (idx >= 0 && idx < DKIM2_N_HASH_ALGS) ? HASH_ALGS[idx].name : NULL;
}

size_t dkim2_hash_alg_len(int idx) {
    return (idx >= 0 && idx < DKIM2_N_HASH_ALGS) ? HASH_ALGS[idx].len : 0;
}
```

Change `struct dkim2_body_hasher` to hold `EVP_MD_CTX *md_ctx[DKIM2_N_HASH_ALGS]`, initialising each with its own `HASH_ALGS[i].md()`. Every `EVP_DigestUpdate` in `flush_pending` and `dkim2_body_hasher_update` becomes a loop over the array. Add:

```c
int dkim2_body_hasher_final_all(dkim2_body_hasher_t *bh, dkim2_digests_t *out) {
    if (bh->prev_was_cr) bh->pending_crlfs++;
    for (int i = 0; i < DKIM2_N_HASH_ALGS; i++) {
        EVP_DigestUpdate(bh->md_ctx[i], "\r\n", 2);
        unsigned int dlen = (unsigned int)HASH_ALGS[i].len;
        if (EVP_DigestFinal_ex(bh->md_ctx[i], out->d[i], &dlen) != 1) return -1;
    }
    return 0;
}
```

Keep `dkim2_body_hasher_final` as a wrapper that calls `_final_all` and copies `out.d[0]`. Generalise `sha256_buf` into `digest_buf(parts, lens, nparts, alg, digest)` selecting `HASH_ALGS[alg].md()`, and route the `_alg` body/header hash variants through it.

- [ ] **Step 5: Widen the context and the parser**

- `c/dkim2_internal.h:67`: `unsigned char body_digest[DKIM2_HASH_LEN]` → `dkim2_digests_t body_digests;`
- `c/eml_parse.h:15,21` and `c/eml_parse.c:9,103,109`: change the `body_digest_out[DKIM2_HASH_LEN]` parameters to `dkim2_digests_t *body_digests_out` and call `dkim2_body_hasher_final_all`.

- [ ] **Step 6: Make the verifier algorithm-aware**

Replace the hash comparison at `c/dkim2_verify.c:299-334` so the loop resolves each hash-set's algorithm and honours the Global Constraints semantics:

```c
        int n_checked = 0;
        for (int hi = 0; hi < mi->n_hsets; hi++) {
            int alg = dkim2_hash_alg_index(mi->hsets[hi].alg);
            if (alg < 0) continue;          /* §3.4: ignore what we don't implement */
            size_t alen = dkim2_hash_alg_len(alg);
            n_checked++;

            unsigned char stored_bh[DKIM2_MAX_HASH_LEN];
            int bh_len = (int)b64_decode(mi->hsets[hi].body_hash, stored_bh, sizeof stored_bh);
            if (bh_len != (int)alen) {
                snprintf(errbuf, errbufsz, "PERMERROR: bad body hash in MI m=%d", mi->m);
                ret = -1; goto done;
            }
            unsigned char computed_bh[DKIM2_MAX_HASH_LEN];
            if (cur_body) {
                dkim2_body_hash_raw_alg(cur_body, cur_body_len, alg, computed_bh);
            } else if (vi == n_mi - 1) {
                memcpy(computed_bh, ctx->body_digests.d[alg], alen);
            } else {
                continue;                    /* no body bytes for inner MIs */
            }
            if (memcmp(computed_bh, stored_bh, alen) != 0) {
                snprintf(errbuf, errbufsz,
                    "FAIL: Message-Instance m=%d body hash mismatch", mi->m);
                ret = -1; goto done;
            }

            unsigned char computed_hh[DKIM2_MAX_HASH_LEN];
            if (dkim2_header_hash_raw_alg((const char **)content, n_content, alg, computed_hh) < 0) {
                snprintf(errbuf, errbufsz, "PERMERROR: header hash computation failed");
                ret = -1; goto done;
            }
            unsigned char stored_hh[DKIM2_MAX_HASH_LEN];
            int hh_len = (int)b64_decode(mi->hsets[hi].hdr_hash, stored_hh, sizeof stored_hh);
            if (hh_len != (int)alen || memcmp(computed_hh, stored_hh, alen) != 0) {
                snprintf(errbuf, errbufsz,
                    "FAIL: Message-Instance m=%d header hash mismatch", mi->m);
                ret = -1; goto done;
            }
        }
        /* Fail closed: an MI naming no implemented algorithm is unverifiable. */
        if (n_checked == 0) {
            snprintf(errbuf, errbufsz,
                "FAIL: Message-Instance m=%d no supported hash algorithm", mi->m);
            ret = -1; goto done;
        }
```

Note the `top_body_digest` parameter is replaced by `ctx->body_digests`; adjust the enclosing function's signature and its caller accordingly.

- [ ] **Step 7: Add the `--hash` flag to the C signer**

In `c/dkim2sign_cli.c`, accept `--hash sha256|sha512|both`; in `c/dkim2_sign.c:165`, build one `dkim2_hashset_t` per selected algorithm instead of the single hardcoded `{ "sha256", ... }`, and join them with commas in the `h=` tag at `:304`.

- [ ] **Step 8: Build and run the C suite**

Run: `make -C c clean && make -C c check`
Expected: PASS, all test binaries, no warnings about buffer sizes.

- [ ] **Step 9: Commit**

```bash
git add c/
git commit -m "c: spec-05 hash agility (sha512, per-algorithm hash-sets)

Also fixes a pre-existing bug: the verifier looped over hash-sets but never
read alg, decoding every one into a 32-byte buffer, so any message carrying
a non-sha256 hash-set failed instead of being ignored per §3.4."
```

### Task 12: Browser JS — hash agility

**Files:**
- Modify: `deploy/www/verify/crypto.js`
- Modify: `deploy/www/verify/verify.js:224-248`
- Test: `deploy/www/verify/tests/hash-agility.test.mjs` (create)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `HASH_ALGS: Record<string, string>` mapping `sha256`→`SHA-256`, `sha512`→`SHA-512` (WebCrypto names)
  - `hashB64(bytes, alg) -> Promise<string>`
  - `parseHashSets(h) -> {alg, headerHash, bodyHash}[]` exported from `parse.js`

- [ ] **Step 1: Write the failing test**

Create `deploy/www/verify/tests/hash-agility.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert';
import { HASH_ALGS, hashB64 } from '../crypto.js';
import { parseHashSets } from '../parse.js';

test('spec-05 §3: both hashing algorithms are implemented', () => {
  assert.deepEqual(Object.keys(HASH_ALGS).sort(), ['sha256', 'sha512']);
});

test('spec-05 §7.3: h= parses as a list of hash-sets', () => {
  const sets = parseHashSets('sha256:AAA:BBB,sha512:CCC:DDD');
  assert.equal(sets.length, 2);
  assert.deepEqual(sets[0], { alg: 'sha256', headerHash: 'AAA', bodyHash: 'BBB' });
  assert.equal(sets[1].alg, 'sha512');
});

test('hash-name matching is case-insensitive (RFC 5234)', () => {
  assert.equal(parseHashSets('SHA512:AAA:BBB')[0].alg, 'sha512');
});

test('sha512 digest is 64 bytes (88 base64 chars)', async () => {
  const b = new TextEncoder().encode('Hello\r\n');
  assert.equal((await hashB64(b, 'sha512')).length, 88);
  assert.equal((await hashB64(b, 'sha256')).length, 44);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd deploy/www/verify && node --test tests/hash-agility.test.mjs`
Expected: FAIL — `HASH_ALGS`, `hashB64`, `parseHashSets` are not exported.

- [ ] **Step 3: Generalise `crypto.js`**

Add to `deploy/www/verify/crypto.js`:

```javascript
// spec-05 §3.1: two hashing algorithms are defined; Verifiers MUST implement
// both. Values are WebCrypto SubtleCrypto digest names.
export const HASH_ALGS = { sha256: 'SHA-256', sha512: 'SHA-512' };

export async function hashBytes(bytes, alg) {
  const name = HASH_ALGS[alg.toLowerCase()];
  if (!name) throw new Error(`unsupported hash algorithm: ${alg}`);
  return new Uint8Array(await crypto.subtle.digest(name, bytes));
}

export async function hashB64(bytes, alg) {
  return bytesToB64(await hashBytes(bytes, alg));
}
```

Keep `sha256Bytes` / `sha256B64` as wrappers so the signature path at `verify.js:354` is untouched.

- [ ] **Step 4: Export `parseHashSets` from `parse.js`**

Add to `deploy/www/verify/parse.js`:

```javascript
// spec-05 §7.3: h= is hash-set *("," hash-set). Hash names are lowercased —
// RFC 5234 makes ABNF quoted strings case-insensitive. parseTagList has
// already stripped all FWS from the value.
export function parseHashSets(h) {
  const out = [];
  for (const item of (h || '').split(',')) {
    const parts = item.trim().split(':');
    if (parts.length !== 3) continue;
    out.push({ alg: parts[0].trim().toLowerCase(), headerHash: parts[1], bodyHash: parts[2] });
  }
  return out;
}
```

If `verify.js` already imports a local `parseHashSets`, remove that definition and import this one.

- [ ] **Step 5: Dispatch over every implemented hash-set in `verify.js`**

Replace `verify.js:224-243` so it computes each implemented algorithm's hashes and requires all to match, replacing the single `sets.find(s => s.alg === 'sha256')`:

```javascript
      const sets = parseHashSets(mi.map.h);
      const hdrBytes = stringToBytes(canonHeaderHash(signedFields(state.fields)));
      const bodyBytes = stringToBytes(canonBody(linesToBody(state.bodyLines)));
      // §3.4: ignore hash-sets naming algorithms we do not implement; all the
      // ones we do implement must match (mirrors §11.6 for signatures).
      const usable = sets.filter((s) => s.alg in HASH_ALGS);
      if (usable.length === 0) {
        level.result = 'fail';
        level.detail = `Message Instance m=${m} no supported hash algorithm`;
        bump('fail');
      } else {
        level.header_hash = 'match';
        level.body_hash = 'match';
        for (const s of usable) {
          if (await hashB64(hdrBytes, s.alg) !== s.headerHash) {
            level.header_hash = 'mismatch';
            level.result = 'fail';
            level.detail = `Message Instance m=${m} ${s.alg} header hash mismatch`;
            bump('fail');
            break;
          }
          if (await hashB64(bodyBytes, s.alg) !== s.bodyHash) {
            level.body_hash = 'mismatch';
            level.result = 'fail';
            level.detail = `Message Instance m=${m} ${s.alg} body hash mismatch`;
            bump('fail');
            break;
          }
        }
      }
```

- [ ] **Step 6: Run the JS suite**

Run: `cd deploy/www/verify && node --test tests/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add deploy/www/verify/
git commit -m "js: spec-05 hash agility (sha512, multi-hash-set h=)"
```

---

## Phase 3 — Duplicate and limit checks (§7.3, §8.9, §11.2)

The `h=` duplicate-algorithm check landed with Task 8/9/10/11/12 in Python; these tasks add the two `s=` checks everywhere and backfill the `h=` check in the other four.

### Task 13: Duplicate/limit checks — Python

**Files:**
- Modify: `python/dkim2verify.py:379-450`
- Test: `python/tests/test_duplicate_checks.py` (create)

**Interfaces:**
- Consumes: `parse_hash_sets` from Task 8.
- Produces: `_check_signature_duplicates(sig_items, i_val) -> list[str]` — returns PERMERROR strings, empty if clean.

- [ ] **Step 1: Write the failing test**

Create `python/tests/test_duplicate_checks.py`:

```python
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2verify import _check_signature_duplicates  # noqa: E402


def test_clean_signature_list_has_no_errors():
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "ed25519-sha256", "BBB")]
    assert _check_signature_duplicates(items, "1") == []


def test_duplicate_selector_is_permerror():
    # spec-05 §8.9: a Selector MUST NOT be present more than once
    items = [("sel1", "rsa-sha256", "AAA"), ("sel1", "ed25519-sha256", "BBB")]
    errs = _check_signature_duplicates(items, "3")
    assert errs == ["PERMERROR DKIM2-Signature i=3 has a duplicate selector"]


def test_duplicate_selector_is_case_insensitive():
    # Selector is a Domain (§3.5); DNS names are case-insensitive
    items = [("Sel1", "rsa-sha256", "AAA"), ("sel1", "ed25519-sha256", "BBB")]
    assert "has a duplicate selector" in _check_signature_duplicates(items, "1")[0]


def test_same_algorithm_twice_with_distinct_selectors_is_allowed():
    # spec-05 §8.9: one additional signature using the same algorithm MAY be
    # present provided a different Selector is used
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "rsa-sha256", "BBB")]
    assert _check_signature_duplicates(items, "1") == []


def test_same_algorithm_three_times_is_too_many():
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "rsa-sha256", "BBB"),
             ("sel3", "rsa-sha256", "CCC")]
    errs = _check_signature_duplicates(items, "2")
    assert errs == ["PERMERROR DKIM2-Signature i=2 has too many signatures"]


def test_duplicate_selector_and_too_many_are_independent():
    # two sigs sharing an algorithm AND a selector is a duplicate-selector
    # error but NOT too-many-signatures (the count is 2, not 3+)
    items = [("sel1", "rsa-sha256", "AAA"), ("sel1", "rsa-sha256", "BBB")]
    errs = _check_signature_duplicates(items, "1")
    assert any("duplicate selector" in e for e in errs)
    assert not any("too many signatures" in e for e in errs)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd python && python3 -m pytest tests/test_duplicate_checks.py -v`
Expected: FAIL — `ImportError: cannot import name '_check_signature_duplicates'`.

- [ ] **Step 3: Implement the check**

Add to `python/dkim2verify.py` above `verify_dkim2_signature`:

```python
def _check_signature_duplicates(sig_items, i_val) -> list[str]:
    """spec-05 §8.9 duplicate/limit rules for one DKIM2-Signature s= tag.

    A Selector MUST NOT appear more than once. The same signing algorithm may
    appear at most twice, and only with distinct Selectors. Selector matching is
    case-insensitive (a Selector is a Domain, §3.5).
    """
    errors = []
    selectors = [sel.lower() for sel, _, _ in sig_items]
    if len(set(selectors)) != len(selectors):
        errors.append(f"PERMERROR DKIM2-Signature i={i_val} has a duplicate selector")
    counts = {}
    for _, alg, _ in sig_items:
        counts[alg.lower()] = counts.get(alg.lower(), 0) + 1
    if any(n > 2 for n in counts.values()):
        errors.append(f"PERMERROR DKIM2-Signature i={i_val} has too many signatures")
    return errors
```

Call it in `verify_dkim2_signature` immediately after `sig_items` is built (around `:449`), returning its errors before any DNS lookup or crypto.

- [ ] **Step 4: Run the Python suite**

Run: `cd python && python3 -m pytest tests/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add python/dkim2verify.py python/tests/test_duplicate_checks.py
git commit -m "python: spec-05 §8.9 duplicate-selector and signature-count checks"
```

### Task 14: Duplicate/limit checks — Go

**Files:**
- Modify: `go/dkim2/mi.go` (h= duplicate check), `go/dkim2/verify.go:375-390`
- Test: `go/dkim2/duplicate_test.go` (create)

**Interfaces:**
- Consumes: `parseHashSets`, `HashSet` from Task 9.
- Produces: `checkSignatureDuplicates(items []sigItem, i int) []string`, using the existing `s=` item type in `verify.go`.

- [ ] **Step 1: Write the failing test**

Create `go/dkim2/duplicate_test.go` mirroring Task 13's cases: clean list, duplicate selector (case-insensitively), same algorithm twice allowed, three times too many, and the independence case. Assert the exact Global Constraints strings with `i=` substituted.

```go
package dkim2

import "strings"
import "testing"

func TestDuplicateSelectorIsPermerror(t *testing.T) {
	errs := checkSignatureDuplicates([]sigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel1", Algorithm: "ed25519-sha256"},
	}, 3)
	want := "PERMERROR DKIM2-Signature i=3 has a duplicate selector"
	if len(errs) != 1 || errs[0] != want {
		t.Errorf("got %v, want [%q]", errs, want)
	}
}

func TestSameAlgorithmTwiceAllowed(t *testing.T) {
	errs := checkSignatureDuplicates([]sigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel2", Algorithm: "rsa-sha256"},
	}, 1)
	if len(errs) != 0 {
		t.Errorf("spec-05 §8.9 allows one additional same-algorithm signature with a distinct Selector; got %v", errs)
	}
}

func TestThreeSameAlgorithmIsTooMany(t *testing.T) {
	errs := checkSignatureDuplicates([]sigItem{
		{Selector: "sel1", Algorithm: "rsa-sha256"},
		{Selector: "sel2", Algorithm: "rsa-sha256"},
		{Selector: "sel3", Algorithm: "rsa-sha256"},
	}, 2)
	if len(errs) != 1 || !strings.Contains(errs[0], "has too many signatures") {
		t.Errorf("got %v, want a too-many-signatures PERMERROR", errs)
	}
}

func TestDuplicateHashAlgorithmIsPermerror(t *testing.T) {
	_, err := parseMI("Message-Instance: m=4; h=sha256:AAA:BBB,sha256:CCC:DDD;")
	if err == nil || !strings.Contains(err.Error(), "has a duplicate hash algorithm") {
		t.Errorf("got %v, want a duplicate-hash-algorithm PERMERROR (spec-05 §7.3)", err)
	}
}
```

Rename `sigItem` to whatever `verify.go` actually calls the parsed `selector:algorithm:signature` triple; check `verify.go:437-452` before writing the test.

- [ ] **Step 2: Run to verify it fails**

Run: `cd go && go test ./dkim2/ -run 'Duplicate|TooMany|SameAlgorithm' -v`
Expected: FAIL — `checkSignatureDuplicates` undefined.

- [ ] **Step 3: Implement both checks**

In `mi.go`, immediately after `parseHashSets` returns in `parseMI`:

```go
	// spec-05 §7.3: an algorithm MUST NOT be present more than once.
	seen := map[string]bool{}
	for _, hs := range hashes {
		if seen[hs.Alg] {
			return nil, fmt.Errorf("PERMERROR Message-Instance m=%d has a duplicate hash algorithm", m)
		}
		seen[hs.Alg] = true
	}
```

In `verify.go`, add `checkSignatureDuplicates` with the same logic as Task 13 Step 3 and call it right after the `s=` items are parsed, before any DNS lookup.

- [ ] **Step 4: Run the Go suite**

Run: `cd go && go test ./dkim2/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go/dkim2/
git commit -m "go: spec-05 §7.3/§8.9 duplicate and signature-count checks"
```

### Task 15: Duplicate/limit checks — Perl

**Files:**
- Modify: `perl/lib/Mail/DKIM2/MessageInstance.pm` (h= duplicate), `perl/lib/Mail/DKIM2/Signature.pm` (s= checks)
- Test: `perl/t/duplicate-checks.t` (create)

**Interfaces:**
- Consumes: `parse_hash_sets` from Task 10.
- Produces: `Mail::DKIM2::Signature::check_duplicates($sig)` → list of PERMERROR strings.

- [ ] **Step 1: Write the failing test**

Create `perl/t/duplicate-checks.t` covering the same six cases as Task 13, asserting the exact Global Constraints strings. Use `Mail::DKIM2::Signature->parse` on a synthetic header for each case, e.g.:

```perl
#!/usr/bin/perl -w
use 5.020;
use strict;
use warnings;
use Test::More;
use lib 'lib', 't/lib';
use Mail::DKIM2::Signature;
use Mail::DKIM2::MessageInstance;

my $dup_sel = Mail::DKIM2::Signature->parse(
    'i=3; m=1; t=1740000000; d=a.example; nd=b.example; '
  . 's=sel1:rsa-sha256:AAA,sel1:ed25519-sha256:BBB');
my @errs = Mail::DKIM2::Signature::check_duplicates($dup_sel);
is_deeply(\@errs, ['PERMERROR DKIM2-Signature i=3 has a duplicate selector'],
          'spec-05 §8.9: a Selector MUST NOT repeat');

my $twice = Mail::DKIM2::Signature->parse(
    'i=1; m=1; t=1740000000; d=a.example; nd=b.example; '
  . 's=sel1:rsa-sha256:AAA,sel2:rsa-sha256:BBB');
is_deeply([Mail::DKIM2::Signature::check_duplicates($twice)], [],
          'spec-05 §8.9: same algorithm twice with distinct Selectors is allowed');

my $thrice = Mail::DKIM2::Signature->parse(
    'i=2; m=1; t=1740000000; d=a.example; nd=b.example; '
  . 's=sel1:rsa-sha256:AAA,sel2:rsa-sha256:BBB,sel3:rsa-sha256:CCC');
is_deeply([Mail::DKIM2::Signature::check_duplicates($thrice)],
          ['PERMERROR DKIM2-Signature i=2 has too many signatures'],
          'spec-05 §8.9: three same-algorithm signatures is too many');

# spec-05 §7.3
my $sets = Mail::DKIM2::MessageInstance::parse_hash_sets('sha256:AAA:BBB,SHA256:CCC:DDD');
my %seen;
my $dup = grep { $seen{$_->[0]}++ } @$sets;
ok($dup, 'duplicate hash algorithm detected case-insensitively');

done_testing();
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd perl && prove -l t/duplicate-checks.t`
Expected: FAIL — `check_duplicates` undefined.

- [ ] **Step 3: Implement**

Add `check_duplicates` to `perl/lib/Mail/DKIM2/Signature.pm` with the Task 13 logic (lowercase both Selector and algorithm before counting), and add the duplicate-algorithm guard to `MessageInstance::parse` after `parse_hash_sets`, dying with the exact PERMERROR string. Call `check_duplicates` from `Mail::DKIM2::Verifier` before the public-key fetch.

- [ ] **Step 4: Run the Perl suite**

Run: `cd perl && prove -l t/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add perl/lib/Mail/DKIM2/ perl/t/duplicate-checks.t
git commit -m "perl: spec-05 §7.3/§8.9 duplicate and signature-count checks"
```

### Task 16: Duplicate/limit checks — C

**Files:**
- Modify: `c/dkim2_header.c:20-45` (`parse_hsets` duplicate detection), `c/dkim2_verify.c:141-175` (`s=` parsing)
- Test: `c/tests/test_header.c`

**Interfaces:**
- Consumes: `dkim2_hash_alg_index` from Task 11.
- Produces: `parse_hsets` returns `-2` on a duplicate algorithm (distinct from `-1` malloc/syntax failure); `int dkim2_sig_check_duplicates(const dkim2_sig_t *sig, char *errbuf, size_t errbufsz)` returning 0 clean / -1 with `errbuf` filled.

- [ ] **Step 1: Write the failing test**

Append to `c/tests/test_header.c`:

```c
    /* spec-05 §7.3: an algorithm MUST NOT be present more than once */
    assert(dkim2_mi_parse("m=1; h=sha256:AAA:BBB,sha256:CCC:DDD;") == NULL);
    /* ...detected case-insensitively (RFC 5234) */
    assert(dkim2_mi_parse("m=1; h=sha256:AAA:BBB,SHA256:CCC:DDD;") == NULL);
    /* ...but two different algorithms are fine */
    dkim2_mi_t *ok_mi = dkim2_mi_parse("m=1; h=sha256:AAA:BBB,sha512:CCC:DDD;");
    assert(ok_mi != NULL);
    assert(ok_mi->n_hsets == 2);
    dkim2_mi_free(ok_mi);
```

- [ ] **Step 2: Run to verify it fails**

Run: `make -C c tests/test_header && ./c/tests/test_header`
Expected: FAIL — the duplicate cases currently parse successfully.

- [ ] **Step 3: Implement**

In `parse_hsets`, after filling each entry, compare its `alg` case-insensitively against all previously stored entries and return `-2` on a match; propagate that so `dkim2_mi_parse` returns NULL. Add `dkim2_sig_check_duplicates` in `dkim2_verify.c` with the Task 13 logic, writing the exact PERMERROR strings into `errbuf`, and call it before the public-key fetch.

- [ ] **Step 4: Run the C suite**

Run: `make -C c check`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add c/
git commit -m "c: spec-05 §7.3/§8.9 duplicate and signature-count checks"
```

### Task 17: Duplicate/limit checks — Browser JS

**Files:**
- Modify: `deploy/www/verify/verify.js`
- Test: `deploy/www/verify/tests/duplicate.test.mjs` (create)

**Interfaces:**
- Consumes: `parseHashSets` from Task 12.
- Produces: `checkSignatureDuplicates(items, i) -> string[]` exported from `verify.js`.

- [ ] **Step 1: Write the failing test**

Create `deploy/www/verify/tests/duplicate.test.mjs` with the same six cases as Task 13, asserting the exact Global Constraints strings via `checkSignatureDuplicates`, plus a `parseHashSets` duplicate-algorithm case.

- [ ] **Step 2: Run to verify it fails**

Run: `cd deploy/www/verify && node --test tests/duplicate.test.mjs`
Expected: FAIL — `checkSignatureDuplicates` is not exported.

- [ ] **Step 3: Implement**

Add `checkSignatureDuplicates` to `verify.js` with the Task 13 logic and call it where `s=` items are parsed, before the DNS fetch; add the duplicate-algorithm guard where `parseHashSets(mi.map.h)` is consumed, setting `level.result = 'fail'` with the exact PERMERROR detail.

- [ ] **Step 4: Run the JS suite**

Run: `cd deploy/www/verify && node --test tests/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/www/verify/
git commit -m "js: spec-05 §7.3/§8.9 duplicate and signature-count checks"
```

---

## Phase 4 — Recipes, §9.1, versions, editorial

### Task 18: Invalid-JSON PERMERROR and Recipe comment updates

§11.2: "To assist debugging, errors in a JSON object specifying Recipes should be called out specifically." Lower-case emission is already correct everywhere — only comments change.

**Files:**
- Modify: `python/dkim2verify.py`, `go/dkim2/mi.go`, `perl/lib/Mail/DKIM2/MessageInstance.pm:200`, `c/dkim2_verify.c`, `deploy/www/verify/verify.js`
- Modify (comments only): `perl/lib/Mail/DKIM2/MessageInstance.pm:120`, `go/dkim2/recipe.go:38`, `python/dkim2sign.py:243`, `go/dkim2/recipe_test.go:8`, `python/tests/test_recipe_case.py:2`
- Test: `python/tests/test_invalid_json.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: no new public symbols; the r= decode path emits the invalid-JSON PERMERROR.

- [ ] **Step 1: Write the failing test**

Create `python/tests/test_invalid_json.py`:

```python
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2verify import verify_message_instance  # noqa: E402


def _mi_with_r(raw_json: bytes) -> str:
    r = base64.b64encode(raw_json).decode()
    return f"Message-Instance: m=2; h=sha256:AAA:BBB; r={r};"


def test_malformed_recipe_json_is_reported_specifically():
    # spec-05 §11.2: JSON errors are called out specifically, not as a
    # generic syntax error
    errs = verify_message_instance(_mi_with_r(b'{"h": '), [b"From: a@b\r\n"], b"x\r\n")
    assert any("contains invalid JSON" in e for e in errs)
    assert any("m=2" in e for e in errs)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd python && python3 -m pytest tests/test_invalid_json.py -v`
Expected: FAIL — the current code raises or reports a generic error.

- [ ] **Step 3: Emit the specific error in all five verifiers**

Wrap each JSON decode of the `r=` payload so a parse failure yields exactly
`PERMERROR Message-Instance m=<x> contains invalid JSON`, distinct from the generic syntax error:
`python/dkim2verify.py` (`json.JSONDecodeError`), `go/dkim2/mi.go:59-65` (replace `fmt.Errorf("invalid recipe JSON: %w", err)`), `perl/lib/Mail/DKIM2/MessageInstance.pm:200` (wrap `decode_tag_json` in `eval`), `c/dkim2_verify.c` (cJSON parse failure), `deploy/www/verify/verify.js` (the `JSON.parse` in the recipe path).

- [ ] **Step 4: Update the five stale comments**

Replace *"not yet mandated by the draft, but we do it"* / *"Not yet mandated by the draft, but we always do it"* with a citation, e.g. `spec-05 §5.1: header field names in the JSON Recipes MUST be lower case (matching against the message stays case-insensitive).` at `perl/lib/Mail/DKIM2/MessageInstance.pm:120`, `go/dkim2/recipe.go:38`, `python/dkim2sign.py:243`, `go/dkim2/recipe_test.go:8`, `python/tests/test_recipe_case.py:2`.

- [ ] **Step 5: Run every suite**

Run:
```bash
cd python && python3 -m pytest tests/ -q && cd ../go && go test ./dkim2/ -count=1 && \
cd ../perl && prove -l t/ && cd .. && make -C c check && \
cd deploy/www/verify && node --test tests/
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add python/ go/ perl/ c/ deploy/www/verify/
git commit -m "all: spec-05 §11.2 invalid-JSON PERMERROR; §5.1 recipe comments

Lower-case recipe keys were already emitted everywhere; §5.1 now mandates it,
so the 'not yet mandated by the draft' comments are updated to cite it."
```

### Task 19: Version strings

**Files:**
- Modify: `perl/lib/Mail/DKIM2/Common.pm:41,43`
- Modify: `perl/t/version.t:4-5`
- Modify: `sympa/src/lib/Sympa/Message.pm:464,466`
- Modify: `mailman/src/mailman/handlers/message_instance.py` (`DKIM2_DRAFT`, `DKIM2_DATE`)
- Modify: `mailman/src/mailman/handlers/tests/test_message_instance.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `DKIM2_DRAFT` = `ietf-dkim-dkim2-spec-05`, `DKIM2_DATE` = `2026-08-25` in all three trees.

- [ ] **Step 1: Update the pinning tests first (they should fail)**

`perl/t/version.t:4-5`:

```perl
is(DKIM2_DRAFT, 'ietf-dkim-dkim2-spec-05', 'draft constant is -05');
is(DKIM2_DATE, '2026-08-25', 'draft date is the -05 date');
```

and the equivalent assertions in `mailman/src/mailman/handlers/tests/test_message_instance.py`.

- [ ] **Step 2: Run to verify they fail**

Run: `cd perl && prove -l t/version.t`
Expected: FAIL — got `-04` / `2026-07-05`.

- [ ] **Step 3: Bump the constants**

`perl/lib/Mail/DKIM2/Common.pm:41,43`:

```perl
use constant DKIM2_DRAFT => 'ietf-dkim-dkim2-spec-05';
use constant DKIM2_DATE  => '2026-08-25';
```

`sympa/src/lib/Sympa/Message.pm:464,466` and Mailman's `message_instance.py` likewise. Confirm Sympa is on its `dkim2` branch first (`cd ../sympa && git branch --show-current`).

- [ ] **Step 4: Verify**

Run: `cd perl && prove -l t/version.t && cd ../../mailman && python -m pytest src/mailman/handlers/tests/test_message_instance.py -q`
Expected: PASS.

- [ ] **Step 5: Commit in all three repos**

```bash
cd /Users/brong/src/interop && git add perl/ && git commit -m "perl: bump spec version to -05 (2026-08-25)"
cd ../mailman && git add src/ && git commit -m "dkim2: bump spec version to -05 (2026-08-25)"
cd ../sympa  && git add src/ && git commit -m "dkim2: bump spec version to -05 (2026-08-25)"
```

### Task 20: §9.1 and the capitalisation sweep

**Files:**
- Modify: any implementation encoding the removed §9.1 SHOULD NOT
- Modify: comments and docs across all trees

**Interfaces:**
- Consumes: nothing.
- Produces: no code-behaviour change beyond the §9.1 relaxation.

- [ ] **Step 1: Find any encoded §9.1 SHOULD NOT**

Run:
```bash
cd /Users/brong/src && grep -rniE 'SHOULD NOT.*(message-instance|pointless)|pointless.*message-instance' \
  interop/perl/lib interop/python interop/go interop/c interop/deploy/www \
  mailman/src sympa/src 2>/dev/null | grep -v '/blib/'
```
Expected: comments only. **If any of them gates a code path** (refusing to add an MI when hashes match), remove the refusal — §9.1 now says only that doing so is pointless. If it is purely a comment, reword it.

- [ ] **Step 2: Sweep the stale spec references**

Run:
```bash
cd /Users/brong/src && grep -rln 'spec-04\|draft-04\|2026-07-05' \
  interop/perl/lib interop/perl/t interop/python interop/go interop/c \
  interop/deploy/www interop/docs interop/README.md mailman/src sympa/src 2>/dev/null | grep -v '/blib/'
```
Update each hit to `-05` / `2026-08-25`, **except** `interop/docs/superpowers/specs/2026-07-05-*` and `interop/docs/superpowers/plans/2026-07-05-*`, which are historical records of the -04 upgrade and must not be rewritten.

- [ ] **Step 3: Apply the capitalisation sweep**

In comments, docstrings and docs only, capitalise Recipes / Selector / Chain of Custody per §17's "Made Capitalisation Consistent". Do **not** touch JSON keys, tag names, wire strings, function or variable names.

- [ ] **Step 4: Run every suite**

Run:
```bash
cd interop/python && python3 -m pytest tests/ -q && cd ../go && go test ./dkim2/ -count=1 && \
cd ../perl && prove -l t/ && cd .. && make -C c check && \
cd deploy/www/verify && node --test tests/ && cd ../../.. && ./util/turscar-all.sh
cd ../mailman && python -m pytest src/mailman/handlers/tests/ -q
```
Expected: all PASS.

- [ ] **Step 5: Commit in all three repos**

```bash
cd /Users/brong/src/interop && git add -A && git commit -m "all: spec-05 §9.1 and the capitalisation sweep"
cd ../mailman && git add -A && git commit -m "dkim2: spec-05 §9.1 and the capitalisation sweep"
cd ../sympa  && git add -A && git commit -m "dkim2: spec-05 §9.1 and the capitalisation sweep"
```

---

## Phase 5 — Cross-implementation proof

### Task 21: Hash-agility matrix

Nothing else in this plan proves that one implementation's sha512 output verifies in another. This is new coverage — no existing test exercises a non-sha256 hash.

**Files:**
- Create: `util/hash-matrix.sh`
- Modify: `README.md` (document the runner beside the Turscar section)

**Interfaces:**
- Consumes: the `--hash`/`-hash` flags from Tasks 8, 9, 10, 11.
- Produces: an executable that exits non-zero if any (signer, algorithm, verifier) cell disagrees.

- [ ] **Step 1: Write the runner**

Create `util/hash-matrix.sh`:

```sh
#!/bin/sh
# Cross-implementation hash-agility matrix (spec-05 §3.1, §7.3).
#
#   ./util/hash-matrix.sh
#
# Signs one message with each signer at --hash sha256, sha512 and both, then
# verifies every output with every verifier. Proves algorithm dexterity across
# implementations, which no single-language suite can.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Verified against the actual CLIs on 2026-08-25 -- note each one spells its
# flags differently, and Go's signer reads the message on stdin.
SRC=perl/tests/emails/brong-orig.eml
KEY=keys/sel1._domainkey.test1.dkim2.com.pem
DOM=test1.dkim2.com
SEL=sel1
MF='<brong@test1.dkim2.com>'
RT='<user@test2.dkim2.com>'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rc=0

sign() { # sign <impl> <alg> <out>
    case $1 in
    python) python3 python/dkim2sign.py "$SRC" -s "$SEL" -d "$DOM" -k "$KEY" \
                --mailfrom "$MF" --rcptto "$RT" --hash "$2" > "$3" 2>"$tmp/err" ;;
    go)     ./go/dkim2sign -selector "$SEL" -domain "$DOM" -key "$KEY" \
                -mail-from "$MF" -rcpt-to "$RT" -hash "$2" < "$SRC" > "$3" 2>"$tmp/err" ;;
    c)      ./c/dkim2sign "$SRC" -s "$SEL" -d "$DOM" -k "$KEY" \
                --mailfrom "$MF" --rcptto "$RT" --hash "$2" > "$3" 2>"$tmp/err" ;;
    perl)   (cd perl && perl -Ilib bin/dkim2sign.pl "../$SRC" -s "$SEL" -d "$DOM" \
                -k "../$KEY" --mailfrom "$MF" --rcptto "$RT" --hash "$2") > "$3" 2>"$tmp/err" ;;
    esac
}

# validate.pl and verify-sig.pl both read ../dns.json relative to cwd, so the
# Perl verifier must run from perl/.
verify() { # verify <impl> <file>
    case $1 in
    python) python3 python/dkim2verify.py "$2" --dns-json dns.json --ignore-timestamps ;;
    go)     ./go/dkim2verify -dns dns.json -ignore-timestamps "$2" ;;
    c)      ./c/dkim2verify "$2" --dns-json dns.json --ignore-timestamps ;;
    perl)   (cd perl && perl -Ilib bin/validate.pl --ignore-timestamps "../$2") \
                | grep -qi '^pass' ;;
    js)     (cd deploy/www/verify && node tests/verify-file.mjs "../../../$2") ;;
    esac
}

for signer in python go c perl; do
    for alg in sha256 sha512 both; do
        out="$tmp/$signer-$alg.eml"
        if ! sign "$signer" "$alg" "$out"; then
            printf '  %-7s %-7s SIGN FAILED\n' "$signer" "$alg"; rc=1; continue
        fi
        for verifier in python go c perl js; do
            if verify "$verifier" "$out" >"$tmp/v.log" 2>&1; then
                printf '  %-7s %-7s -> %-7s ok\n' "$signer" "$alg" "$verifier"
            else
                printf '  %-7s %-7s -> %-7s FAILED\n' "$signer" "$alg" "$verifier"
                sed 's/^/           /' "$tmp/v.log" | head -3
                rc=1
            fi
        done
    done
done

echo
[ "$rc" -eq 0 ] && echo "All signer/algorithm/verifier combinations agree." \
                || echo "At least one combination disagrees."
exit "$rc"
```

`chmod +x util/hash-matrix.sh`.

- [ ] **Step 2: Write the JS file-driven entry point**

The four native CLIs' flags above were checked against their sources and `keys/`
and `dns.json` were confirmed to hold `sel1._domainkey.test1.dkim2.com`, so only
the JS side is missing: there is no file-driven entry point, since
`tests/vectors.test.mjs` drives vectors through `node --test`. Create
`deploy/www/verify/tests/verify-file.mjs` as a thin wrapper over the same code
path `vectors.test.mjs` uses — read the path in `process.argv[2]`, run the
verifier, print the result and `process.exit(result === 'pass' ? 0 : 1)`. Read
`vectors.test.mjs` first to reuse its existing setup rather than duplicating it.

- [ ] **Step 3: Build the CLIs and run the matrix**

Run: `make -C c tools && (cd go && go build -o ../go/dkim2sign ./cmd/dkim2sign && go build -o ../go/dkim2verify ./cmd/dkim2verify) && ./util/hash-matrix.sh`
Expected: every cell `ok` — 60 combinations (4 signers × 3 algorithms × 5 verifiers).

- [ ] **Step 4: Document it**

Add to `README.md` beside the Turscar section:

```markdown
## Hash agility

`draft-05` added sha512 alongside sha256. To check that every signer's output
verifies in every implementation, at each algorithm:

    ./util/hash-matrix.sh
```

- [ ] **Step 5: Commit**

```bash
git add util/hash-matrix.sh README.md
git commit -m "util: cross-implementation hash-agility matrix

Signs with each signer at sha256/sha512/both and verifies with all five
verifiers -- the only check that proves §3.1 dexterity across languages."
```

---

## Phase 6 — Deploy

### Task 22: Deploy and acceptance-test on production

**Files:** none — this is an operational task.

**Interfaces:**
- Consumes: everything above.
- Produces: `X-DKIM2-Info` on live mail reading `draft=ietf-dkim-dkim2-spec-05; date=2026-08-25`.

- [ ] **Step 1: Confirm every suite is green locally**

Run:
```bash
cd /Users/brong/src/interop && \
  (cd python && python3 -m pytest tests/ -q) && (cd go && go test ./dkim2/ -count=1) && \
  (cd perl && prove -l t/) && make -C c check && \
  (cd deploy/www/verify && node --test tests/) && \
  ./util/turscar-all.sh && ./util/hash-matrix.sh
cd ../mailman && python -m pytest src/mailman/handlers/tests/ -q
```
Expected: all PASS. Do not deploy on a red suite.

- [ ] **Step 2: Merge the interop branch to master**

Per the standing preference, finish the branch by merging locally (not a PR):

```bash
cd /Users/brong/src/interop && git checkout master && git merge --no-ff <branch> && git log --oneline -3
```

- [ ] **Step 3: Deploy**

Run: `cd /Users/brong/src/interop && ./deploy/deploy.sh`
Read the script's output; it drives the Perl stack (milter, reflector, validator) and the website. Mailman and Sympa deploy from their `dkim2` branches — confirm the script picks those branches up rather than master/main, and push those branches first if it deploys from the remote.

- [ ] **Step 4: Run the list smoke test**

Run: `./deploy/dkim2-list-smoke.sh`
Expected: pass. This is the reusable dkim2capture/dkim2test setup; it exercises real list mail through the signers and verifiers.

- [ ] **Step 5: Acceptance-test on production**

Send a message through the live path and confirm:
- `X-DKIM2-Info` reads `draft=ietf-dkim-dkim2-spec-05; date=2026-08-25`
- the message verifies at https://dkim2.com/verify/
- a message carrying `Received-SPF` still verifies (the §4 change is live and consistent end to end)

- [ ] **Step 6: Report**

State plainly what was deployed, what the smoke test and acceptance checks showed, and anything left out. If any step failed, say so with the output rather than reporting success.

---

## Self-Review

**Spec coverage** — every design section maps to a task:

| Design section | Tasks |
|---|---|
| §1 Hash agility (registry, list parsing, semantics, `--hash`) | 8, 9, 10, 11, 12 |
| §2 Duplicate and limit checks | 8 (h=, Python), 13, 14, 15, 16, 17 |
| §3 Unsigned header fields | 1, 2, 3, 4, 5, 6 + fixture repair in 7 |
| §4 Recipes (lower case, invalid JSON) | 18 |
| §5 §9.1 and editorial | 20 |
| §6 Version strings | 19 |
| Testing (suites, Turscar, matrix, negative vectors) | 7 step 8, 21, 13–17 |
| Deployment | 22 |
| Risk: fixture regeneration baking in a wrong hash | 7 steps 4–5 (cross-verify with a second implementation) |
| Risk: `Received-*` sweep misses a tree | 7 step 1 (all-tree grep, stop-and-report) |
| Risk: C fixed 32-byte buffers | 11 (`DKIM2_MAX_HASH_LEN`, every buffer widened) |
| Risk: prod regression | 22 steps 4–5 |

**Type consistency** — checked across tasks: `parse_hash_sets` (Python/Perl, tuple/arrayref of `(alg, hdr, body)`), `parseHashSets` (Go/JS, struct/object with `Alg`/`alg`), `HASH_ALGS` (Python dict, JS object), `HashAlg` (Go), `dkim2_hash_alg_index` (C). Naming differs per language convention as intended; the shape is consistent. `_check_signature_duplicates` (Python) / `checkSignatureDuplicates` (Go, JS) / `check_duplicates` (Perl) / `dkim2_sig_check_duplicates` (C) all take the parsed `s=` items plus the `i=` value and return the same two PERMERROR strings.

**Known soft spots**, flagged rather than papered over:

- Task 21's invocations were checked against each CLI's source on 2026-08-25 (they differ substantially — Go reads stdin, C takes the message positionally, Perl's verifier resolves `../dns.json` relative to cwd). The one real gap is the JS file-driven entry point, which does not exist; Step 2 creates it.
- Tasks 10, 15, 16, 17 describe the implementation prose-first where the change is a mechanical repeat of code given in full in an earlier task (13 for the duplicate logic, 8 for the hash semantics). The executing agent should read the referenced task.
- Task 9 Step 5 ("fix every consumer") cannot enumerate the call sites without building; the compiler produces the list.

---

## Execution note

Tasks 1–6 are independent of each other and can run in parallel. **Task 7 must follow Task 3** and should land before Phase 2 begins, so later tasks build on stable fixtures. Within Phase 2 and Phase 3, the per-language tasks are independent. Task 19 is independent of everything. Tasks 21 and 22 are strictly last.
