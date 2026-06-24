# DKIM2 draft-03 Spec Upgrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring all four DKIM2 reference implementations (C, Go, Python, Perl), the Mailman handler, and the Sympa integration into conformance with `draft-ietf-dkim-dkim2-spec-03`, then deploy the changes to the `mail.dkim2.com` demo server.

**Architecture:** Six independent codebases share one spec. The deployed signing/verification path is the **Perl** `Mail::DKIM2` library (backs the milter, reflector, validator, and is Sympa's dependency). C/Go/Python are interop reference code. Mailman ships its own embedded Python Message-Instance code. Each change is applied per-codebase with its own test gate; deployment is a final phase via `git pull` (interop) + `rsync` (Mailman/Sympa) + service restart.

**Tech Stack:** C (cJSON, OpenSSL, libmilter), Go (stdlib), Python 3.13 (stdlib `email`), Perl (Mail::DKIM2 dist), GNU Mailman 3.3.11, Sympa 6.2.76.

## Global Constraints

- Target spec: `draft-ietf-dkim-dkim2-spec-03` (dated 24 June 2026). Bump every embedded spec-version string from `...spec-02` to `...spec-03`.
- Hash algorithm: SHA256 only. Signing: RSA-SHA256 (pubexp 65537) and Ed25519-SHA256. Unchanged by -03.
- `nd=` tag ABNF: `sig-nd-tag = %x6e %x64 [FWS] "=" [FWS] Domain` (literally the bytes `n` `d`). Value is a bare DNS domain (NOT base64).
- Required DKIM2-Signature tags under -03: `i= m= t= d= s=` MUST be present, **plus** either an `nd=` tag **or** both `mf=` and `rt=` tags. When `nd=` is present, `mf=` and `rt=` MUST be absent (and vice-versa).
- `nd=` semantics: the domain in `nd=` MUST exactly match the `d=` value of the next-higher-sequence (`i=`) DKIM2-Signature.
- Header ignore list now also includes `Delivered-To` (RFC 9228). Full list: `received`, `return-path`, `delivered-to`, `authentication-results`, `dkim-signature`, prefix `arc-`, prefix `x-`. Implementations additionally exclude their own `dkim2-signature` / `message-instance` framing headers from the content hash.
- Header recipes: a **null `"h"`** value is no longer permitted. Recipes MUST be provided for every *relevant* (non-ignored) header field that changed. A null **body** recipe (`"b": null`) is still permitted (unchanged).
- New `f=` flag value: `feedhere`. Full flag set: `donotmodify`, `donotexplode`, `feedback`, `feedhere`, `exploded`, plus `x-*` extension values. Only `donotmodify`/`donotexplode`/`exploded` carry verifier enforcement; `feedback`/`feedhere` round-trip with no enforcement.
- DSN reference is now **RFC 3462** (multipart/report) rather than RFC 3461. A DKIM2 DSN MUST have exactly three parts: human-readable text, `message/delivery-status`, and either `message/rfc822` (full original) or `text/rfc822-headers` (headers only). A propagated DSN is a *new* message: exactly one DKIM2-Signature and one Message-Instance.

---

## Phase 0: Baseline — capture current passing state

### Task 0: Record green baseline for all test suites

**Files:**
- Test: existing suites only (no edits)

- [ ] **Step 1: Run each suite and record results**

```bash
# Go
cd /Users/brong/src/interop/go && go test ./... 2>&1 | tee /tmp/baseline-go.txt
# Python
cd /Users/brong/src/interop/python && ./tests/run_tests.sh 2>&1 | tee /tmp/baseline-py.txt
# Perl
cd /Users/brong/src/interop/brong && perl Makefile.PL >/dev/null && make test 2>&1 | tee /tmp/baseline-perl.txt
# C
cd /Users/brong/src/interop/c && make 2>&1 | tee /tmp/baseline-c.txt
# Mailman
cd /Users/brong/src/mailman && tox -e py3-nocov -- mailman.handlers.tests.test_message_instance 2>&1 | tee /tmp/baseline-mailman.txt
```

Expected: all currently-passing. Note any pre-existing failures so they are not attributed to this work.

- [ ] **Step 2: Commit nothing** — this is a read-only checkpoint. Record the baseline file paths in the execution log.

---

## Phase 1: `delivered-to` added to the header ignore list

Each implementation maintains (or inherits) an ignore list used for the header-fields hash and recipe building. Add `delivered-to`. Sympa inherits this from the Perl `Common::should_skip` and needs no edit (covered in Phase 1.4 + deploy).

### Task 1.1: C — add `delivered-to` to `hdr_ignore`

**Files:**
- Modify: `c/dkim2_hash.c:124-138`
- Test: `c/tests/` (add `test_ignore_deliveredto`) — if no C test harness exists, use the milter round-trip check in Step 4 instead.

**Interfaces:**
- Produces: `hdr_ignore("delivered-to", 12)` returns `1`.

- [ ] **Step 1: Add the entry** to the `skip[]` array (after `dkim2-signature`):

```c
        {"dkim2-signature",       15},
        {"delivered-to",          12},
        {"dkim-signature",        14},
```

- [ ] **Step 2: Rebuild**

Run: `cd /Users/brong/src/interop/c && make`
Expected: clean build, no warnings.

- [ ] **Step 3: Verify ignore behavior** with a quick driver (sign a message with and without a `Delivered-To:` header and confirm the header hash is identical):

```bash
cd /Users/brong/src/interop/c
# build a 2-message pair differing only by Delivered-To, sign both, diff the m= header hash
./debug_verify --print-header-hash tests/with-deliveredto.eml > /tmp/a
./debug_verify --print-header-hash tests/without-deliveredto.eml > /tmp/b
diff /tmp/a /tmp/b && echo "IGNORED OK"
```
Expected: `IGNORED OK`. (If `debug_verify` lacks `--print-header-hash`, add a one-shot debug print guarded by an env var; remove before commit.)

- [ ] **Step 4: Commit**

```bash
cd /Users/brong/src/interop && git add c/dkim2_hash.c && \
  git commit -m "c: ignore Delivered-To in header hash (draft-03 §4.1)"
```

### Task 1.2: Go — add `delivered-to` to `excludedHeaderNames`

**Files:**
- Modify: `go/dkim2/canon.go:51-56`
- Test: `go/dkim2/canon_test.go` (create if absent)

- [ ] **Step 1: Write the failing test** in `go/dkim2/canon_test.go`:

```go
package dkim2

import "testing"

func TestDeliveredToExcluded(t *testing.T) {
	if !shouldExcludeHeader("delivered-to") {
		t.Fatal("Delivered-To must be excluded from header hash (draft-03 §4.1)")
	}
}
```

- [ ] **Step 2: Run it, expect failure**

Run: `cd /Users/brong/src/interop/go && go test ./dkim2/ -run TestDeliveredToExcluded`
Expected: FAIL.

- [ ] **Step 3: Add the map entry** at `canon.go:52`:

```go
	"received": true, "return-path": true, "message-instance": true,
	"dkim2-signature": true, "dkim-signature": true,
	"authentication-results": true, "delivered-to": true,
```

- [ ] **Step 4: Run, expect pass**

Run: `cd /Users/brong/src/interop/go && go test ./dkim2/ -run TestDeliveredToExcluded`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add go/dkim2/canon.go go/dkim2/canon_test.go && \
  git commit -m "go: ignore Delivered-To in header hash (draft-03 §4.1)"
```

### Task 1.3: Python — add `delivered-to` to `_EXCLUDED_NAMES`

**Files:**
- Modify: `python/dkim2sign.py:94-97`
- Test: `python/tests/test_exclusions.py` (create)

- [ ] **Step 1: Write the failing test** `python/tests/test_exclusions.py`:

```python
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2sign import _should_exclude_header

def test_delivered_to_excluded():
    assert _should_exclude_header(b"delivered-to")
```

- [ ] **Step 2: Run, expect fail**

Run: `cd /Users/brong/src/interop/python && venv/bin/python -m pytest tests/test_exclusions.py -q`
Expected: FAIL.

- [ ] **Step 3: Add to the set** at `dkim2sign.py:95`:

```python
_EXCLUDED_NAMES = {b"received", b"return-path", b"message-instance",
                   b"dkim2-signature", b"dkim-signature",
                   b"delivered-to",
                   b"authentication-results"}
```

- [ ] **Step 4: Run, expect pass**

Run: `cd /Users/brong/src/interop/python && venv/bin/python -m pytest tests/test_exclusions.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add python/dkim2sign.py python/tests/test_exclusions.py && \
  git commit -m "python: ignore Delivered-To in header hash (draft-03 §4.1)"
```

### Task 1.4: Perl — add `delivered-to` to `should_skip` (also fixes Sympa)

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Common.pm:45-56` and the POD list at `Common.pm:400-405`
- Test: `brong/t/common.t`

- [ ] **Step 1: Add the failing assertion** to `brong/t/common.t`:

```perl
ok(Mail::DKIM2::Common::should_skip('Delivered-To'), 'Delivered-To skipped (draft-03 §4.1)');
```

- [ ] **Step 2: Run, expect fail**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/common.t`
Expected: FAIL on the new assertion.

- [ ] **Step 3: Add the rule** at `Common.pm:48` (after `return-path`):

```perl
    return 1 if $hname eq 'return-path';
    return 1 if $hname eq 'delivered-to';
```

Update the POD excluded-headers list at `Common.pm:400-405` to mention `Delivered-To`.

- [ ] **Step 4: Run, expect pass**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/common.t`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add brong/lib/Mail/DKIM2/Common.pm brong/t/common.t && \
  git commit -m "perl: ignore Delivered-To in header hash (draft-03 §4.1)"
```

### Task 1.5: Mailman — add `delivered-to` to `_EXCLUDED_NAMES`

**Files:**
- Modify: `src/mailman/handlers/message_instance.py:74-90` (in the `~/src/mailman` repo)
- Test: `src/mailman/handlers/tests/test_message_instance.py`

- [ ] **Step 1: Write the failing test** in `test_message_instance.py`:

```python
def test_delivered_to_excluded(self):
    from mailman.handlers.message_instance import _should_exclude_header
    self.assertTrue(_should_exclude_header('delivered-to'))
```

- [ ] **Step 2: Run, expect fail**

Run: `cd /Users/brong/src/mailman && tox -e py3-nocov -- mailman.handlers.tests.test_message_instance.<TestClass>.test_delivered_to_excluded`
Expected: FAIL.

- [ ] **Step 3: Add to `_EXCLUDED_NAMES`** at `message_instance.py:74-90`:

```python
_EXCLUDED_NAMES = {'received', 'return-path', 'message-instance',
                   'dkim2-signature', 'dkim-signature',
                   'delivered-to',
                   'authentication-results'}
```

- [ ] **Step 4: Run, expect pass**, then commit in the mailman repo:

```bash
cd /Users/brong/src/mailman && git add src/mailman/handlers/message_instance.py src/mailman/handlers/tests/test_message_instance.py && \
  git commit -m "dkim2: ignore Delivered-To in header hash (draft-03 §4.1)"
```

---

## Phase 2: Remove null header-recipe support

Under -03 the `"h"` recipe value can no longer be null. Implementations must (a) never *emit* `"h": null`, and (b) treat a parsed `"h": null` as a syntax error (PERMERROR). The null **body** recipe (`"b": null`) is unchanged and must be retained. The only implementation with active null-`h` machinery is Perl; the others need at most a tightening + a guard test.

### Task 2.1: Perl — drop null-header-recipe emit, reject on parse

**Files:**
- Modify: `brong/lib/Mail/DKIM2/MessageInstance.pm:84-87` (`unrecoverable`), `:183-205` (parse), and remove any `rh_null` emit path
- Test: `brong/t/mi-null-recipe.t`

**Interfaces:**
- Produces: parsing an MI whose `r=` decodes to `{"h": null}` `die`s with a message containing `header recipes are null` (caught upstream → PERMERROR). `{"b": null}` still parses and sets `rb_null`.
- `unrecoverable()` reflects body-only (`rb_null`); header recipes are never null.

- [ ] **Step 1: Update the test** `brong/t/mi-null-recipe.t`. Keep the existing `"b": null` round-trip assertion. Add:

```perl
use Test::More;
# parsing "h": null must now be rejected (draft-03 removed null header recipes)
my $bad = Mail::DKIM2::MessageInstance->new;
eval { $bad->_parse_recipe_json('{"h":null}') };  # use whatever the internal entry point is
like($@, qr/header recipes? (?:are|is) null/i, '"h": null rejected (draft-03 §5.1)');
# "b": null still allowed
my $ok = Mail::DKIM2::MessageInstance->new;
ok(eval { $ok->_parse_recipe_json('{"b":null}'); 1 }, '"b": null still accepted');
```

If `MessageInstance` has no public `_parse_recipe_json`, drive it through the existing parse path used by the current test (the existing test already builds an MI from a header string — reuse that route).

- [ ] **Step 2: Run, expect fail**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/mi-null-recipe.t`
Expected: FAIL (currently null `h` is silently accepted as `rh_null`).

- [ ] **Step 3: Change the parse branch** at `MessageInstance.pm:194-203`. Replace the `else { $self->{bits}{rh_null} = 1; }` with a hard error:

```perl
    if (exists $recipe_data->{h}) {
        if (defined $recipe_data->{h} && ref($recipe_data->{h}) eq 'HASH' && keys %{$recipe_data->{h}}) {
            my %rh;
            for my $h (keys %{$recipe_data->{h}}) {
                $rh{$h} = _decode_recipe_list($recipe_data->{h}{$h});
            }
            $self->{bits}{rh} = \%rh;
        } else {
            # draft-03 §5.1: null/empty header recipes are no longer permitted.
            Carp::croak "header recipes are null: cannot occur under draft-03";
        }
    }
```

Remove `rh_null` from `unrecoverable()` at `:84-87`:

```perl
sub unrecoverable {
    my ($self) = @_;
    return $self->{bits}{rb_null} ? 1 : 0;
}
```

Grep for any code that *sets* `rh_null` or a `set_null_header_recipe`; delete it. (`set_null_body_recipe` stays.)

- [ ] **Step 4: Run the full MI suite, expect pass**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/mi-null-recipe.t && make test`
Expected: PASS; no other test regresses.

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add brong/lib/Mail/DKIM2/MessageInstance.pm brong/t/mi-null-recipe.t && \
  git commit -m "perl: reject null header recipes; keep null body recipe (draft-03 §5.1)"
```

### Task 2.2: Python — reject parsed `"h": null` (already raises on undo; tighten verify)

**Files:**
- Modify: `python/dkim2undo.py:139-140` and `:322-338`; `python/dkim2verify.py:543-549`
- Test: `python/tests/test_null_recipe.py` (create)

- [ ] **Step 1: Write the failing test** `python/tests/test_null_recipe.py`:

```python
import sys, os, json, base64
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2undo import undo_message_instance  # adjust to actual signature

def _mi(recipe):
    b = base64.b64encode(json.dumps(recipe).encode()).decode()
    return f"m=2; r={b}; h=sha256:...:..."

def test_null_h_is_error():
    import pytest
    with pytest.raises(ValueError):
        # an MI carrying "h": null must be rejected
        undo_message_instance(_mi({"h": None}), b"")  # adjust args to real API
```

- [ ] **Step 2: Run, expect fail-or-error-shape** and adjust the call to the real `undo_message_instance` signature discovered in the file. The intent: `"h": null` → `ValueError`.

Run: `cd /Users/brong/src/interop/python && venv/bin/python -m pytest tests/test_null_recipe.py -q`

- [ ] **Step 3: Ensure the guard is explicit.** At `dkim2undo.py:322-338`, the dead `elif h_recipes is None` branch after `if h_recipes is not None` never runs; rewrite to reject null at the top:

```python
    h_recipes = recipes.get("h")
    if "h" in recipes and h_recipes is None:
        raise ValueError(f"v={version}: header recipes are null — not permitted under draft-03")
    if h_recipes is not None:
        ...
```

At `dkim2verify.py:543-549`, leave the `if h_recipes and isinstance(h_recipes, dict)` guard; a null `h` will now already have raised during the undo path. Confirm no path silently emits `"h": null` in `dkim2sign.py` (it doesn't — it only emits provided recipes).

- [ ] **Step 4: Run, expect pass**

Run: `cd /Users/brong/src/interop/python && venv/bin/python -m pytest tests/test_null_recipe.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add python/dkim2undo.py python/tests/test_null_recipe.py && \
  git commit -m "python: reject null header recipes (draft-03 §5.1)"
```

### Task 2.3: C & Go — add guard tests (no behavior change needed)

**Files:**
- C: `c/dkim2_recipe.c:140-141` — make the null check explicit
- Go: `go/dkim2/recipe_test.go` (create)

- [ ] **Step 1: C — make the reject explicit** at `dkim2_recipe.c:140-141`:

```c
    cJSON *h = cJSON_GetObjectItemCaseSensitive(root, "h");
    if (h && cJSON_IsNull(h)) {
        /* draft-03 §5.1: null header recipe no longer permitted */
        return DKIM2_ERR_RECIPE_NULL_H;   /* or existing parse-error code */
    }
    if (!h || !cJSON_IsObject(h)) {
        ...
    }
```

Add `DKIM2_ERR_RECIPE_NULL_H` to the error enum if one exists, else return the generic recipe-parse error code already used in that function. Rebuild: `cd /Users/brong/src/interop/c && make`.

- [ ] **Step 2: Go — add a guard test** `go/dkim2/recipe_test.go`:

```go
package dkim2

import "testing"

func TestNullHeaderRecipeRejected(t *testing.T) {
	_, err := parseRecipe([]byte(`{"h":null,"b":[{"c":[1,1]}]}`))
	if err == nil {
		t.Fatal("null header recipe must be rejected (draft-03 §5.1)")
	}
}
```

If `parseRecipe` currently tolerates `"h": null` (decodes to a nil map), add a post-unmarshal check in `recipe.go:17-23`:

```go
func parseRecipe(b []byte) (*Recipe, error) {
	// draft-03 §5.1: an explicit JSON null for "h" is invalid.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err == nil {
		if v, ok := probe["h"]; ok && string(v) == "null" {
			return nil, fmt.Errorf("null header recipe not permitted (draft-03 §5.1)")
		}
	}
	var r Recipe
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
```

- [ ] **Step 3: Run both, expect pass**

Run: `cd /Users/brong/src/interop/go && go test ./dkim2/ -run TestNullHeaderRecipeRejected && cd ../c && make`
Expected: PASS / clean build.

- [ ] **Step 4: Commit**

```bash
cd /Users/brong/src/interop && git add go/dkim2/recipe.go go/dkim2/recipe_test.go c/dkim2_recipe.c && \
  git commit -m "c,go: reject null header recipes (draft-03 §5.1)"
```

### Task 2.4: Mailman — guard test (never emits null h; confirm)

**Files:**
- Test: `src/mailman/handlers/tests/test_message_instance.py`

- [ ] **Step 1: Add a test** asserting that when only the body changes, the emitted recipe has no `"h"` key (rather than `"h": null`), and when headers change a non-empty `"h"` dict is present:

```python
def test_no_null_h_recipe(self):
    # body-only change → recipe dict must not contain "h": None
    recipe = compute_recipe_for(orig, body_only_modified)  # use the module's real helper
    self.assertNotIn(None, [recipe.get('h')])  # never null
```

Adjust to the real helper names (`compute_header_recipe`/`build_mi_header_value`). The handler already returns `None` for an absent recipe and omits the tag, so this should pass without code change — it is a regression guard.

- [ ] **Step 2: Run, expect pass; commit** in the mailman repo:

```bash
cd /Users/brong/src/mailman && git add src/mailman/handlers/tests/test_message_instance.py && \
  git commit -m "dkim2: guard against null header recipe (draft-03 §5.1)"
```

---

## Phase 3: `nd=` tag — parse, validate, verify chain, and emit

This is the largest semantic change. For each of the four full implementations: add `nd=` parsing/serialization, enforce the new required-tag rule (`i m t d s` + (`nd` XOR (`mf`+`rt`))), add the verifier check (`nd=` must equal the next sig's `d=`), and let the signer emit `nd=` for imaginary forwarding hops instead of fabricating `mf=`/`rt=` values. Mailman/Sympa do not parse DKIM2-Signature and are unaffected.

### Task 3.1: Go — `nd=` field, parse, required-tag rule

**Files:**
- Modify: `go/dkim2/signature.go` (struct + `parseSig` + `String`)
- Test: `go/dkim2/signature_test.go` (create/extend)

**Interfaces:**
- Produces: `DKIM2Signature.NextDomain string` (the `nd=` value, "" if absent). `parseSig` enforces the -03 required-tag rule and the `nd` XOR `mf`/`rt` mutual exclusion.

- [ ] **Step 1: Write failing tests** `go/dkim2/signature_test.go`:

```go
package dkim2

import "testing"

func sig(s string) (*DKIM2Signature, error) { return parseSig("DKIM2-Signature:" + s) }

func TestNDParsed(t *testing.T) {
	s, err := sig(" i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; s=sel:rsa-sha256:AAA")
	if err != nil { t.Fatal(err) }
	if s.NextDomain != "mx.dest.example" { t.Fatalf("nd=%q", s.NextDomain) }
}

func TestNDAndMFMutuallyExclusive(t *testing.T) {
	_, err := sig(" i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; mf=PA==; rt=PA==; s=sel:rsa-sha256:AAA")
	if err == nil { t.Fatal("nd= with mf=/rt= must be rejected") }
}

func TestMissingChainTags(t *testing.T) {
	_, err := sig(" i=2; m=2; t=1; d=fwd.example; s=sel:rsa-sha256:AAA")
	if err == nil { t.Fatal("must require nd= or mf=+rt=") }
}

func TestRequiredCoreTags(t *testing.T) {
	_, err := sig(" m=2; t=1; d=fwd.example; nd=x.example; s=sel:rsa-sha256:AAA") // no i=
	if err == nil { t.Fatal("must require i=") }
}
```

- [ ] **Step 2: Run, expect fail**

Run: `cd /Users/brong/src/interop/go && go test ./dkim2/ -run 'TestND|TestMissing|TestRequired'`
Expected: FAIL (field/checks absent).

- [ ] **Step 3: Add the field** to the `DKIM2Signature` struct (in signature.go where `Domain`, `MailFrom` etc. are declared):

```go
	NextDomain string // nd= tag (draft-03 §8.7); empty if absent
```

Add parsing after the `d=` line (`signature.go:84`):

```go
	sig.Domain = tvl.get("d")
	sig.NextDomain = tvl.get("nd")
```

Replace the trailing required-tag block (`signature.go:131-136`) with the -03 rule:

```go
	// draft-03 §8: i= m= t= d= s= required; plus either nd= or both mf=+rt=.
	if !tvl.has("i") || !tvl.has("m") || !tvl.has("t") {
		return nil, fmt.Errorf("missing required i=/m=/t= tag in DKIM2-Signature")
	}
	if sig.Domain == "" {
		return nil, fmt.Errorf("missing required d= tag in DKIM2-Signature")
	}
	if len(sig.Sigs) == 0 {
		return nil, fmt.Errorf("missing required s= tag in DKIM2-Signature")
	}
	hasND := sig.NextDomain != ""
	hasMF := tvl.has("mf")
	hasRT := tvl.has("rt")
	if hasND && (hasMF || hasRT) {
		return nil, fmt.Errorf("DKIM2-Signature i=%d tag=nd was unexpected: nd= excludes mf=/rt=", sig.Sequence)
	}
	if !hasND && !(hasMF && hasRT) {
		return nil, fmt.Errorf("DKIM2-Signature i=%d missing chain tags: need nd= or both mf=+rt=", sig.Sequence)
	}
```

Add a `has` method to the tag-value list in `tagvalue.go` (next to `get`):

```go
func (t *tagValueList) has(key string) bool { _, ok := t.m[key]; return ok }
```

(Adjust `t.m` to the actual map field name in `tagValueList`.)

Add `nd=` to the `String()` serializer: emit `; nd=<domain>` when `NextDomain != ""`, and skip `mf=`/`rt=` in that case.

- [ ] **Step 4: Run, expect pass**

Run: `cd /Users/brong/src/interop/go && go test ./dkim2/`
Expected: PASS (all, including pre-existing).

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add go/dkim2/signature.go go/dkim2/tagvalue.go go/dkim2/signature_test.go && \
  git commit -m "go: parse nd= tag + draft-03 required-tag rule (§8)"
```

### Task 3.2: Go — verifier `nd=` chain-match + skip mf/rt check for nd hops

**Files:**
- Modify: `go/dkim2/verify.go:180-207` (chain-of-custody loop)
- Test: `go/dkim2/verify_test.go` or `verifyfull_test.go`

**Interfaces:**
- Consumes: `DKIM2Signature.NextDomain` from Task 3.1.
- Produces: chain check accepts an `nd=` hop when `nd=` equals the next sig's `d=`; rejects on mismatch with `DKIM2-Signature i=<x> nd= does not match`.

- [ ] **Step 1: Write a failing test** building a 2-sig chain where sig i=1 uses `nd=` equal to sig i=2's `d=` (should verify), and a variant where it differs (should fail). Use the existing chain-build helpers in `verifyfull_test.go`.

- [ ] **Step 2: Run, expect fail**

- [ ] **Step 3: Update the chain loop** at `verify.go:180-207`. Currently it matches each sig's `mf=` domain against the previous sig's `rt=`. Add nd handling: when the *previous* sig carries `nd=`, require it to equal the current sig's `d=` instead of the mf/rt match:

```go
		for idx := 1; idx < len(parsedSigs); idx++ {
			cur := parsedSigs[idx]
			prev := parsedSigs[idx-1]
			if cur == nil || prev == nil {
				continue
			}
			if prev.NextDomain != "" {
				// draft-03 §11.4: nd= must exactly match the next sig's d=.
				if !strings.EqualFold(prev.NextDomain, cur.Domain) {
					return nil, fmt.Errorf("DKIM2-Signature i=%d nd= does not match d= of i=%d", prev.Sequence, cur.Sequence)
				}
				continue
			}
			curMFDomain := domainFromAddr(cur.MailFrom)
			if curMFDomain == "" {
				continue // null sender (DSN)
			}
			... // existing rt= match unchanged
		}
```

- [ ] **Step 4: Run, expect pass**

Run: `cd /Users/brong/src/interop/go && go test ./dkim2/`

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add go/dkim2/verify.go go/dkim2/*_test.go && \
  git commit -m "go: verify nd= chain-of-custody match (draft-03 §11.4)"
```

### Task 3.3: Go — signer emits `nd=` for imaginary hops

**Files:**
- Modify: `go/dkim2/sign.go` (and `go/cmd/dkim2sign` flag wiring)
- Test: `go/dkim2/sign_test.go`

- [ ] **Step 1: Write a failing test** asserting that signing a forwarded message with an imaginary-hop option produces a fabricated DKIM2-Signature carrying `nd=<next-domain>` and no `mf=`/`rt=`.

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Add an option** to the sign API, e.g. a `NextDomain string` field on the sign options struct. When set, the fabricated chain-of-custody signature emits `nd=NextDomain` and omits `mf=`/`rt=`. Wire a `-nd <domain>` flag in `go/cmd/dkim2sign/main.go`.

- [ ] **Step 4: Run, expect pass.**

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add go/dkim2/sign.go go/cmd/dkim2sign/main.go go/dkim2/sign_test.go && \
  git commit -m "go: emit nd= for imaginary forwarding hops (draft-03 §9.3)"
```

### Task 3.4: Python — `nd=` parse + required-tag rule

**Files:**
- Modify: `python/dkim2verify.py:215-224` (required-tag check) and add `nd=` extraction alongside `mf=`/`rt=` (`:437-438`, `:482-483`)
- Test: `python/tests/test_nd_tag.py` (create)

- [ ] **Step 1: Write failing tests** `python/tests/test_nd_tag.py` covering: `nd=` extracted; `nd=` with `mf=`/`rt=` → error; missing both → error; missing `i/m/t/d/s` → error. Drive through `verify_dkim2_signature` (adjust to the real entry point).

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Update `verify_dkim2_signature`** at `dkim2verify.py:215-224`:

```python
    i_val = _extract_tag(value, "i")
    m_val = _extract_tag(value, "m")
    t_val = _extract_tag(value, "t")
    d_val = _extract_tag(value, "d")
    s_tag = _extract_tag(value, "s")
    nd_val = _extract_tag(value, "nd")
    mf_val = _extract_tag(value, "mf")
    rt_val = _extract_tag(value, "rt")

    if not all([i_val, m_val, t_val, d_val, s_tag]):
        return [f"DKIM2-Signature i={i_val}: missing required tag(s)"]
    if nd_val and (mf_val or rt_val):
        return [f"DKIM2-Signature i={i_val} tag=nd was unexpected: nd= excludes mf=/rt="]
    if not nd_val and not (mf_val and rt_val):
        return [f"DKIM2-Signature i={i_val}: missing chain tags (need nd= or mf=+rt=)"]
```

Add `nd=` extraction where `mf`/`rt` are read for chain checks (`:437-438` and `:482-483`).

- [ ] **Step 4: Run, expect pass.**

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add python/dkim2verify.py python/tests/test_nd_tag.py && \
  git commit -m "python: parse nd= + draft-03 required-tag rule (§8)"
```

### Task 3.5: Python — verifier `nd=` chain match + signer emit

**Files:**
- Modify: `python/dkim2verify.py:434-455` & `:478-500` (chain check); `python/dkim2sign.py:348-374` (emit)
- Test: `python/tests/test_nd_tag.py`

- [ ] **Step 1: Extend tests** with a 2-hop chain: `nd=` matching next `d=` verifies; mismatch → error string `nd= does not match`.

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: In the chain-of-custody check**, when the lower-`i=` signature has `nd=`, require it to equal the next signature's `d=` (case-insensitive) and skip the `mf=`/`rt=` match for that hop. In `dkim2sign.py:348-374`, add an optional `next_domain` parameter to the chain-of-custody signature builder; when present emit `nd=` and omit `mf=`/`rt=`. Add a `--nd <domain>` CLI flag.

- [ ] **Step 4: Run, expect pass.**

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add python/dkim2verify.py python/dkim2sign.py python/tests/test_nd_tag.py && \
  git commit -m "python: verify + emit nd= (draft-03 §9.3, §11.4)"
```

### Task 3.6: Perl — `nd=` accessor, parse, required-tag rule

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Signature.pm` (add `next_domain` accessor after `domain`, line ~91; add `Nd`/`NextDomain` to constructor `:19-54`); `brong/lib/Mail/DKIM2/Verifier.pm` (required-tag validation)
- Test: `brong/t/signature-nd.t` (create)

**Interfaces:**
- Produces: `$sig->next_domain` returns the `nd=` value or undef. Constructor accepts `NextDomain => 'mx.dest.example'`.

- [ ] **Step 1: Write failing test** `brong/t/signature-nd.t`:

```perl
use Test::More;
use Mail::DKIM2::Signature;
my $s = Mail::DKIM2::Signature->parse('DKIM2-Signature: i=2; m=2; t=1; d=fwd.example; nd=mx.dest.example; s=sel:rsa-sha256:AAA');
is($s->next_domain, 'mx.dest.example', 'nd= accessor');
my $built = Mail::DKIM2::Signature->new(Sequence=>2, Version=>2, Timestamp=>1, Domain=>'fwd.example', NextDomain=>'mx.dest.example');
like($built->as_string // $built->to_string, qr/nd=mx\.dest\.example/, 'nd= serialized');
done_testing;
```

(Use whichever serializer method exists — match the existing test style in `t/`.)

- [ ] **Step 2: Run, expect fail.**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/signature-nd.t`

- [ ] **Step 3: Add the accessor** to `Signature.pm` after `domain` (line ~91):

```perl
sub next_domain {
    my $self = shift;
    if (@_) { $self->set_tag('nd', shift) }
    return $self->get_tag('nd');
}
```

Add to the constructor `:19-54`:

```perl
    $self->set_tag('nd', $args{NextDomain}) if defined $args{NextDomain};
```

In `Verifier.pm`, add a per-signature required-tag/mutual-exclusion validation (new helper `_validate_sig_tags($sig, $i)`) called where each sig is processed (around `:99-130`):

```perl
sub _validate_sig_tags {
    my ($self, $sig, $i) = @_;
    for my $t (qw(i m t d s)) {
        unless (defined $sig->get_tag($t)) {
            $self->{result} = 'permerror';
            $self->{details} = "DKIM2-Signature i=$i tag=$t missing";
            return 0;
        }
    }
    my $nd = $sig->get_tag('nd');
    my $mf = $sig->get_tag('mf');
    my $rt = $sig->get_tag('rt');
    if (defined $nd && (defined $mf || defined $rt)) {
        $self->{result} = 'permerror';
        $self->{details} = "DKIM2-Signature i=$i tag=nd was unexpected";
        return 0;
    }
    unless (defined $nd || (defined $mf && defined $rt)) {
        $self->{result} = 'permerror';
        $self->{details} = "DKIM2-Signature i=$i missing chain tags (nd= or mf=+rt=)";
        return 0;
    }
    return 1;
}
```

- [ ] **Step 4: Run, expect pass.**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/signature-nd.t && make test`

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add brong/lib/Mail/DKIM2/Signature.pm brong/lib/Mail/DKIM2/Verifier.pm brong/t/signature-nd.t && \
  git commit -m "perl: nd= accessor + draft-03 required-tag validation (§8)"
```

### Task 3.7: Perl — verifier `nd=` chain match + Signer/Reflector emit

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Verifier.pm` (chain check around `:290-300`); `brong/lib/Mail/DKIM2/Signer.pm` (emit option); `brong/lib/Mail/DKIM2/Reflector.pm` (use nd= for the imaginary hop it fabricates)
- Test: `brong/t/full-chain.t`, `brong/t/reflector.t`

**Interfaces:**
- Consumes: `$sig->next_domain` (Task 3.6).
- Produces: Signer accepts `NextDomain => $d`; when set the fabricated chain-of-custody signature carries `nd=` and omits `mf=`/`rt=`. Verifier checks `nd=` equals next sig `d=`.

- [ ] **Step 1: Write failing tests** in `t/full-chain.t`: a fabricated `nd=` hop verifies when `nd=` equals the next sig `d=`, fails on mismatch (`details` matches `/nd= does not match/`).

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Verifier** — in the chain walk, when a signature has `nd=`, require it equals the next (higher `i=`) signature's `d=` (relaxed-match not required — spec says *exactly match*), and skip the `mf=`/`rt=` chain match for that hop. **Signer** — add a `NextDomain` arg; the imaginary-hop signature it generates emits `nd=` instead of fabricated `mf=`/`rt=`. **Reflector** — where it currently fabricates an imaginary hop for forwarding (the chain-of-custody signature), prefer `nd=` (set to the reflector's own outgoing `d=`).

- [ ] **Step 4: Run, expect pass.**

Run: `cd /Users/brong/src/interop/brong && make test`

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add brong/lib/Mail/DKIM2/{Verifier,Signer,Reflector}.pm brong/t/full-chain.t brong/t/reflector.t && \
  git commit -m "perl: verify + emit nd= for imaginary hops (draft-03 §9.3, §11.4)"
```

### Task 3.8: C — `nd=` parse, struct, required-tag rule

**Files:**
- Modify: `c/dkim2_internal.h` (struct field), `c/dkim2_header.c:142-174` (parse) and `:208-234` (format)
- Test: ad-hoc driver (see Step 4) — C has no unit harness

**Interfaces:**
- Produces: `dkim2_sig` gains `char *nd;`. `dkim2_sig_parse` enforces -03 required-tag + mutual-exclusion, returning the existing parse-error path on violation.

- [ ] **Step 1: Add the struct field** to `dkim2_internal.h` near `flags`:

```c
    char *nd;               /* nd= next-domain (draft-03 §8.7), NULL if absent */
```

- [ ] **Step 2: Rework the parser** at `dkim2_header.c:142-174`. Keep `i/m/t/d/s` as required via `REQ`. Make `mf`/`rt` conditional, and add `nd`:

```c
    REQ("i"); sig->i = atoi(v);
    REQ("m"); sig->m = atoi(v);
    REQ("t"); sig->t = (uint64_t)strtoull(v, NULL, 10);
    REQ("d"); sig->d = strdup(v);

    const char *nd = tag_get(tl, "nd");
    const char *mf = tag_get(tl, "mf");
    const char *rt = tag_get(tl, "rt");
    if (nd && (mf || rt)) goto err;          /* nd= excludes mf=/rt= */
    if (!nd && !(mf && rt)) goto err;        /* need nd= or both mf=+rt= */
    if (nd) sig->nd = strdup(nd);
    if (mf) {
        unsigned char dec[512]; int n = b64_decode(mf, dec, sizeof dec);
        if (n < 0) goto err;
        sig->mf = malloc((size_t)n + 1); memcpy(sig->mf, dec, (size_t)n); sig->mf[n] = '\0';
    }
    if (rt) { int nrt = 0; sig->rt = parse_rt(rt, &nrt); if (!sig->rt) goto err; }
    REQ("s");
    if (parse_ssets(v, &sig->ssets, &sig->n_ssets) < 0) goto err;
```

Add `nd=` to the formatter at `:208-234` (emit `; nd=%s` when `sig->nd`, and never emit `mf=`/`rt=` when `nd` is set). Free `sig->nd` in the free function (`:188`).

- [ ] **Step 3: Rebuild**

Run: `cd /Users/brong/src/interop/c && make`
Expected: clean build.

- [ ] **Step 4: Round-trip check** with `debug_verify` on a hand-built two-sig message using `nd=`; confirm parse succeeds and a mismatch fails. Commit:

```bash
cd /Users/brong/src/interop && git add c/dkim2_internal.h c/dkim2_header.c && \
  git commit -m "c: parse/format nd= + draft-03 required-tag rule (§8)"
```

### Task 3.9: C — verifier `nd=` chain match + signer emit

**Files:**
- Modify: `c/dkim2_verify.c:405-437` (chain check); `c/dkim2_sign.c` (emit path); add new error string
- Test: `debug_verify` driver

- [ ] **Step 1: Chain check** — in `dkim2_verify.c`, where adjacent sigs are validated, when the lower-`i=` sig has `nd`, require `strcasecmp(prev->nd, cur->d) == 0`, else:

```c
SETSTATUS(DKIM2_PERMERROR, "PERMERROR: DKIM2-Signature i=%d nd= does not match d= of i=%d", prev->i, cur->i);
```

and skip the `mf`/`rt` match for that hop.

- [ ] **Step 2: Signer emit** — in `dkim2_sign.c`, where the imaginary-hop signature is fabricated (if implemented; if not, add an option `nd` to the sign context) emit `nd=` and omit `mf=`/`rt=`.

- [ ] **Step 3: Rebuild + driver check.** Commit:

```bash
cd /Users/brong/src/interop && git add c/dkim2_verify.c c/dkim2_sign.c && \
  git commit -m "c: verify + emit nd= for imaginary hops (draft-03 §9.3, §11.4)"
```

---

## Phase 4: `feedhere` flag + full flag infrastructure

Go and Perl already parse `f=` generically and only enforce `donotmodify`/`donotexplode`. C and Python have no flag parsing at all; add it. `feedhere` and `feedback` are recognized but carry no enforcement (round-trip only).

### Task 4.1: Go — recognize `feedhere` (no-op enforcement)

**Files:**
- Modify: `go/dkim2/verify.go:209-249` (flag switch) — add a no-op `case "feedhere":` / `case "feedback":` so unknown-flag tooling doesn't warn
- Test: `go/dkim2/verify_test.go`

- [ ] **Step 1: Test** that a signature with `f=feedhere` parses and verifies without error and the flag is preserved on `String()`.
- [ ] **Step 2: Run, expect pass already** (generic parse handles it). If a default branch warns on unknown flags, add explicit no-op cases for `feedback`/`feedhere`.
- [ ] **Step 3: Commit**

```bash
cd /Users/brong/src/interop && git add go/dkim2/verify.go go/dkim2/verify_test.go && \
  git commit -m "go: recognize feedhere/feedback flags (draft-03 §8.10)"
```

### Task 4.2: Perl — recognize `feedhere` (no-op enforcement)

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Verifier.pm` (after the existing flag checks, ~`:173`) — document `feedhere`/`feedback` as recognized-but-unenforced
- Test: `brong/t/verifier_flags.t`

- [ ] **Step 1: Test** that `f=feedhere,feedback` round-trips through `Signature->flags` as `['feedhere','feedback']` and the verifier neither errors nor enforces.
- [ ] **Step 2: Run, expect pass** (generic split already works); add a comment block listing the full -03 flag set near the enforcement checks.
- [ ] **Step 3: Commit**

```bash
cd /Users/brong/src/interop && git add brong/lib/Mail/DKIM2/Verifier.pm brong/t/verifier_flags.t && \
  git commit -m "perl: recognize feedhere/feedback flags (draft-03 §8.10)"
```

### Task 4.3: C — add `f=` flag parsing/formatting incl. `feedhere`

**Files:**
- Modify: `c/dkim2_header.c` (add `parse_flags`, call after `nd=` parse, add to formatter)
- Test: `debug_verify` driver

**Interfaces:**
- Produces: `sig->flags` (the existing `char **flags` NULL-terminated array) is populated from `f=`; flags round-trip on format. No enforcement is added.

- [ ] **Step 1: Implement `parse_flags`** (modeled on `parse_rt` at `dkim2_header.c:87-112`) splitting on `,` (stripping WSP), returning a NULL-terminated `char **`. Recognize any token; this is a list, not validated.

- [ ] **Step 2: Call it** in `dkim2_sig_parse` after the `nd=` block:

```c
    const char *f = tag_get(tl, "f");
    if (f) { int nf = 0; sig->flags = parse_flags(f, &nf); if (!sig->flags) goto err; }
```

- [ ] **Step 3: Format** — at `:208-234`, after the `n=` output:

```c
    if (sig->flags)
        for (int k = 0; sig->flags[k]; k++)
            pos += snprintf(buf + pos, sizeof(buf) - pos, "%s%s", (k == 0 ? "; f=" : ","), sig->flags[k]);
```

(The free path at `:188` already frees `sig->flags`.)

- [ ] **Step 4: Rebuild + driver round-trip** of `f=donotmodify,feedhere`. Commit:

```bash
cd /Users/brong/src/interop && git add c/dkim2_header.c && \
  git commit -m "c: parse/format f= flags incl. feedhere (draft-03 §8.10)"
```

### Task 4.4: Python — add `f=` flag parsing/serialization incl. `feedhere`

**Files:**
- Modify: `python/dkim2verify.py` (extract `f=` after `n=`, ~`:227`); `python/dkim2sign.py:348-374` (emit `f=` when flags provided)
- Test: `python/tests/test_flags.py` (create)

- [ ] **Step 1: Failing test** `python/tests/test_flags.py`: building a signature with `flags=['feedhere']` emits `f=feedhere`; verifying a message with `f=donotmodify,feedhere` parses the flag list and enforces only `donotmodify`.

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Parse** in `verify_dkim2_signature` after the `n=` extraction:

```python
    f_val = _extract_tag(value, "f")
    flags = [x.strip() for x in f_val.split(",")] if f_val else []
```

Enforce only `donotmodify`/`donotexplode` (mirror the Go logic); `feedback`/`feedhere`/`exploded` are recognized without action here. In `dkim2sign.py:348-374`, append `; f=<joined>` when a `flags` list is supplied.

- [ ] **Step 4: Run, expect pass. Commit**

```bash
cd /Users/brong/src/interop && git add python/dkim2verify.py python/dkim2sign.py python/tests/test_flags.py && \
  git commit -m "python: parse/emit f= flags incl. feedhere (draft-03 §8.10)"
```

---

## Phase 5: PERMERROR strings & "unexpected tag"

Most new strings were folded into Phase 3 (the `i=`-prefixed chain errors and `tag=nd was unexpected`). This phase aligns the remaining error text with the -03 wording and adds the generic "tag was unexpected" PERMERROR for tags that cannot co-occur.

### Task 5.1: Align verifier error strings across the 4 implementations

**Files:**
- Modify: `c/dkim2_verify.c` (chain/MAILFROM/RCPT errors → add `i=` prefix where missing), `go/dkim2/verify.go`, `python/dkim2verify.py`, `brong/lib/Mail/DKIM2/Verifier.pm`
- Test: per-impl existing verifier tests

- [ ] **Step 1: Per impl**, ensure chain-of-custody PERMERRORs carry the offending `i=` (most already do — Go uses bare messages in a couple of places). Match the -03 list:
  - `PERMERROR: DKIM2-Signature i=<x> MAIL FROM <value> did not match`
  - `PERMERROR: DKIM2-Signature i=<x> RCPT TO <value> did not match`
  - `PERMERROR: DKIM2-Signature i=<x> MAIL FROM and d= do not match`
  - `PERMERROR: DKIM2-Signature i=<x> nd= does not match`
  - `PERMERROR DKIM2-Signature i=<x> tag=<y> was unexpected`

- [ ] **Step 2: Update tests** that assert on the old strings (Python `_classify_status` keys on substrings like `did not match` — keep those substrings intact). Run each suite green.

- [ ] **Step 3: Commit** per repo:

```bash
cd /Users/brong/src/interop && git add c/dkim2_verify.c go/dkim2/verify.go python/dkim2verify.py brong/lib/Mail/DKIM2/Verifier.pm && \
  git commit -m "all: align verifier PERMERROR strings with draft-03 §11"
```

---

## Phase 6: DSN propagation (RFC 3462 model)

Implement DSN *propagation* by a Forwarder per -03 §12.1.1. No implementation has DSN code today, so this is new. The deployed path is Perl (the reflector handles bounce addresses), so Perl is primary; Python and Go get reference implementations (both have MIME libraries); C gets a focused implementation using its existing parser plus a minimal multipart split.

**Shared algorithm (§12.1.1):** given an inbound DKIM2-signed DSN that this Forwarder received, to propagate it upstream:
1. Verify the enclosed original message (or its headers) chain.
2. Rebuild the enclosed message to the state it was in **when this Forwarder forwarded it outward**: undo this Forwarder's outward header/body modifications using the Message-Instance recipe it added, then **remove** that Message-Instance header and the DKIM2-Signature header this Forwarder added.
3. If the body cannot be regenerated (outward change used a null body recipe), drop the body and emit a `text/rfc822-headers` part instead of `message/rfc822`.
4. Rewrite the human-readable first part to strip destination-specific detail.
5. Address the new DSN to the MAIL FROM of the now-highest DKIM2-Signature; the new DSN is a fresh message: exactly one Message-Instance (v=1) and one DKIM2-Signature, signed by this Forwarder with MAIL FROM `<>`.

### Task 6.1: Perl — `Mail::DKIM2::DSN->propagate`

**Files:**
- Create: `brong/lib/Mail/DKIM2/DSN.pm`
- Modify: `brong/MANIFEST` (add the new module)
- Test: `brong/t/dsn-propagate.t` (create); fixture DSN under `brong/t/data/`

**Interfaces:**
- Produces: `Mail::DKIM2::DSN->propagate(\%args)` where args are `{ raw => $dsn_bytes, signer => $Mail_DKIM2_Signer, forwarder_domain => $d }`. Returns `{ raw => $new_dsn_bytes, upstream_mailfrom => $addr }` or dies with a PERMERROR-style message.

- [ ] **Step 1: Write the failing test** `brong/t/dsn-propagate.t`:

```perl
use Test::More;
use Mail::DKIM2::DSN;
my $dsn = do { local $/; open my $fh, '<', 't/data/inbound-dsn.eml'; <$fh> };
my $out = Mail::DKIM2::DSN->propagate({ raw => $dsn, forwarder_domain => 'fwd.example', signer => mk_test_signer() });
like($out->{raw}, qr{Content-Type:\s*multipart/report}i, 'still multipart/report');
is(scalar(() = $out->{raw} =~ /^DKIM2-Signature:/mig), 1, 'exactly one DKIM2-Signature (new message)');
is(scalar(() = $out->{raw} =~ /^Message-Instance:/mig), 1, 'exactly one Message-Instance');
ok($out->{upstream_mailfrom}, 'addressed to upstream MAIL FROM');
done_testing;
```

Create `t/data/inbound-dsn.eml`: a `multipart/report` DSN whose third part is a `message/rfc822` original carrying a 2-hop DKIM2 chain where the *top* hop is this forwarder (`fwd.example`) and includes an MI documenting an outward footer change.

- [ ] **Step 2: Run, expect fail** (module missing).

- [ ] **Step 3: Implement `DSN.pm`.** Parse the `multipart/report` with `Email::MIME` (already a dependency of the dist via Reflector) into its three parts. On the embedded original: parse the DKIM2 chain via `Mail::DKIM2::Verifier`/`MessageInstance`; identify the forwarder's own top signature (its `d=` equals `forwarder_domain`); undo that hop's MI recipe via `MessageInstance->undo` to restore outward-state, then strip that MI + that DKIM2-Signature. If the MI body recipe is a null body recipe → drop the body and re-encode the third part as `text/rfc822-headers`. Recompute `upstream_mailfrom` = MAIL FROM of the now-highest signature. Rebuild the DSN as a fresh message, then sign it with the supplied `$signer` using MAIL FROM `<>` (one MI v=1, one DKIM2-Signature). Return `{ raw, upstream_mailfrom }`.

- [ ] **Step 4: Run, expect pass.**

Run: `cd /Users/brong/src/interop/brong && perl -Ilib t/dsn-propagate.t`

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop && git add brong/lib/Mail/DKIM2/DSN.pm brong/t/dsn-propagate.t brong/t/data/inbound-dsn.eml brong/MANIFEST && \
  git commit -m "perl: Mail::DKIM2::DSN->propagate (draft-03 §12.1.1)"
```

### Task 6.2: Perl — wire DSN propagation into the bounce path

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm` and/or `brong/bin/` bounce handler; `deploy/looper-forward` / `deploy/reflector-aliases` if a new bounce hook is needed
- Test: `brong/t/reflector.t`

- [ ] **Step 1: Test** that a DSN delivered to the reflector's bounce address is propagated via `DSN->propagate` and re-injected, addressed to the upstream MAIL FROM.
- [ ] **Step 2: Run, expect fail.**
- [ ] **Step 3: Wire** the bounce mailbox handler to call `Mail::DKIM2::DSN->propagate` and submit the result over the no-milter injector (`127.0.0.1:10588`, per SERVER.md §6). Gate behind a config flag so existing reflector tests are unaffected unless the DSN path is exercised.
- [ ] **Step 4: Run, expect pass. Commit.**

```bash
cd /Users/brong/src/interop && git add brong/lib/Mail/DKIM2/Reflector.pm brong/bin/ brong/t/reflector.t && \
  git commit -m "perl: propagate inbound DSNs through the reflector bounce path (draft-03 §12.1.1)"
```

### Task 6.3: Python — `dkim2dsn.py` propagate

**Files:**
- Create: `python/dkim2dsn.py`
- Test: `python/tests/test_dsn.py` (create); fixture reused from generation

- [ ] **Step 1: Failing test** `python/tests/test_dsn.py` mirroring 6.1's assertions, driving `dkim2dsn.propagate(raw_bytes, forwarder_domain=..., signer_key=...)`.
- [ ] **Step 2: Run, expect fail.**
- [ ] **Step 3: Implement** using stdlib `email` (`email.message_from_bytes`, `iter_parts`). Reuse `dkim2undo` for MI recipe undo and `dkim2sign` for the fresh signature. Same 5-step algorithm; emit `text/rfc822-headers` when the body can't be regenerated.
- [ ] **Step 4: Run, expect pass. Commit.**

```bash
cd /Users/brong/src/interop && git add python/dkim2dsn.py python/tests/test_dsn.py && \
  git commit -m "python: dkim2dsn.propagate (draft-03 §12.1.1)"
```

### Task 6.4: Go — DSN propagate

**Files:**
- Create: `go/dkim2/dsn.go`, `go/cmd/dkim2dsn/main.go`
- Test: `go/dkim2/dsn_test.go`

- [ ] **Step 1: Failing test** `dsn_test.go` mirroring 6.1, driving `Propagate(raw []byte, opts PropagateOptions) ([]byte, string, error)`.
- [ ] **Step 2: Run, expect fail.**
- [ ] **Step 3: Implement** using `mime/multipart` + `net/mail`. Reuse `undo.go` for MI recipe undo and `sign.go` for the fresh signature. Same algorithm; `text/rfc822-headers` fallback.
- [ ] **Step 4: Run, expect pass. Commit.**

```bash
cd /Users/brong/src/interop && git add go/dkim2/dsn.go go/cmd/dkim2dsn/main.go go/dkim2/dsn_test.go && \
  git commit -m "go: DSN propagate (draft-03 §12.1.1)"
```

### Task 6.5: C — DSN propagate (minimal multipart)

**Files:**
- Create: `c/dkim2_dsn.c`, `c/dkim2_dsn.h`
- Modify: `c/Makefile` (add object), `c/dkim2-milter.conf.example` doc note
- Test: ad-hoc driver `c/debug_dsn`

- [ ] **Step 1: Implement** `dkim2_dsn_propagate(const char *raw, size_t len, const char *forwarder_domain, ...)`. Use a minimal `multipart/report` boundary split (the boundary is in the top Content-Type), locate the third part, reuse `dkim2_message.c`/`dkim2_recipe.c` to undo the forwarder's MI hop and strip its MI + DKIM2-Signature, then re-sign via `dkim2_sign.c` with MAIL FROM `<>`. `text/rfc822-headers` fallback when body unrecoverable.
- [ ] **Step 2: Add to Makefile**, build, run `debug_dsn` on the Perl test fixture (`brong/t/data/inbound-dsn.eml`) and confirm the output has exactly one MI and one DKIM2-Signature and is `multipart/report`.
- [ ] **Step 3: Commit.**

```bash
cd /Users/brong/src/interop && git add c/dkim2_dsn.c c/dkim2_dsn.h c/Makefile && \
  git commit -m "c: DSN propagate (draft-03 §12.1.1)"
```

---

## Phase 7: Cross-implementation interop + spec-version bumps

### Task 7.1: Bump embedded spec-version strings to `spec-03`

**Files:**
- Modify: any embedded `...spec-02` strings. Known: `sympa/src/lib/Sympa/Message.pm` `DKIM2_DRAFT`/`DKIM2_DATE` (lines ~462-480); recipe schema `description` "see draft-dkim-dkim2-spec" (no version, leave); C `c/dkim2-spec.txt` is a stale spec copy — replace with the -03 text or delete.
- Test: grep gate

- [ ] **Step 1: Find them**

```bash
grep -rn "spec-02\|dkim2-spec-02\|2026-05-17" /Users/brong/src/interop /Users/brong/src/sympa /Users/brong/src/mailman --include=*.pm --include=*.py --include=*.go --include=*.c
```

- [ ] **Step 2: Update** each to `spec-03` and date `2026-06-24`. In `sympa/src/lib/Sympa/Message.pm` set `DKIM2_DRAFT => 'ietf-dkim-dkim2-spec-03'`, `DKIM2_DATE => '2026-06-24'`. Refresh `c/dkim2-spec.txt` from the new draft (or delete it and point a README at the canonical source).

- [ ] **Step 3: Commit** per repo (interop, sympa, mailman as applicable):

```bash
cd /Users/brong/src/interop && git add -A && git commit -m "bump embedded spec reference to draft-03"
cd /Users/brong/src/sympa && git add src/lib/Sympa/Message.pm && git commit -m "dkim2: bump spec reference to draft-03"
```

### Task 7.2: Regenerate interop fixtures and run the full cross-impl matrix

**Files:**
- Modify: regenerated `python/tests/expected/*.eml`, `examples/*`, `interop/keys`/`dns.json` only if signatures change
- Test: the interop harness

- [ ] **Step 1: Regenerate** any fixtures whose bytes changed because of `delivered-to` exclusion or new required-tag emission:

```bash
cd /Users/brong/src/interop/python && python tests/generate_multihop.py   # if it writes expected/
```

Review diffs: only header-hash and tag-set changes are expected; flag unexpected diffs.

- [ ] **Step 2: Cross-verify** — sign with each implementation, verify with the other three (the repo's interop convention). Build a small matrix script if one doesn't exist:

```bash
# pseudo: for signer in perl go python c; do for verifier in ...; do sign|verify; done; done
```

Include an `nd=` imaginary-hop message and a propagated DSN in the matrix.

- [ ] **Step 3: Run all suites green**

```bash
cd /Users/brong/src/interop/go && go test ./...
cd /Users/brong/src/interop/python && ./tests/run_tests.sh
cd /Users/brong/src/interop/brong && make test
cd /Users/brong/src/interop/c && make && ./run-c-tests.sh 2>/dev/null || true
cd /Users/brong/src/mailman && tox -e py3-nocov -- mailman.handlers.tests.test_message_instance
```

- [ ] **Step 4: Commit** regenerated fixtures:

```bash
cd /Users/brong/src/interop && git add python/tests/expected examples && \
  git commit -m "interop: regenerate fixtures for draft-03 (delivered-to, nd=)"
```

---

## Phase 8: Deploy to mail.dkim2.com

Deploy order minimizes interop breakage: library first (milter/reflector/validator/sympa-dep), then Mailman, then Sympa, with a health check and a live round-trip after each. All commands per `deploy/SERVER.md`.

### Task 8.1: Push all commits to the upstreams

- [ ] **Step 1: Push** each repo's branch:

```bash
cd /Users/brong/src/interop && git push
cd /Users/brong/src/mailman && git push
cd /Users/brong/src/sympa && git push
```

(Confirm branch names: interop deploys from the branch the server's `/root/interop` tracks; Sympa server overlays files via rsync, so push is for record-keeping. Mailman likewise.)

### Task 8.2: Deploy the Perl library + milter + reflector + validator

- [ ] **Step 1: Pull, rebuild, reinstall, restart**

```bash
ssh dkim2 'cd /root/interop && git pull && \
  cd brong && perl Makefile.PL && make && make test && make install && \
  install -m 755 bin/dkim2-reflector.pl /usr/local/bin/dkim2-reflect && \
  install -m 755 bin/validate.cgi /usr/local/bin/dkim2-validate.cgi && \
  systemctl restart dkim2-milter-inbound dkim2-milter-outbound'
```

`make test` MUST pass on the server before `make install`. If it fails, abort and do not restart services.

- [ ] **Step 2: Health check**

```bash
ssh dkim2 'systemctl status dkim2-milter-inbound dkim2-milter-outbound --no-pager | head -20'
```

Expected: both `active (running)`.

- [ ] **Step 3: Live round-trip** — send a test message through a reflector address and confirm it verifies, and that an `nd=` chain verifies:

```bash
ssh dkim2 'journalctl -u dkim2-milter-outbound -n 30 --no-pager'
# send to reflector-both@dkim2.com from a known account, then check the reply verifies via the validator
```

### Task 8.3: Deploy Mailman handler changes

- [ ] **Step 1: rsync the two handler files + tests** from local `~/src/mailman`:

```bash
DEST=root@dkim2.com:/opt/mailman/venv/lib/python3.13/site-packages/mailman
rsync -av /Users/brong/src/mailman/src/mailman/handlers/message_instance.py $DEST/handlers/
rsync -av /Users/brong/src/mailman/src/mailman/mta/message_instance.py $DEST/mta/
```

(No model/migration change in this upgrade, so no Alembic step.)

- [ ] **Step 2: Restart + health check**

```bash
ssh dkim2 'systemctl restart mailman3 mailman-web && \
  systemctl status mailman3 --no-pager | head -15'
```

- [ ] **Step 3: Live round-trip** — post to `test@mailman.dkim2.com`, confirm the outbound MI excludes `Delivered-To` and the chain verifies in the validator.

### Task 8.4: Deploy Sympa (library dependency only; Message.pm bumps spec string)

- [ ] **Step 1: rsync Message.pm** (only the spec-version bump from Task 7.1; ignore-list/recipes come from the already-deployed Perl lib):

```bash
rsync -av /Users/brong/src/sympa/src/lib/Sympa/Message.pm \
  root@dkim2.com:/usr/share/sympa/lib/Sympa/Message.pm
ssh dkim2 'systemctl restart sympa sympa-bulk sympa-archived sympa-bounced'
```

(`Mail::DKIM2` was reinstalled in Task 8.2, so Sympa already picks up the `delivered-to` ignore + recipe changes.)

- [ ] **Step 2: Health check + live round-trip** through a Sympa list; confirm chain verifies.

### Task 8.5: Full-server health check + validator spot-checks

- [ ] **Step 1: One-shot status**

```bash
ssh dkim2 'systemctl status dkim2-milter-inbound dkim2-milter-outbound mailman3 mailman-web sympa postfix nginx --no-pager | grep -E "●|Active:"'
```

Expected: all `active (running)`.

- [ ] **Step 2: Validator spot-checks** at `https://dkim2.com/validate/` — paste (a) a reflector reply with an `nd=` hop, (b) a Mailman post, (c) a Sympa post; confirm each reports `pass` per level.

- [ ] **Step 3: Tail logs briefly** for errors:

```bash
ssh dkim2 'journalctl -u dkim2-milter-outbound -n 50 --no-pager | grep -i error; \
  tail -n 50 /var/log/mailman3/dkim2.log | grep -i error; \
  journalctl -u sympa -n 50 --no-pager | grep -i error'
```

Expected: no new errors attributable to the upgrade.

### Task 8.6: Optional follow-up — simplify the reflector transport (document only)

- [ ] **Step 1:** Note in `deploy/SERVER.md` §6 that the rationale for the `pipe(8)` transport ("`Delivered-To` is not in the skip list") is **obsolete** under draft-03, since `Delivered-To` is now ignored. Do **not** change the live transport in this pass (it works; changing it risks the demo). Record it as a future simplification.

```bash
cd /Users/brong/src/interop && git add deploy/SERVER.md && \
  git commit -m "docs: note pipe(8) reflector rationale obsolete under draft-03"
```

---

## Self-Review

**Spec coverage** — every -03 changelog item maps to a task:
- "Move ignored header fields into own section + add Delivered-To" → Phase 1 (all 6 codebases).
- "Remove possibility of a null recipe for header field changes" → Phase 2.
- "Add nd= as alternative to mf=/rt=" → Phase 3 (4 impls: parse/verify/emit).
- "feedhere flag added" → Phase 4 (incl. new flag infra in C/Python per scope decision).
- "Change DSN propagation rules" / RFC3461→3462 → Phase 6 (4 impls) + Task 7.1 (RFC ref).
- New/changed PERMERROR strings → Phase 5 (+ folded into Phase 3).
- Spec-version/date bumps → Task 7.1. Interop fixtures → Task 7.2. Deploy → Phase 8.

**Placeholder scan** — driver-based C steps name the exact functions; the only deliberately-deferred specifics are the real entry-point names in Perl/Python that the implementer confirms against the file (flagged inline as "adjust to actual signature"), because the surveys gave line ranges but not every signature. No "TBD/handle edge cases" left.

**Type consistency** — `NextDomain` (Go field), `next_domain` (Perl accessor), `nd=` (wire), `sig->nd` (C), `nd_val` (Python) are the agreed names per language. `propagate`/`Propagate` returns `{raw, upstream_mailfrom}` (Perl/Python) and `([]byte, string, error)` (Go) consistently. `_should_exclude_header` is the shared Python/Mailman predicate name.

**Known residual risk:** DSN propagation in C (Task 6.5) is the heaviest item and depends on a minimal multipart splitter that doesn't exist yet; if the C effort balloons, descope C DSN to "parse + identify upstream MAIL FROM, defer rebuild" and record it — the deployed path (Perl) is unaffected.
