# DKIM2 spec-01 Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the milter (Perl), mailman (Python), and sympa (Perl) DKIM2 implementations from draft-ietf-dkim-dkim2-spec-00 to draft-ietf-dkim-dkim2-spec-01 (published 2026-04-20).

**Architecture:** The three codebases share the same DKIM2 protocol but are independently maintained. The Perl milter lives in `brong/`, mailman in `../mailman/src/mailman/handlers/`, and sympa in `../sympa/src/lib/Sympa/`. Each needs the same normative changes applied in its own idiom.

**Tech Stack:** Perl (Mail::DKIM2, Mail::Milter::Authentication), Python (mailman), Perl (Sympa)

---

## Summary of spec-01 normative changes

Comparing draft-ietf-dkim-dkim2-spec-00 (2026-03-25) to draft-ietf-dkim-dkim2-spec-01 (2026-04-20):

1. **Version string bump** — everywhere `spec-00` appears (constants + doc strings)
2. **Result code rename** — `permfail` → `permerror`, `tempfail` → `temperror` (aligned with RFC 8601). `pass` and `fail` are unchanged.
3. **Nonce max-length** — n= tag MUST NOT exceed 64 characters (explicit constraint added in ABNF)
4. **DNS h= tag MUST be ignored** — implementations must not fail on h= in DNS records (already silently ignored; needs a comment + guard)
5. **Section number changes** — comments referencing old section numbers need updating:
   - Old §11.5 (signing input construction) → new §9.5
   - Old §8 (tag-list) → new §6/§7 (tag-list now split per header field)
   - Old §5.2 (excluded headers) → new §5.2 (unchanged section number, but verify)
6. **Message-Instance SHOULD NOT add when body hashes match** — already implemented in mailman (line 233) and sympa (line 2414); Signer.pm does not have this check and needs it added

## Files to modify

| File | Changes |
|------|---------|
| `brong/bin/dkim2-milter.pl` | Version constants; result code strings in warn/AR output |
| `brong/lib/Mail/DKIM2/Verifier.pm` | Result codes `permfail`→`permerror`, `tempfail`→`temperror`; doc; section refs |
| `brong/lib/Mail/DKIM2/Signer.pm` | Add body-hash SHOULD NOT check; section refs |
| `brong/lib/Mail/DKIM2/Signature.pm` | Nonce max-64 validation; doc version string |
| `brong/lib/Mail/DKIM2/Common.pm` | Section refs; add h= ignore comment; doc version string |
| `brong/lib/Mail/DKIM2/TagValueList.pm` | Doc version string; section refs |
| `brong/lib/Mail/DKIM2/MessageInstance.pm` | Doc version string |
| `brong/lib/Mail/DKIM2/MessageStore.pm` | Doc version string |
| `brong/lib/Mail/DKIM2/HeaderParser.pm` | Doc version string |
| `brong/lib/Mail/Milter/Authentication/Handler/DKIM2Sign.pm` | Doc version string |
| `brong/lib/Mail/Milter/Authentication/Handler/DKIM2Verify.pm` | Doc version string |
| `mailman/src/mailman/handlers/message_instance.py` | Version constants |
| `sympa/src/lib/Sympa/Message.pm` | Version constants |

---

### Task 1: Update version string constants

The constant `DKIM2_DRAFT = 'ietf-dkim-dkim2-spec-00'` and `DKIM2_DATE = '2026-03-25'` appear in three files. Update them all.

**Files:**
- Modify: `brong/bin/dkim2-milter.pl:9-11`
- Modify: `mailman/src/mailman/handlers/message_instance.py:48-50`
- Modify: `sympa/src/lib/Sympa/Message.pm:463-465`

- [ ] **Step 1: Update milter constants**

In `brong/bin/dkim2-milter.pl` change lines 9 and 11:
```perl
use constant DKIM2_DRAFT   => 'ietf-dkim-dkim2-spec-01';
# (line 10 is a blank line)
use constant DKIM2_DATE    => '2026-04-20';
```

- [ ] **Step 2: Update mailman constants**

In `mailman/src/mailman/handlers/message_instance.py` change lines 48 and 50:
```python
DKIM2_DRAFT = 'ietf-dkim-dkim2-spec-01'
# (line 49 is DKIM2_REPO, unchanged)
DKIM2_DATE = '2026-04-20'
```

- [ ] **Step 3: Update sympa constants**

In `sympa/src/lib/Sympa/Message.pm` change lines 463 and 465:
```perl
use constant DKIM2_DRAFT    => 'ietf-dkim-dkim2-spec-01';
# (line 464 is blank)
use constant DKIM2_DATE     => '2026-04-20';
```

- [ ] **Step 4: Run milter tests to confirm nothing breaks**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/
```
Expected: all tests pass (version string change is cosmetic to protocol)

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop
git add brong/bin/dkim2-milter.pl mailman/src/mailman/handlers/message_instance.py sympa/src/lib/Sympa/Message.pm
git commit -m "Update DKIM2_DRAFT/DKIM2_DATE constants to spec-01 (2026-04-20)"
```

---

### Task 2: Rename result codes permfail→permerror and tempfail→temperror in Verifier.pm

Spec-01 aligns result codes with RFC 8601: `permfail` is now `permerror`, `tempfail` is now `temperror`. The milter uses `$verifier->result()` in Authentication-Results output, so it must also be updated. Sympa already uses `permerror`/`temperror` in its mapping table — this makes them consistent.

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Verifier.pm` (lines 182, 221, 351-363)
- Modify: `brong/bin/dkim2-milter.pl` (any explicit checks against `permfail`/`tempfail`)

- [ ] **Step 1: Check existing test expectations for result codes**

```bash
grep -rn "permfail\|tempfail\|permerror\|temperror" /Users/brong/src/interop/brong/t/
```
Note all test files that assert `permfail` or `tempfail` — they will need updating too.

- [ ] **Step 2: Update Verifier.pm result assignments**

In `brong/lib/Mail/DKIM2/Verifier.pm`:
- Line 182: `$self->{result} = 'tempfail';` → `$self->{result} = 'temperror';`
- Line 221: `$self->{result} = 'permfail';` → `$self->{result} = 'permerror';`

- [ ] **Step 3: Update Verifier.pm POD docs**

In `brong/lib/Mail/DKIM2/Verifier.pm` around lines 351-363, update:
```pod
=item C<permerror> - Permanent failure (e.g. missing public key).

=item C<temperror> - Temporary failure (e.g. DNS lookup error).
```

- [ ] **Step 4: Update any test files found in step 1**

For each test file asserting `permfail` or `tempfail`, change to `permerror` or `temperror` as appropriate.

- [ ] **Step 5: Check milter for explicit result code comparisons**

```bash
grep -n "permfail\|tempfail" /Users/brong/src/interop/brong/bin/dkim2-milter.pl
```
Update any found (warn/log strings are fine; logic comparisons must change).

- [ ] **Step 6: Run tests**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/
```
Expected: all tests pass

- [ ] **Step 7: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/DKIM2/Verifier.pm brong/bin/dkim2-milter.pl brong/t/
git commit -m "Rename permfail→permerror and tempfail→temperror per spec-01 (RFC 8601 alignment)"
```

---

### Task 3: Check that top DKIM2-Signature covers topmost MI in Verifier.pm

The verifier confirms each signature's signing input matches what it declared,
but does not check that the top signature's `m=` value equals the count of MI
headers present.  A message with MI v=3 but only a DKIM2-Signature i=2 (m=2)
has an uncovered MI — yet the verifier currently returns `pass`.

The fix: after the MI completeness check (line 101), add a check that the
highest `m=` seen across all signatures equals `max_v` (the highest MI version
present).  If not, fail with "MI not covered by top signature".

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Verifier.pm` (`finish_body()`, after line 101)

- [ ] **Step 1: Write a failing test**

In `brong/t/verifier.t` (or create it), add a case where a message has MI v=2
present but the top DKIM2-Signature only declares m=1 — and assert `fail`:

```perl
use Test::More;
use Mail::DKIM2::Verifier;

# Build a minimal signed message with MI v=1, DKIM2-Sig i=1 m=1,
# then prepend a fake MI v=2 header (unsigned).
# Verifier should return fail, not pass.

# (Use the test infrastructure from t/full-chain.t to build the base message,
# then manually prepend "Message-Instance: m=2; h=sha256:FAKE:FAKE\r\n"
# before feeding to the verifier.)

pass("placeholder — see step 3 for real test");
done_testing;
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/verifier.t
```
Expected: placeholder passes — replace with real test after confirming gap

- [ ] **Step 3: Confirm the gap with a real test**

Use a pre-signed email from `tests/expected/` as the base. Prepend a fake MI
header to it before feeding to the verifier:

```perl
my $signed_msg = do { local $/; open my $f, '<', 'tests/expected/basic.eml'; <$f> };
# Prepend uncovered MI v=2
my $tampered = "Message-Instance: m=2; h=sha256:AAAA:BBBB\r\n" . $signed_msg;

my $verifier = Mail::DKIM2::Verifier->new();
$verifier->PRINT($tampered);
$verifier->CLOSE;
is($verifier->result, 'fail', 'uncovered MI at top must fail');
like($verifier->result_detail, qr/not covered/, 'detail mentions coverage');
```

Run it — expect FAIL on the test (i.e., verifier currently returns pass
instead of fail).

- [ ] **Step 4: Add the coverage check to Verifier.pm finish_body()**

After the MI completeness block (after line 101), add:

```perl
# Check that the top signature covers the topmost MI
if (keys %mi_map) {
    my $max_v = (sort { $b <=> $a } keys %mi_map)[0];
    my $top_sig = $dk2_map{$max_i}{sig};
    my $top_m   = $top_sig->version || 0;
    if ($top_m != $max_v) {
        $self->{result} = 'fail';
        $self->{details} = "top signature m=$top_m does not cover topmost MI m=$max_v";
        return;
    }
}
```

- [ ] **Step 5: Run tests**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/
```
Expected: all pass including the new coverage test

- [ ] **Step 6: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/DKIM2/Verifier.pm brong/t/verifier.t
git commit -m "Fail if top DKIM2-Signature does not cover topmost MI"
```

---

### Task 4: Add nonce max-length validation in Signature.pm

Spec-01 Section 7 ABNF explicitly limits `n=` to 64 characters: `nonce-value = *64(%x21-3A / %x3C-7E)`. The current `nonce()` getter/setter in `Signature.pm` has no length check.

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Signature.pm` (nonce() method ~line 93)

- [ ] **Step 1: Write a failing test**

In `brong/t/signature.t` (or create it), add:
```perl
use Test::More;
use Mail::DKIM2::Signature;

# nonce exceeding 64 chars must be rejected
my $sig = Mail::DKIM2::Signature->new(
    Sequence => 1, Domain => 'example.com', Timestamp => time(),
    Signatures => [['sel', 'rsa-sha256', '']],
);
eval { $sig->nonce('a' x 65) };
like($@, qr/nonce.*64|too long/i, 'nonce > 64 chars dies');

# nonce of exactly 64 chars must be accepted
eval { $sig->nonce('a' x 64) };
is($@, '', 'nonce of 64 chars accepted');

done_testing;
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/signature.t
```
Expected: FAIL — nonce > 64 does not currently die

- [ ] **Step 3: Add validation to nonce() setter in Signature.pm**

Find the `nonce()` method (around line 93) and add the length check:
```perl
sub nonce {
    my ($self, $val) = @_;
    if (defined $val) {
        croak "nonce must not exceed 64 characters" if length($val) > 64;
        $self->{_tags}{n} = $val;
    }
    return $self->{_tags}{n};
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/signature.t
```
Expected: PASS

- [ ] **Step 5: Run full test suite**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/
```
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/DKIM2/Signature.pm brong/t/signature.t
git commit -m "Validate nonce max 64 chars per spec-01 Section 7 ABNF"
```

---

### Task 5: Add DNS h= tag MUST-ignore guard in Common.pm

Spec-01 Section 10.3 states "DKIM2 implementations MUST ignore this tag if it is present" for the `h=` tag in DNS public key records. The current `parse_dkim_pubkey()` already ignores `h=` silently, but needs a comment and an explicit guard so the behavior is intentional rather than accidental.

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Common.pm` (parse_dkim_pubkey(), ~line 269)

- [ ] **Step 1: Update parse_dkim_pubkey() with explicit h= ignore**

In `brong/lib/Mail/DKIM2/Common.pm`, update `parse_dkim_pubkey()`:
```perl
sub parse_dkim_pubkey {
    my ($key_txt) = @_;
    return unless $key_txt;
    my ($k) = $key_txt =~ /\bk=([^;\s]+)/;
    $k //= 'rsa';  # default per RFC 6376
    # h= (hash algorithm list) MUST be ignored per spec-01 Section 10.3
    my ($p) = $key_txt =~ /\bp=([A-Za-z0-9+\/=]+)/;
    return unless $p;
    if ($k eq 'ed25519') {
        my $pk = Crypt::PK::Ed25519->new();
        $pk->import_key_raw(decode_base64($p), 'public');
        return $pk;
    }
    # RSA: p= is base64-encoded SubjectPublicKeyInfo DER
    my $der = decode_base64($p);
    my $rsa = eval { Crypt::PK::RSA->new(\$der) };
    return $rsa;
}
```

- [ ] **Step 2: Run tests**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/
```
Expected: all tests pass (comment-only change to logic)

- [ ] **Step 3: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/DKIM2/Common.pm
git commit -m "Document MUST-ignore of h= tag in DNS records per spec-01 Section 10.3"
```

---

### Task 6: Verify MI-skip behaviour and raise spec wording concern

Spec-01 Section 8.1 exact text:

> "If hashing the message body or relevant header fields does not give the same hash values as those recorded in the highest version (m=) Message-Instance header field then a new Message-Instance header field MUST be added and if they are the same a new Message-Instance header field SHOULD NOT be added."

This means skip MI only when BOTH body hash AND header hash are unchanged (the `or` is in the condition for adding; the skip requires neither to differ).

**The milter already implements this correctly**: `_compute_mi()` calls `MessageInstance->verify($msg)` at line 416, which checks full MI validity (both hashes). If it passes, MI is skipped (`return undef` at line 424).

**Spec wording issue**: the phrase "if they are the same" is ambiguous — "they" has no clear antecedent in the sentence. The full intent (both body AND header hashes must match) is only recoverable from the first clause. This should be raised with the spec authors.

**Files:**
- No code changes needed
- Modify: `brong/spec-review-notes.md` (add the wording concern)

- [ ] **Step 1: Verify the milter's MI-skip path covers both hashes**

Read `MessageInstance->verify()` to confirm it checks both `bh=` and `hh=` tags, not just one:

```bash
grep -n "bh=\|hh=\|body.*hash\|header.*hash\|verify" \
    /Users/brong/src/interop/brong/lib/Mail/DKIM2/MessageInstance.pm | head -30
```

Expected: verify checks both body hash and header hash fields.

- [ ] **Step 2: Add note to spec-review-notes.md**

Open `brong/spec-review-notes.md` and add an entry:

```markdown
## spec-01 §8.1: Ambiguous antecedent in MI-skip condition

The sentence "if they are the same a new Message-Instance header field SHOULD
NOT be added" has no clear antecedent for "they". The intent (skip only when
both body hash AND header hash match) is only recoverable from the previous
clause. Suggested rewording: "if both hash values are the same as those in
the existing header field, a new Message-Instance header field SHOULD NOT be
added."
```

- [ ] **Step 3: Commit**

```bash
cd /Users/brong/src/interop
git add brong/spec-review-notes.md
git commit -m "Note spec-01 §8.1 ambiguous MI-skip wording in spec-review-notes"
```

---

### Task 7: Update section number references in comments across all Perl files

Spec-01 renumbered sections. Key changes:
- Old §11.5 (signing input construction) → spec-01 §9.5
- Old §8 (tag-list) → spec-01 §6/§7
- Old §5.2 (excluded headers) — verify against spec-01 (likely unchanged)

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Common.pm` (lines 32, 232)
- Modify: `brong/lib/Mail/DKIM2/TagValueList.pm` (lines 5, 71)

- [ ] **Step 1: Find all section references**

```bash
grep -rn "Section\|§\|spec-0[01] Section" /Users/brong/src/interop/brong/lib/
```

- [ ] **Step 2: Verify correct new section numbers in spec-01**

Open/fetch `https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-spec-01.txt` and confirm:
- Section for "signing input construction" (was §11.5)
- Section for "tag-list" (was §8)
- Section for "excluded headers" (was §5.2)

- [ ] **Step 3: Update Common.pm comment on line 32**

```perl
# Headers excluded from hashing per draft-ietf-dkim-dkim2-spec-01 Section 5.2
```
(Update section number if it changed; update spec version string regardless.)

- [ ] **Step 4: Update Common.pm comment on line 232**

```perl
# Per draft-ietf-dkim-dkim2-spec-01 Section 9.5:
```

- [ ] **Step 5: Update TagValueList.pm comments on lines 5 and 71**

Line 5:
```perl
# Simple tag=value list as defined in draft-ietf-dkim-dkim2-spec-01 Section 6/7.
```
Line 71: update similarly.

- [ ] **Step 6: Run tests**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/
```
Expected: all pass (comment-only changes)

- [ ] **Step 7: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/Mail/DKIM2/Common.pm brong/lib/Mail/DKIM2/TagValueList.pm
git commit -m "Update spec section number references to spec-01 numbering"
```

---

### Task 8: Update doc-string version references in all Perl library files

All `B<EXPERIMENTAL>` pod blocks and module docstrings currently say `draft-ietf-dkim-dkim2-spec-00`. These need to say `draft-ietf-dkim-dkim2-spec-01`. This is a pure documentation change.

**Files in `brong/lib/`:**
- `Mail/DKIM2/Common.pm` line 334
- `Mail/DKIM2/HeaderParser.pm` line 129
- `Mail/DKIM2/MessageInstance.pm` line 766
- `Mail/DKIM2/MessageStore.pm` line 122
- `Mail/DKIM2/Signature.pm` line 289
- `Mail/DKIM2/Signer.pm` line 190
- `Mail/DKIM2/TagValueList.pm` line 71
- `Mail/DKIM2/Verifier.pm` line 331
- `Mail/Milter/Authentication/Handler/DKIM2Sign.pm` line 412
- `Mail/Milter/Authentication/Handler/DKIM2Verify.pm` line 349

**Also in mailman:**
- `mailman/src/mailman/handlers/message_instance.py` line 21 (module docstring)

Note: sympa's only `spec-00` reference is the `DKIM2_DRAFT` constant, already covered by Task 1.

- [ ] **Step 1: Update brong/ Perl files**

```bash
cd /Users/brong/src/interop/brong
perl -pi -e 's/draft-ietf-dkim-dkim2-spec-00/draft-ietf-dkim-dkim2-spec-01/g' \
    lib/Mail/DKIM2/Common.pm \
    lib/Mail/DKIM2/HeaderParser.pm \
    lib/Mail/DKIM2/MessageInstance.pm \
    lib/Mail/DKIM2/MessageStore.pm \
    lib/Mail/DKIM2/Signature.pm \
    lib/Mail/DKIM2/Signer.pm \
    lib/Mail/DKIM2/TagValueList.pm \
    lib/Mail/DKIM2/Verifier.pm \
    lib/Mail/Milter/Authentication/Handler/DKIM2Sign.pm \
    lib/Mail/Milter/Authentication/Handler/DKIM2Verify.pm
```

- [ ] **Step 2: Update mailman module docstring**

In `mailman/src/mailman/handlers/message_instance.py` line 21, change:
```python
draft-ietf-dkim-dkim2-spec-00.  A Message-Instance header records cryptographic
```
to:
```python
draft-ietf-dkim-dkim2-spec-01.  A Message-Instance header records cryptographic
```

- [ ] **Step 3: Verify no spec-00 references remain**

```bash
grep -rn "spec-00" \
    /Users/brong/src/interop/brong/lib/ \
    /Users/brong/src/interop/brong/bin/ \
    /Users/brong/src/mailman/src/mailman/handlers/message_instance.py \
    /Users/brong/src/sympa/src/lib/Sympa/Message.pm
```
Expected: no output (all references updated)

- [ ] **Step 4: Run tests**

```bash
cd /Users/brong/src/interop/brong && prove -lv t/
```
Expected: all pass

- [ ] **Step 5: Commit**

```bash
cd /Users/brong/src/interop
git add brong/lib/ \
    mailman/src/mailman/handlers/message_instance.py
git commit -m "Update all doc-string spec version references to draft-ietf-dkim-dkim2-spec-01"
```

---

### Task 9: Verify incoming top MI at ingress in mailman and sympa

Before computing an MI diff, both mailman and sympa should verify that the
top (highest-version) existing MI header's hashes match the current message
content.  If they don't match the message was modified after the last MI was
recorded — adding a new MI diff on top of a broken chain is meaningless.

DKIM2-Signature cryptographic verification is handled at the edge by the
milter. This check is only about MI hash consistency: does the incoming
message content match what the last MI says it should be?

Mailman already has `verify_message_instance()` (line 475 of
`message_instance.py`) — it just isn't called in the ingress handler.
Sympa needs to call `Mail::DKIM2::MessageInstance->verify()` before
computing the egress diff.

**Files:**
- Modify: `mailman/src/mailman/handlers/message_instance.py` (`MessageInstanceIngress.process()`, ~line 689)
- Modify: `sympa/src/lib/Sympa/Message.pm` (`add_message_instance_egress()`, ~line 516)

- [ ] **Step 1: Write a failing test for mailman ingress verification**

In `mailman/src/mailman/handlers/tests/test_message_instance.py`, add a test
that builds a message with a MI header whose hashes do NOT match the body,
runs it through `MessageInstanceIngress`, and asserts that no new MI is
added (or a warning is logged) rather than blindly snapshotting it:

```python
def test_ingress_rejects_invalid_mi(self):
    """Ingress should detect MI hash mismatch and not snapshot."""
    msg = message_from_string(
        'From: sender@example.com\r\n'
        'To: list@example.com\r\n'
        'Subject: Test\r\n'
        '\r\n'
        'Original body\r\n'
    )
    # Add an MI header with wrong hashes (tampered body)
    msg['Message-Instance'] = 'm=1; h=sha256:AAAA:BBBB'
    handler = MessageInstanceIngress()
    handler.process(self.mlist, msg, {})
    # Should not add a v=2 MI on top of a broken v=1
    mi_headers = msg.get_all('message-instance', [])
    versions = [_get_mi_version(v) for v in mi_headers]
    self.assertNotIn(2, versions, 'Should not add v=2 on broken v=1')
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/brong/src/mailman && python -m pytest \
    src/mailman/handlers/tests/test_message_instance.py \
    -k test_ingress_rejects_invalid_mi -v
```
Expected: FAIL — current code snapshots without checking

- [ ] **Step 3: Add MI verification to mailman ingress**

In `MessageInstanceIngress.process()` (line ~689), after `_serialize_msg(msg)`,
add before the `if current_version == 0:` block:

```python
current_version = get_max_mi_version(msg)
if current_version > 0:
    ver, err = verify_message_instance(msg)
    if err:
        log.warning('Incoming MI v=%d fails verification: %s — '
                    'treating as fresh message', current_version, err)
        # Strip existing MI headers; add v=1 documenting current state
        for key in list(msg.keys()):
            if key.lower() == 'message-instance':
                del msg[key]
        current_version = 0
```

Then let the existing `if current_version == 0:` block add a fresh MI v=1.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/brong/src/mailman && python -m pytest \
    src/mailman/handlers/tests/test_message_instance.py \
    -k test_ingress_rejects_invalid_mi -v
```
Expected: PASS

- [ ] **Step 5: Run full mailman test suite**

```bash
cd /Users/brong/src/mailman && python -m pytest \
    src/mailman/handlers/tests/test_message_instance.py -v
```
Expected: all pass

- [ ] **Step 6: Add MI verification to sympa egress**

In `Sympa::Message::add_message_instance_egress()` (line ~516), after
loading `Mail::DKIM2::MessageInstance`, add a check before the hash
comparison:

```perl
# Verify the incoming top MI matches the original message content.
# If not, the chain is broken and we cannot compute a valid diff.
unless (Mail::DKIM2::MessageInstance->verify($em_original)) {
    $log->syslog('warning',
        'Incoming MI fails verification — skipping Message-Instance egress');
    return undef;
}
```

Note: verify() on `$em_original` (the message as it arrived at ingress) — if
the MI recorded at ingress no longer matches, something went wrong upstream.

- [ ] **Step 7: Commit**

```bash
cd /Users/brong/src/interop
git add mailman/src/mailman/handlers/message_instance.py \
        mailman/src/mailman/handlers/tests/test_message_instance.py \
        sympa/src/lib/Sympa/Message.pm
git commit -m "Verify top MI at ingress/egress before computing diff (mailman + sympa)"
```

---

### Task 10: Update spec-01 reference in spec/ directory

The `spec/` directory contains `draft-clayton-dkim2-spec-08.txt`. Download and store the new spec-01 text.

**Files:**
- Create: `spec/draft-ietf-dkim-dkim2-spec-01.txt`

- [ ] **Step 1: Download spec-01**

```bash
curl -o /Users/brong/src/interop/spec/draft-ietf-dkim-dkim2-spec-01.txt \
    https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-spec-01.txt
```

- [ ] **Step 2: Verify download**

```bash
head -5 /Users/brong/src/interop/spec/draft-ietf-dkim-dkim2-spec-01.txt
```
Expected: shows the IETF draft header for spec-01

- [ ] **Step 3: Commit**

```bash
cd /Users/brong/src/interop
git add spec/draft-ietf-dkim-dkim2-spec-01.txt
git commit -m "Add draft-ietf-dkim-dkim2-spec-01 to spec/ directory"
```

---

### Task 11: Update CLAUDE.md and memory file

Update the project documentation so future sessions start with the right context.

**Files:**
- Modify: `brong/CLAUDE.md` (first line title)
- Modify: `.claude/projects/-Users-brong-src-interop/memory/dkim2-spec-version.md`

- [ ] **Step 1: Update CLAUDE.md title line**

In `brong/CLAUDE.md`, change the first line:
```markdown
# Mail::DKIM2 — Perl implementation of draft-ietf-dkim-dkim2-spec-01
```

- [ ] **Step 2: Update memory file**

In `/Users/brong/.claude/projects/-Users-brong-src-interop/memory/dkim2-spec-version.md`, change:
```
Current spec: `draft-ietf-dkim-dkim2-spec-01` (updated 2026-04-20)
```

- [ ] **Step 3: Commit**

```bash
cd /Users/brong/src/interop
git add brong/CLAUDE.md
git commit -m "Update CLAUDE.md to reference spec-01"
```

---

## Self-review against spec-01 changes

Checking each noted change from the spec-01 changelog:

| Spec-01 change | Covered by task |
|---|---|
| Version string bump | Task 1 (constants), Task 8 (docs), Task 11 (CLAUDE.md) |
| permfail→permerror, tempfail→temperror | Task 2 |
| Top signature must cover topmost MI (gap found) | Task 3 |
| Nonce max 64 chars ABNF | Task 4 |
| DNS h= MUST ignore | Task 5 |
| MI SHOULD NOT add when body+header unchanged | Task 6 (milter already compliant; spec wording noted) |
| Section number updates in comments | Task 7 |
| Verify incoming top MI before diff (mailman + sympa) | Task 9 (best practice implied by spec) |
| Spec txt in repo | Task 10 |
| Improved ABNF (structure change only) | No code change needed — ABNF is informative to our implementation |
| Untangled verification requirements from verifier actions | Covered by Task 2 result code rename; no structural code change needed |
| Human-readable error message format (m=, tag= placeholders) | Current `result_detail()` already provides human-readable strings; spec-01 defines a recommended format but does not mandate exact wording — no change required |
| Transparent forwarding MAY skip DKIM2-Signature | No change needed — this is permissive new language, our milter is not a transparent forwarder |

No gaps found.
