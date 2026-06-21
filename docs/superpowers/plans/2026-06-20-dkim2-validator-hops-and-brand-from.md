# Validator Per-Hop Details + Brand ESP From/To — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the web validator spell out each signature's From/To and each Message-Instance's recovered recipe values, and make the `reflector-brand` message read as ESP-sent (From the brand, To the sender, `dkim2.com` only in the signature/envelope).

**Architecture:** Add fields to the `Mail::DKIM2::Validate` report (signature `mail_from`/`rcpt_to`; MI `header_recipes`/`body_recipe`, recovered from the undo clone `_mi_level` already builds) and render them in `validate.js`. Change `generate_brand`'s delegated From/To/`mf`.

**Tech Stack:** Perl 5.20+ (`Mail::DKIM2::{Validate,Reflector,Signature,MessageInstance}`, `Email::MIME`), vanilla JS (`validate.js`); `Test::More` + `DKIM2TestKeys`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-20-dkim2-validator-hops-and-brand-from-design.md`.
- Display-only changes for the validator; no change to hashes, verdicts, or the `Received-SPF` strip-and-retry.
- Brand delegated message: `From: dkim2demo@<brand domain>`, `To: <sender>`, `Subject:` unchanged; `i=1 mf=dkim2demo@<brand domain>`, `i=1 rt=reflector-brand@<domain>` (unchanged), `i=2` unchanged. No `dkim2.com` in `From`/`To`/`Subject`.
- Not-delegated (CNAME-absent) path unchanged (fresh `From: "DKIM2 Generator" <fresh@<domain>>` + error body).

---

## File Structure

- `brong/lib/Mail/DKIM2/Validate.pm` — report fields (signature + MI).
- `deploy/www/validate/validate.js` — render the new fields.
- `brong/lib/Mail/DKIM2/Reflector.pm` — `generate_brand` delegated From/To/`mf`/body.
- `brong/t/validate-report.t`, `brong/t/reflector.t` — tests.

---

### Task 1: Report fields in `Mail::DKIM2::Validate`

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Validate.pm`
- Test: `brong/t/validate-report.t`

**Interfaces:**
- Produces: signature level gains `mail_from` (string) + `rcpt_to` (arrayref of strings); MI level gains `header_recipes` (arrayref of `{name, current, previous}`) + `body_recipe` (`'diff'`/`'null'`/`'none'`).

- [ ] **Step 1: Write the failing test** (append to `brong/t/validate-report.t`, before `done_testing;`)

```perl
# 8) per-hop details: signature From/To + recovered MI recipe values
{
    my $in = signed_input("From: a\@test1.dkim2.com\r\nTo: reflector-both\@test2.dkim2.com\r\nSubject: hi\r\n\r\norig body\r\n");
    my $r2 = Mail::DKIM2::Reflector::reflect(%common, mode=>'both', message=>$in);
    my $rep = Mail::DKIM2::Validate::report($r2->{message}, %ropt);

    my ($sig2) = grep { $_->{kind} eq 'signature' && $_->{i} == 2 } @{$rep->{levels}};
    ok($sig2->{mail_from}, 'sig i=2 has mail_from');
    is(ref $sig2->{rcpt_to}, 'ARRAY', 'sig i=2 rcpt_to is a list');
    ok(scalar @{$sig2->{rcpt_to}}, 'sig i=2 has at least one rcpt_to');

    my ($topmi) = grep { $_->{kind} eq 'mi' && $_->{m} == 2 } @{$rep->{levels}};
    is($topmi->{body_recipe}, 'diff', 'top MI body_recipe is diff');
    my ($subj) = grep { $_->{name} eq 'subject' } @{$topmi->{header_recipes} || []};
    ok($subj, 'top MI has a subject header recipe');
    like($subj->{current},  qr/\Q[DKIM2]\E/, 'subject recipe current is the prefixed subject');
    is($subj->{previous}, 'hi', 'subject recipe previous is the original subject');
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd brong && perl -I lib -I t/lib t/validate-report.t 2>&1 | tail -8`
Expected: FAIL — `mail_from`/`body_recipe`/`header_recipes` undefined.

- [ ] **Step 3: Add `mail_from`/`rcpt_to` to the signature level**

In `_sig_level`, extend the `%lvl` initialiser to include the new keys, and populate them inside the `if ($sig) { ... }` block. Change the initialiser:
```perl
    my %lvl = (kind => 'signature', i => $num, m => _m($sig_by_i->{$num}),
               domain => ($sig ? ($sig->domain // '') : ''),
               mail_from => '', rcpt_to => [],
               items => [], timestamp => { ok => 1, detail => '' },
               custody => { ok => 1, detail => '' }, result => 'fail', detail => '');
```
and immediately inside `if ($sig) {` (before the `sig_count` loop) add:
```perl
        $lvl{mail_from} = $sig->mail_from // '';
        my $rt = $sig->rcpt_to;
        $lvl{rcpt_to} = [ ref $rt eq 'ARRAY' ? @$rt : (defined $rt ? ($rt) : ()) ];
```

- [ ] **Step 4: Add `header_recipes`/`body_recipe` to the MI level**

In `_mi_level`, extend the `%lvl` initialiser:
```perl
    my %lvl = (kind => 'mi', m => $inst, result => 'fail',
               header_hash => 'mismatch', body_hash => 'mismatch',
               recipe => 'none', undo => 'n/a', detail => '',
               header_recipes => [], body_recipe => 'none');
```
After the `$lvl{recipe} = ...` line, derive `body_recipe`:
```perl
    my $rh = $mi->get_tag('rh');
    my $rb = $mi->get_tag('rb');
    $lvl{body_recipe} = $mi->unrecoverable ? 'null' : ($rb ? 'diff' : 'none');
```
Then in the `else` branch that builds the undo clone, after computing `$lvl{undo}`, capture recovered header values:
```perl
    } else {
        my $clone = Email::MIME->new($msg->as_string);
        my $ok = eval { Mail::DKIM2::MessageInstance->undo($clone) };
        $lvl{undo} = ($ok && !$@) ? 'clean' : 'failed';
        if ($ok && !$@ && $rh) {
            for my $h (sort keys %$rh) {
                my $cur  = join(' / ', $msg->header($h));
                my $prev = join(' / ', $clone->header($h));
                push @{$lvl{header_recipes}}, {
                    name => $h,
                    current  => (length $cur  ? $cur  : '(absent)'),
                    previous => (length $prev ? $prev : '(absent)'),
                };
            }
        }
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd brong && perl -I lib -I t/lib t/validate-report.t 2>&1 | tail -8`
Expected: PASS — the new assertions `ok`.

- [ ] **Step 6: Full suite**

Run: `cd brong && prove -I lib -I t/lib t/ 2>&1 | tail -3`
Expected: `All tests successful.`

- [ ] **Step 7: Commit**

```bash
git add brong/lib/Mail/DKIM2/Validate.pm brong/t/validate-report.t
git commit -m "feat(validate): report per-hop From/To and recovered MI recipe values

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Render the new fields in `validate.js`

**Files:**
- Modify: `deploy/www/validate/validate.js`

**Interfaces:**
- Consumes: report `mail_from`/`rcpt_to`/`header_recipes`/`body_recipe` from Task 1.

- [ ] **Step 1: Add rendering**

In `deploy/www/validate/validate.js` `render()`, in the signature branch, after the `domain` line:
```javascript
        if (lvl.mail_from) card.appendChild(kv('from', lvl.mail_from));
        if (lvl.rcpt_to && lvl.rcpt_to.length) card.appendChild(kv('to', lvl.rcpt_to.join(', ')));
```
and in the MI (`else`) branch, after the `recipe` line:
```javascript
        (lvl.header_recipes || []).forEach(function (r) {
          card.appendChild(kv('recipe', r.name + ': "' + r.current + '" ← "' + r.previous + '"'));
        });
        if (lvl.body_recipe && lvl.body_recipe !== 'none') card.appendChild(kv('body recipe', lvl.body_recipe));
```

- [ ] **Step 2: Verify the rendering is present and the file is well-formed**

Run: `grep -n "header_recipes\|body_recipe\|kv('from'\|kv('to'" deploy/www/validate/validate.js`
Expected: matches for `from`, `to`, `header_recipes`, `body_recipe`.

Run: `node --check deploy/www/validate/validate.js 2>&1 || perl -e 'my $s=do{local(@ARGV,$/)="deploy/www/validate/validate.js";<>}; my $o=($s=~tr/{//); my $c=($s=~tr/}//); die "brace mismatch $o/$c\n" unless $o==$c; print "braces balanced ($o)\n"'`
Expected: `node` reports no error, or (if node is absent) `braces balanced`.

- [ ] **Step 3: Commit**

```bash
git add deploy/www/validate/validate.js
git commit -m "feat(www): show signature From/To and recovered recipe values in the validator

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Brand message ESP From/To

**Files:**
- Modify: `brong/lib/Mail/DKIM2/Reflector.pm`
- Test: `brong/t/reflector.t`

**Interfaces:**
- Modifies `generate_brand` delegated path only.

- [ ] **Step 1: Update the brand test expectations** (in `brong/t/reflector.t`, the delegated block)

Replace the two existing assertions:
```perl
    is($em->header('From'), 'brand@test1.dkim2.com', 'brand: From is the brand');
    is($em->header('To'), 'reflector-brand@test2.dkim2.com', 'brand: To is reflector-brand');
```
with:
```perl
    is($em->header('From'), 'dkim2demo@test1.dkim2.com', 'brand: From is dkim2demo@<brand>');
    is($em->header('To'), 'brand@test1.dkim2.com', 'brand: To is the sender');
    unlike($em->header('From').'|'.$em->header('To').'|'.$em->header('Subject'),
           qr/dkim2\.com/, 'brand: dkim2.com not in visible From/To/Subject');
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd brong && perl -I lib -I t/lib t/reflector.t 2>&1 | grep -E "brand:|not ok" | head`
Expected: FAIL — From is `brand@test1.dkim2.com`, not `dkim2demo@...`.

- [ ] **Step 3: Change the delegated path in `generate_brand`**

In `brong/lib/Mail/DKIM2/Reflector.pm`, in `generate_brand`'s delegated branch, change the message build and the `i=1` signer args. The `_fresh_message_text` call becomes:
```perl
    my $from = "dkim2demo\@$bd";
    my $text = _fresh_message_text(
        from => $from, to => $a{sender}, subject => 'Brand-signed DKIM2 message',
        body => $body, now => $now, message_id => $a{message_id}, domain => $a{domain},
    );
```
and the `i=1` signer `MailFrom` becomes `$from` (was `$a{sender}`):
```perl
    my %b = (Domain => $bd, Selector => $a{brand_selector},
             MailFrom => $from, RcptTo => [ $rcpt ], Timestamp => $now);
```
(`$rcpt` = `"reflector-brand\@$a{domain}"` stays as the `i=1` `rt`; `i=2` is unchanged.) Update the body's first lines to describe the ESP framing:
```perl
    my $body =
        "Hello,\r\n\r\n"
      . "This is a brand-signed DKIM2 message, sent on $bd's behalf by an ESP\r\n"
      . "that does not show its own identity in the visible headers. It is freshly\r\n"
      . "originated (a single Message-Instance, m=1) but carries TWO DKIM2-Signatures:\r\n\r\n"
      . "  i=1  d=$bd  (signed with the key you delegated via the\r\n"
      . "       dkim2test._domainkey.$bd CNAME to dkim2test._domainkey.$a{domain})\r\n"
      . "  i=2  d=$a{domain}  (the ESP/platform hop out to you)\r\n\r\n"
      . "Paste it into https://$a{domain}/validate/ to see both signatures verify.\r\n\r\n"
      . "-- \r\n"
      . "The DKIM2 reflector at $a{domain}\r\n";
```
(Define `$body` before `_fresh_message_text`, as it already is; just update its text. Keep `$rcpt` defined before both.)

- [ ] **Step 4: Run brand tests + full suite**

Run: `cd brong && perl -I lib -I t/lib t/reflector.t 2>&1 | grep -E "brand:|not ok" | head && prove -I lib -I t/lib t/ 2>&1 | tail -3`
Expected: all `brand:` `ok` (incl. the two-sig verify still passing); `All tests successful.`

- [ ] **Step 5: Commit**

```bash
git add brong/lib/Mail/DKIM2/Reflector.pm brong/t/reflector.t
git commit -m "feat(reflector): brand message reads as ESP-sent (From brand, To sender)

From: dkim2demo@<brand>, To: <sender>; i=1 mf aligns with From, i=1 rt stays
reflector-brand@<domain> in the signature only. dkim2.com no longer appears in
the visible From/To/Subject — only in the i=2 signature and the envelope.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Deploy + verify

**Files:**
- Server: installed libs + `/var/www/dkim2.com/validate/validate.js`.

- [ ] **Step 1: Push**

```bash
git push origin master
```

- [ ] **Step 2: Deploy (libs + validator JS)**

```bash
ssh dkim2 'set -e
cd /root/interop && git pull --ff-only
cd brong && perl Makefile.PL >/dev/null 2>&1 && make >/dev/null 2>&1 && make install 2>&1 | grep -E "Installing.*(Validate|Reflector)" || true
install -m 644 /root/interop/deploy/www/validate/validate.js /var/www/dkim2.com/validate/validate.js
echo "installed validate.js has the new render:"; grep -c "header_recipes" /var/www/dkim2.com/validate/validate.js
echo "installed Validate.pm has body_recipe:"; grep -c "body_recipe" /usr/local/share/perl/5.40.1/Mail/DKIM2/Validate.pm'
```
Expected: `Validate.pm` + `Reflector.pm` reinstalled; both `grep -c` ≥ 1.

- [ ] **Step 3: Verify the report fields via the live API**

Re-validate a known reflect-`both` message (or any 2-hop message) through the live API and confirm the JSON now carries the fields:
```bash
ssh dkim2 'tail -c 4000 /var/spool/reflector-bounces/mbox >/dev/null 2>&1; echo "(use a real two-hop message)"'
```
Or simpler — confirm via the page: paste a `reflector-both`/`reflector-brand` reply into `https://dkim2.com/validate/` and check each signature card shows `from`/`to` and the `m=2` MI card shows `recipe — subject: "…" ← "…"` and `body recipe: diff`.

- [ ] **Step 4: Final brand confirmation**

Send a real message from `brong@brong.net` to `reflector-brand@dkim2.com`. Confirm the reply's `From:` is `dkim2demo@brong.net`, `To:` is `brong@brong.net`, no `dkim2.com` in the visible headers, and the validator shows both signatures with their From/To and **Overall: pass**.

---

## Self-Review

- **Spec coverage:** A1 signature From/To (Task 1 §3 + Task 2), A2 MI recovered values (Task 1 §4 + Task 2), B brand From/To/`mf`/body (Task 3), deploy of validator JS + libs (Task 4). All mapped.
- **Placeholders:** none — all code/commands concrete. The `node --check` step has a brace-balance fallback when node is absent.
- **Type consistency:** `mail_from` (string), `rcpt_to` (arrayref), `header_recipes` (arrayref of `{name,current,previous}`), `body_recipe` (string) — defined in Task 1, rendered in Task 2 with matching names; `$from`/`$rcpt`/`$bd` consistent in Task 3.
