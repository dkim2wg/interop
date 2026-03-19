# DKIM2 Porting Plan — Proposed Patches for Existing DKIM Software

**Date:** 2026-03-18
**Spec:** draft-clayton-dkim2-spec-08
**Reference implementations:** `brong/` (Perl), `python/` (Python)

## Goal

Produce proposed patches adding DKIM2 support to the most widely-used
open source DKIM implementations, enabling real-world deployment and
interoperability testing beyond the hackathon reference code.

---

## What DKIM2 Requires Beyond DKIM

Every target needs these capabilities added:

1. **New header type**: `DKIM2-Signature` with tags including `i=` (sequence
   number), `m=` (SMTP parameters: `mf=`, `rt=`), and an `s=` tag supporting
   multiple simultaneous algorithms (RSA + Ed25519).

2. **Message-Instance (MI) headers**: Document changes made by intermediaries
   using recipes (copy ranges and replacements). Support `calculate()`,
   `verify()`, and `undo()` operations.

3. **Chain-of-custody verification**: Validate a complete chain of signatures
   (i=1, i=2, ...) with no gaps. Each hop's signature covers all prior MI
   and DKIM2-Signature headers.

4. **Signing input construction**: All Message-Instance headers, then all
   prior DKIM2-Signature headers, then the current DKIM2-Signature with
   empty `s=` — as specified in draft-clayton-dkim2-spec-08.

5. **Body hash**: SHA256 of body with simple canonicalization (strip trailing
   CRLF).

6. **Header hash**: SHA256 of selected headers in message order, excluding
   Received, Return-Path, MI, DKIM2-Signature, X-\*, DKIM-Signature, ARC-\*.

7. **Domain alignment**: `d=` must match `mf=` domain at each hop.

8. **JSON handling**: The MI recipe format requires JSON parsing/generation.

---

## Patch Strategy

**Parallel implementation, not modification.** For each target:

- Add DKIM2 as new modules/files alongside existing DKIM code
- Never modify existing DKIM signing/verification paths
- Allow DKIM and DKIM2 to coexist on the same message
- Keep patches self-contained and reviewable

**Port from reference implementations.** The `brong/` (Perl) and `python/`
(Python) code in this repo are the source of truth. Each patch should be
a fresh implementation following the spec, using the reference code to
resolve ambiguities.

**Include interop tests.** Use test messages from `brong/tests/expected/`
and `python/tests/expected/` to verify cross-implementation compatibility.

---

## Targets

### Phase 1 — Libraries (highest leverage)

Patching libraries gives DKIM2 to all downstream consumers at once.

#### 1a. dkimpy (Python)

- **Repository:** https://git.launchpad.net/dkimpy (canonical), GitHub mirrors exist
- **Language:** Python
- **License:** BSD-like
- **Maintainer:** Scott Kitterman (IETF-active, likely receptive)
- **DKIM code:** `dkim/` package — `dkim/dkimsign.py`, `dkim/dkimverify.py`,
  canonicalization, DNS key lookup. Supports ARC, Ed25519.
- **Approach:**
  - Add `dkim/dkim2sign.py`, `dkim/dkim2verify.py`, `dkim/messageinstance.py`
  - Adapt from `python/dkim2sign.py` and `python/dkim2verify.py` in this repo
  - The existing `python/` code already demonstrates all required operations
    in Python — this is largely a matter of fitting it into dkimpy's API
    conventions and class structure
  - Add `dkim/dkim2canon.py` for any canonicalization differences
  - Extend DNS key lookup for DKIM2 selector format
  - Tests using interop test messages
- **Complexity:** Medium
- **Leverage:** High — dkimpy is the standard Python DKIM library, used by
  many tools and services

#### 1b. Mail::DKIM (Perl)

- **Repository:** https://github.com/fastmail/mail-dkim (upstream),
  https://github.com/marcbradshaw/mail-dkim (active maintainer)
- **Language:** Perl
- **License:** Artistic 2.0 / GPL (standard Perl dual)
- **Maintainer:** Marc Bradshaw / Fastmail
- **DKIM code:** `lib/Mail/DKIM/` — `Signer.pm`, `Verifier.pm`,
  `Signature.pm`, `Canonicalization/`, `Algorithm/`. Streaming API
  (PRINT/CLOSE), supports ARC.
- **Approach:**
  - Add `lib/Mail/DKIM2/` subtree mirroring the existing structure
  - The `brong/lib/Mail/DKIM2/` code in this repo is a complete working
    implementation with the same streaming API pattern
  - Adapt to fit Mail::DKIM's class hierarchy and conventions
  - `DKIM2::Signer`, `DKIM2::Verifier`, `DKIM2::Signature`,
    `DKIM2::MessageInstance`
  - Reuse Mail::DKIM's existing crypto and canonicalization where applicable
  - Tests using interop test messages
- **Complexity:** Medium
- **Leverage:** High — Mail::DKIM is used by Amavisd-new, DKIMproxy,
  SpamAssassin, and many Perl-based mail systems

#### 1c. emersion/go-msgauth (Go)

- **Repository:** https://github.com/emersion/go-msgauth
- **Language:** Go
- **License:** MIT
- **Maintainer:** Simon Ser (emersion), responsive to PRs
- **DKIM code:** `dkim/` package — `sign.go`, `verify.go`, `header.go`,
  `canon.go`, `query.go`, `signature.go`. Clean, well-factored.
- **Approach:**
  - Add `dkim2/` package alongside existing `dkim/`
  - Implement `Sign()`, `Verify()` functions following go-msgauth conventions
  - Add `messageinstance.go` for MI header handling
  - JSON handling via stdlib `encoding/json`
  - New implementation from spec (Go has no existing reference to port from)
  - Tests using interop test messages
- **Complexity:** Medium
- **Leverage:** Very high — used by Maddy, dkim-milter, and other Go mail
  software. MIT license is contribution-friendly.

#### 1d. stalwartlabs/mail-auth (Rust)

- **Repository:** https://github.com/stalwartlabs/mail-auth
- **Language:** Rust
- **License:** Apache 2.0 / MIT dual
- **Maintainer:** mdecimus (Stalwart Labs), responsive
- **DKIM code:** `src/dkim/` — signing, verification, canonicalization,
  DNS lookup. Supports Ed25519, ARC, DMARC.
- **Approach:**
  - Add `src/dkim2/` module alongside existing `src/dkim/`
  - New implementation from spec
  - Leverage existing crypto (ring/rustcrypto) and DNS infrastructure
  - Rust's type system will enforce correctness of chain validation
  - Tests using interop test messages
- **Complexity:** Medium-High (Rust)
- **Leverage:** High — Stalwart is gaining significant traction as a modern
  all-in-one mail server

---

### Phase 2 — High-Impact Deployments

#### 2a. Rspamd

- **Repository:** https://github.com/rspamd/rspamd
- **Language:** C (core) + Lua (plugins)
- **License:** Apache 2.0
- **Maintainer:** Vsevolod Stakhov, active community
- **DKIM code:** Core in `src/libserver/dkim.c`, signing/verification policy
  in Lua plugins (`src/plugins/lua/dkim_signing.lua` etc.)
- **Approach:**
  - **Phase A (prototype):** Implement DKIM2 as a Lua plugin first, using
    Rspamd's existing crypto FFI bindings. This allows rapid iteration
    without touching C code.
  - **Phase B (production):** Port core DKIM2 operations to C in
    `src/libserver/dkim2.c` for performance, keeping Lua policy layer.
  - The Lua prototype is valuable on its own — Rspamd's Lua API is powerful
    enough for production use.
- **Complexity:** High (large codebase), but Lua layer reduces initial barrier
- **Leverage:** Very high — Rspamd is the default DKIM solution for many
  Postfix deployments

#### 2b. Exim

- **Repository:** https://github.com/Exim/exim (mirror of git.exim.org)
- **Language:** C
- **License:** GPL v2+
- **Maintainer:** Exim maintainers team, active
- **DKIM code:** `src/src/dkim.c`, `src/src/dkim.h`, `src/src/dkim_transport.c`.
  Custom C implementation (originally derived from libdkim, heavily modified).
  Signing via transport options, verification via `acl_smtp_dkim` ACL.
- **Approach:**
  - Add `src/src/dkim2.c`, `src/src/dkim2.h`, `src/src/dkim2_transport.c`
  - New transport options: `dkim2_domain`, `dkim2_selector`, `dkim2_private_key`,
    `dkim2_mi_recipe` etc.
  - New ACL condition `acl_smtp_dkim2` with expansion variables:
    `$dkim2_verify_status`, `$dkim2_chain_status`, `$dkim2_domain`,
    `$dkim2_sequence` etc.
  - JSON parsing will need a small JSON library (Exim doesn't currently
    bundle one) or a minimal inline parser
  - Tests using Exim's existing test framework (`test/` directory)
- **Complexity:** High — deep C integration, needs new ACL variables,
  transport options, and JSON support
- **Leverage:** High — Exim has significant deployment, especially in
  academic and European hosting environments

#### 2c. OpenDKIM / libopendkim

- **Repository:** https://github.com/trusteddomainproject/OpenDKIM
- **Language:** C
- **License:** BSD
- **Maintainer:** Trusted Domain Project (semi-dormant; 2.11.0 beta after
  3-year gap, recent Debian packaging activity)
- **DKIM code:** `libopendkim/` (library), `opendkim/` (milter daemon).
  Library provides `dkim_sign()`, `dkim_verify()`, key management, DNS lookup.
- **Approach:**
  - Add `libopendkim2/` or extend libopendkim with `dkim2_*` API functions
  - Add `opendkim2/` milter or extend existing milter with DKIM2 mode
  - Alternatively: create a standalone `dkim2-milter` that links libopendkim
    for crypto but implements DKIM2 protocol independently (lower risk,
    avoids entangling with dormant upstream)
  - JSON parsing via jansson or cJSON (small C JSON libraries)
- **Complexity:** High — large legacy C codebase
- **Leverage:** Highest historical deployment, but uncertain upstream velocity.
  A standalone milter may be more practical than patching OpenDKIM itself.
- **Note:** The `brong/bin/dkim2-milter.pl` standalone milter already exists
  as an alternative path for Postfix/Sendmail users who don't want to wait
  for OpenDKIM patches.

---

### Phase 3 — Ecosystem Breadth

#### 3a. postalsys/mailauth (Node.js)

- **Repository:** https://github.com/postalsys/mailauth
- **Language:** JavaScript (Node.js)
- **License:** MIT
- **Maintainer:** Andris Reinman (very active, responsive)
- **DKIM code:** `lib/dkim/` — `sign.js`, `verify.js`, body hash, header
  canonicalization, key retrieval. Supports multiple algorithms.
- **Approach:**
  - Add `lib/dkim2/` directory with signing, verification, MI handling
  - New implementation from spec
  - Node.js has native JSON support (trivial)
  - Andris is likely to be interested given his email ecosystem involvement
- **Complexity:** Medium
- **Leverage:** Medium — used by Haraka (via haraka-plugin-mailauth) and
  other Node.js mail tools

#### 3b. Haraka

- **Repository:** https://github.com/haraka/Haraka,
  https://github.com/haraka/haraka-plugin-dkim
- **Language:** JavaScript (Node.js)
- **License:** MIT
- **Approach:**
  - Create `haraka-plugin-dkim2` as a new npm package
  - Use mailauth's DKIM2 support (from 3a) as the underlying library
  - Plugin hooks: `hook_data_post` for signing, `hook_data` for verification
  - Minimal code — mostly wiring mailauth into Haraka's plugin API
- **Complexity:** Low (if mailauth is done first)
- **Leverage:** Medium — Haraka has a niche but loyal deployment base

#### 3c. Nodemailer (signing only)

- **Repository:** https://github.com/nodemailer/nodemailer
- **Language:** JavaScript (Node.js)
- **License:** MIT/EUPL
- **DKIM code:** `lib/dkim/` — signing only (Nodemailer sends, doesn't verify)
- **Approach:**
  - Add DKIM2 signing support alongside existing DKIM signing
  - Narrower scope: only signing, no verification or chain validation
  - Could use mailauth's DKIM2 signing (from 3a) or implement directly
- **Complexity:** Low
- **Leverage:** High for outbound mail — Nodemailer is extremely widely used
  for sending

#### 3d. Maddy (Go)

- **Repository:** https://github.com/foxcpp/maddy
- **Language:** Go
- **License:** GPL v3
- **DKIM code:** `internal/modify/dkim/` (signing), `internal/check/dkim/`
  (verification). Delegates to go-msgauth.
- **Approach:**
  - Add `internal/modify/dkim2/` and `internal/check/dkim2/` modules
  - Wire in go-msgauth's DKIM2 support (from 1c)
  - Follow existing DKIM module patterns for configuration and integration
- **Complexity:** Low (if go-msgauth is done first)
- **Leverage:** Medium — Maddy is popular for self-hosted mail

---

## Execution Order

```
Phase 1: Libraries — prove DKIM2 works in 4 language ecosystems
  ┌─ 1a. dkimpy (Python)  ──── closest to existing python/ reference code
  ├─ 1b. Mail::DKIM (Perl) ─── closest to existing brong/ reference code
  ├─ 1c. go-msgauth (Go)  ──── unlocks Maddy + Go ecosystem
  └─ 1d. mail-auth (Rust)  ─── unlocks Stalwart + Rust ecosystem

  These four can be worked in parallel. 1a and 1b are fastest since
  reference code exists in the same language.

Phase 2: Major deployments — reach the systems that handle real mail
  ┌─ 2a. Rspamd (Lua prototype first, then C)
  ├─ 2b. Exim (C, deep integration)
  └─ 2c. OpenDKIM (C, or standalone milter alternative)

  These require more effort and upstream coordination. Start with
  Rspamd's Lua prototype as it's the fastest path to a working
  deployment.

Phase 3: Ecosystem breadth — fill remaining gaps
  ┌─ 3a. mailauth (Node.js)  ─── unlocks Haraka + Node.js ecosystem
  ├─ 3b. Haraka (plugin, depends on 3a)
  ├─ 3c. Nodemailer (signing only, depends on 3a or standalone)
  └─ 3d. Maddy (depends on 1c)
```

---

## Per-Target Workflow

For each target, follow this process:

1. **Clone** the upstream repository
2. **Study** the existing DKIM signing and verification flow — identify key
   functions, data structures, and extension points
3. **Create a branch** named `dkim2-support` (or similar)
4. **Implement** DKIM2 as new files/modules alongside existing DKIM code:
   - Signature header parsing/generation (DKIM2-Signature format)
   - Signing input construction (all MI, then all prior sigs, then current sig with empty s=)
   - Body hash computation
   - Header hash computation (with correct include/exclude rules)
   - Multi-algorithm signature support (s= tag)
   - Message-Instance header handling (calculate, verify, undo)
   - Chain-of-custody verification
   - SMTP parameter tracking (m= tag with mf=, rt=)
5. **Test** against interop test messages from this repository
6. **Write documentation** (configuration options, usage examples)
7. **Submit PR** to upstream with clear explanation and spec reference

---

## Common Implementation Challenges

These issues were identified during hackathon interop testing:

1. **Header folding**: Three categories requiring different treatment:
   - Headers being created: fold freely at tag boundaries and inside base64 data
   - Headers read from network: only refold at existing whitespace
   - Headers in signing input: use as-is, canonicalization handles it

2. **Empty s= for signing**: When constructing the signing input, the
   DKIM2-Signature being signed must use empty `s=` (analogous to DKIM1's
   empty `b=` convention).

3. **JSON dependency**: Most DKIM implementations don't currently need JSON.
   C projects (OpenDKIM, Rspamd, Exim) will need to add a JSON library or
   write a minimal parser for MI recipe handling.

---

## Dependencies and Prerequisites

- **Spec stability**: draft-clayton-dkim2-spec-08 is the current reference.
  Some spec ambiguities remain (see `brong/spec-review-notes.md`). Patches
  should note they target this specific draft version.

- **DNS records**: DKIM2 uses a different DNS record format. Test domains
  and keys are available in `keys/` and `dns.json` in this repository.

- **Interop test suite**: Cross-implementation test messages are in
  `brong/tests/expected/` and `python/tests/expected/`. These should be
  used as acceptance tests for all patches.

---

## Lower-Priority Targets (not planned for initial effort)

These are worth tracking but not prioritized for the first round:

| Project | Language | Notes |
|---------|----------|-------|
| Amavisd-new | Perl | Uses Mail::DKIM — gets DKIM2 for free from 1b |
| Alt-N/libdkim | C | Niche, low activity |
| redsift/dkim | Go | Verification only, low activity |
| PHPMailer | PHP | Signing only, large user base but email-sending focused |
| Apache James | Java | Enterprise Java, separate ecosystem |
| MimeKit | .NET | .NET ecosystem, niche for mail servers |
| Ruby dkim/dkimverify | Ruby | Very small user base |
| python-dkim (Scaleway) | Python | Wraps libopendkim — gets DKIM2 from 2c |

---

## Success Criteria

- DKIM2 signing and verification works in at least 4 language ecosystems
- Cross-implementation interop tests pass (messages signed by one
  implementation verify in all others)
- At least one production-ready milter/filter (Rspamd or standalone) that
  can be deployed with Postfix/Sendmail
- Upstream PRs submitted to all Phase 1 and Phase 2 targets
