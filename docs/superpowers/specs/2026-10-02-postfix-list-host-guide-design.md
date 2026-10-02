# DKIM2 for a Postfix mailing-list host: guide and packaging

**Date:** 2026-10-02
**Status:** approved design, awaiting implementation plan

## Purpose

A mailop reader running Postfix wants a mailing-list host that participates
in DKIM2: verify inbound mail, have Mailman 3 (first) or Sympa record
Message-Instance headers for the changes it makes, and sign outbound list
mail without putting every subscriber's address in one `rt=`. They need one
trustworthy guide and installable pieces, not a tour of the dkim2.com demo
box.

Success: someone who has never seen this repository follows the guide end to
end on a fresh Debian or Ubuntu host and gets `dkim2=pass` on list mail at a
receiving verifier, with each delivered copy's `rt=` naming only its own
recipient.

## Decisions already made

- Mailman changes ship as a patch series exported from the `brong/mailman`
  `dkim2` branch, with the fork as the ready-made install. Not a plugin: the
  change inserts pipeline handlers and delivery mixins into core classes.
- Both milters are documented as equal, self-contained paths: the standalone
  `dkim2-milter` (Sendmail::PMilter) and the authentication_milter handlers
  `Mail::Milter::Authentication::Handler::DKIM2Sign` / `DKIM2Verify`.
- The guide lives in the interop repository as Markdown, rendered by GitHub,
  linked from dkim2.com and from the Perl README. The mailop reply is a short
  note with the link.
- Mailman is documented first and most fully; Sympa gets a complete but
  shorter section.
- One Perl distribution. The dist split considered during the API cleanup is
  dropped: the milter, the split daemon and the handlers all install from
  `Mail-DKIM2`.

## Deliverables

### 1. The guide: `docs/dkim2-postfix-list-host-guide.md`

Audience: a Postfix operator comfortable with `main.cf`, systemd and
installing Perl and Python packages. Written in build order; each step ends
with a check the reader can run. Sections:

1. **What you get and how mail flows.** A diagram: inbound SMTP → verify
   milter (adds Authentication-Results and the `m=1` Message-Instance) →
   list manager (records its changes as `m=2` with a Recipe) → loopback
   signing port → sign milter → delivery. States plainly what DKIM2 does
   and does not tell a recipient (from the operator guide's "What a result
   does not tell you").
2. **Prerequisites.** Debian/Ubuntu with Postfix, Perl 5.20+, DNS control
   for the list domain, and which of Mailman 3 or Sympa is already
   installed. Links to the operator guide for the protocol background.
3. **Keys and DNS.** Generate Ed25519 and RSA keys, publish the TXT
   records, the key directory layout (`/etc/dkim2/keys/<domain>/<selector>.key`)
   both milters read. Reuses and corrects the operator guide's text; the
   operator guide then links here instead of repeating it.
4. **Install Mail::DKIM2.** From a release tarball, or clone the interop
   repository and `cpanm .` in `perl/`; what it installs (`dkim2sign`, `dkim2verify`, `dkim2-milter`, `dkim2-split-lmtp`,
   the handlers), the dependency list, and `dkim2verify` as the first check.
5. **The milter.** Two subsections of equal weight, each complete on its
   own so the reader follows one and skips the other:
   - **5a. Standalone `dkim2-milter`.** Two instances, inbound (verify,
     stamp `m=1`, snapshot) and outbound (diff against the snapshot, sign),
     from the example systemd units; the socket paths inside the Postfix
     chroot; the Sendmail::PMilter null-sender patch (why it is needed, how
     to apply it, how to tell it is missing).
   - **5b. authentication_milter.** Installing Mail::Milter::Authentication,
     the DKIM2Verify and DKIM2Sign handler JSON with a shared
     `snapshot_directory`, `ignore_header_prefixes`, and how
     `sign_authenticated`/`sign_local` decide what gets signed.
6. **Postfix.** `smtpd_milters` for port 25, a loopback listener for list
   submission that runs only the signing milter, bounce signing
   (`internal_mail_filter_classes = bounce`, `non_smtpd_milters`,
   `disable_mime_output_conversion = yes` and why), `milter_default_action`.
   Then **recipient privacy**: the signer records the transaction's RCPT TO
   in `rt=`, so list mail must be one recipient per transaction. The simple
   route first: Mailman `max_recipients: 1`, Sympa `nrcpt 1`. The split
   gateway (`dkim2-split-lmtp` on a content_filter) as the general solution
   for hosts that also accept mail from software they cannot configure that
   way.
7. **Mailman 3.** Install the fork (`pip install` from the `dkim2` branch
   into the Mailman venv) or apply the patch series from `mailman/` to a
   checkout; run the Alembic migration; `mailman.cfg` (`[mta]
   message_instance: yes`, `smtp_port` pointing at the signing listener,
   `max_recipients: 1`); the per-list `dkim2_message_instance` flag through
   the REST API; where the handler logs; the `mi-cache` directory.
8. **Sympa.** Apply the patch series from `sympa/` to a 6.2.78 source tree,
   or overlay the listed files onto the distro package (with the
   `URIFind.pm` and `liburi-find-perl` dependency called out, since
   copying `Message.pm` alone has caused an outage); `sympa.conf`
   (`sendmail` pointing at a wrapper that submits to the signing listener,
   `nrcpt 1`); the services to restart.
9. **Check it works.** Post to a test list; read the headers
   (`Authentication-Results`, `Message-Instance`, `DKIM2-Signature`,
   `X-DKIM2-Info`); run `dkim2verify` on a captured copy; paste it into
   https://dkim2.com/validate/; mail the dkim2.com reflector addresses to see
   the chain verified by another implementation.
10. **Operations.** Key rotation, snapshot and cache cleanup, log lines to
    watch, and troubleshooting: the `Delivered-To` trap for anything
    invoked from `local(8)`, transport encoding conversion breaking hashes,
    `temperror` from DNS, the 14-day timestamp window, `permerror
    Message-Instance m=N is not signed` when the list stamps but nothing
    signs.
11. **What is not covered.** The reflector, the validator, DSN propagation,
    and the test domains are dkim2.com demo machinery and stay in
    `deploy/SERVER.md`.

Style: plain prose, short sentences, every command in a fenced block,
no reference to dkim2.com-specific paths or history except as a working
example. The guide names the spec revision it was written against.

### 2. Perl distribution changes

- `perl/bin/dkim2-milter.pl` → `perl/bin/dkim2-milter`;
  `perl/bin/dkim2-split-lmtp.pl` → `perl/bin/dkim2-split-lmtp`. Both added
  to `EXE_FILES`. Both keep working from a checkout (`-I lib`). Their POD
  becomes the installed man pages, so it is brought up to the 0.10
  conventions (no "do not use in production"; `=encoding`).
- `Makefile.PL`: Sendmail::PMilter, Net::SMTP, Sys::Syslog declared as
  runtime recommends; `Mail::Milter::Authentication` and
  `Mail::AuthenticationResults` as recommends for the handlers.
- `perl/README` points at the guide.
- The deploy units, `deploy.sh`, `SERVER.md`, `util/` scripts and tests that
  name the old script paths are updated. The dkim2.com box keeps running
  the scripts from its checkout through `deploy.sh` as now.

### 3. Patch series: `mailman/` and `sympa/`

The fork branches are first rewritten into minimal series, so the branch an
operator installs from and the patches they read are the same thing:

- `brong/mailman` `dkim2` (4 commits on upstream master `687b9e4dc`,
  v3.3.10+466) becomes 3: encoding-preserving decoration; Message-Instance
  handlers, mixin, config, tests and docs, with the debug-header-01
  `X-DKIM2-Info` form folded in; the per-list `dkim2_message_instance`
  flag.
- `brong/sympa` `dkim2` (18 commits on tag `6.2.78`) becomes 3:
  encoding-preserving decoration (the four body-stability commits);
  Message-Instance support with `t/Message_DKIM2.t` and
  `DKIM2-MESSAGE-INSTANCE.md`; the `X-DKIM2-Info` header in its final form.
  The version-bump commits disappear into the commits they amended.

Before each rewrite the old history is tagged `dkim2-history-2026-10-02`
and the tag pushed; the rewritten branch is force-pushed to the `brong`
remote. Each series is checked with `git apply --check` against its base
and the net diff against the old branch tip must be empty (the rewrite
changes history, not content). The dkim2.com deploy procedure for both is
unchanged (rsync of the same files from the branch checkout).

Each directory in the interop repository then holds:

- `README.md`: what the patches do, the upstream base they apply to (commit
  and tag), how to apply (`git am` to a checkout; for Mailman also `pip
  install` of the fork branch), and how they were generated.
- `patches/NNNN-*.patch` from `git format-patch <base>..dkim2` in the
  respective fork checkout.

`util/export-list-patches.sh` regenerates both series from `~/src/mailman`
and `~/src/sympa` (paths overridable) and, with `--check`, verifies with
`git apply --check` that each series still applies to its stated base. For
Mailman it also tries the series against the latest release tag (`v3.3.10`)
and the README records the result. For Sympa the README notes that the
6.2.76 distro package also needs `src/lib/Sympa/HTML/URIFind.pm` (present
upstream from 6.2.78) and the `liburi-find-perl` package.

### 4. Operator templates: `deploy/examples/`

Generic versions of what the dkim2.com box runs, free of its paths:

- `dkim2-milter-inbound.service`, `dkim2-milter-outbound.service` using the
  installed `/usr/local/bin/dkim2-milter`.
- `dkim2-split.service` for the split gateway.
- `postfix-main.cf.fragment`: milter and bounce-signing settings.
- `postfix-master.cf.fragment`: the loopback signing listener, and the split
  entry and re-injection listeners.
- `authentication_milter.json.fragment`: DKIM2Verify and DKIM2Sign handler
  sections.
- `sympa-sendmail`: the submission wrapper, parameterised by port.

### 5. Links and trims

- `deploy/www/index.html` "Learn more" gains "Run your own DKIM2 list host"
  pointing at the guide on GitHub.
- `docs/dkim2-operator-guide.md`: the "Milter integration" paragraph is
  replaced by a pointer to the guide; DNS key generation stays here and the
  guide links to it rather than duplicating it.
- `deploy/README.md` opens with one line saying it describes the dkim2.com
  demo box and that operators want the guide.

## Validation

- `util/export-list-patches.sh --check` passes for both series.
- The Perl suite passes after the script renames; `make distcheck` is
  clean; `dkim2-milter --help` and `dkim2-split-lmtp` run from the installed
  location on the dkim2.com box after `deploy.sh`.
- `deploy/dkim2-list-smoke.sh` passes on the box after deploy (Mailman and
  Sympa lists both verify).
- A read-through of the guide against the box's live configuration
  (`deploy/config/`) confirms every setting named exists and does what the
  guide says.

## Out of scope

- A CPAN upload itself (the dist is ready for one; uploading is a separate
  step for Bron).
- Upstreaming the Mailman or Sympa changes (the squashed series is the
  natural starting point for that, but it is a separate conversation).
- Rewriting the dkim2.com `SERVER.md`.
- Debian or RPM packaging.
