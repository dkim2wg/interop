# DKIM2 Message-Instance support for Sympa 6.2.78

Three patches that make Sympa record, in a `Message-Instance` header, what
it changed about each message it redistributes, so a DKIM2 verifier
downstream can undo the list's changes and check the signatures of earlier
hops. Sympa adds only `Message-Instance` (and `X-DKIM2-Info`); the
`DKIM2-Signature` is added by the MTA (see the [Postfix mailing-list host
guide](../docs/dkim2-postfix-list-host-guide.md)).

The same three commits are the `dkim2` branch of
<https://github.com/brong/sympa>, which is what these patches are exported
from. The design is described in that branch's `DKIM2-MESSAGE-INSTANCE.md`,
which patch 2 adds.

## The patches

1. **Add the dkim2_message_instance list parameter.** An `on`/`off` list
   parameter (with robot and site defaults), off by default. With it off a
   list behaves exactly as stock 6.2.78.
2. **Add DKIM2 Message-Instance support with always-wrap decoration.**
   New module `Sympa::DKIM2`, with hooks in `Sympa::Message` and the
   spindles. At ingress (`ProcessIncoming`, before S/MIME decryption) the
   message is recorded as received, `m=1` added if it has no instance, and
   the header block kept in the `X-Sympa-DKIM2-Headers` pseudo-header,
   which travels through every spool with the message. Decoration wraps the
   original body, byte for byte, as the middle part of a `multipart/mixed`
   between the list's header and footer parts, so the body Recipe is one
   copy range. At egress (`ProcessOutgoing`), after all transformations and
   before DKIM signing, each copy gets the next `m=`, its header Recipe from
   diffing the saved header block against the outgoing one. A body changed
   any other way (txt, html, urlize and notice modes, full-body
   personalisation, S/MIME, content filters) gets a null body Recipe.
   Anonymous lists and resends from the archive strip the chain instead.
   Includes `t/DKIM2.t` and `DKIM2-MESSAGE-INSTANCE.md`.
3. **Add the X-DKIM2-Info debug header.** One above every Message-Instance
   Sympa adds, naming the draft, implementation date, action and hashed
   header fields, so an interop problem can be diagnosed from the message.

The series before the always-wrap rework (encoding-preserving decoration,
a `.mi_orig` spool file, Recipes by diff) is kept as the tag
`dkim2-cte-preserve-6.2.78` in the fork. It is not maintained.

## What they apply to

Sympa **6.2.78** only: the series is based on that tag and applies cleanly
there. Older packages are not supported.

## Dependencies

`Sympa::DKIM2` loads `Mail::DKIM2::MessageInstance` and
`Mail::DKIM2::Common` from the Mail-DKIM2 Perl distribution, version 0.15
or later (source in [`../perl`](../perl); `cpanm Mail::DKIM2` once 0.15 is
on CPAN). It is loaded only for lists with the switch on; a list with the
switch on and no Mail::DKIM2, or one older than 0.15, logs an error and
runs as stock. Nothing else is needed beyond what 6.2.78 itself requires.

## Installing

Apply to a 6.2.78 source tree and build as usual:

```bash
git clone https://github.com/sympa-community/sympa.git && cd sympa
git checkout 6.2.78
git -c user.name=ops -c user.email=ops@example.org am /path/to/interop/sympa/patches-6.2.78/*.patch
autoreconf -i            # needs the autopoint package (gettext)
./configure --enable-fhs --prefix=/usr --sysconfdir=/etc/sympa --localstatedir=/var \
    --with-user=sympa --with-group=sympa ...
make && make install
sympa upgrade --from=OLD --to=6.2.78    # as the sympa user, if replacing an older install
```

If you re-run `./configure` with different paths, `make clean` before
`make`: the C queue wrappers bake the configuration path in at compile time
and are not rebuilt for a changed define. `--enable-fhs` selects the
Filesystem Hierarchy layout; the remaining
`--with-*dir` options should match the install you are replacing (compare
the generated `src/lib/Sympa/Constants.pm` with the installed one before
`make install`). 6.2.78 needs `Archive::Zip::SimpleUnzip`,
`Archive::Zip::SimpleZip` and `Unicode::UTF8`, which a distribution's
6.2.76 package did not; `cpanm` them if `perl -c wwsympa.fcgi` complains.

Or overlay the patched files onto an installed 6.2.78 (an older install,
such as a distribution's 6.2.76 package, is not a supported base: its
`Message.pm` differs and the overlay then needs files from 6.2.78 that the
patches do not carry):

```
src/lib/Sympa/Config/Schema.pm
src/lib/Sympa/DKIM2.pm                     (new)
src/lib/Sympa/Message.pm
src/lib/Sympa/Spindle/ProcessArchive.pm
src/lib/Sympa/Spindle/ProcessIncoming.pm
src/lib/Sympa/Spindle/ProcessOutgoing.pm
src/lib/Sympa/Spindle/ResendArchive.pm
```

Then in `sympa.conf`:

```
# Submit outbound mail to the MTA's signing listener (see the guide).
sendmail /usr/local/bin/sympa-sendmail
# One recipient per transaction, so each signed copy's rt= names only its
# own recipient. See the guide, "Recipient privacy".
nrcpt 1
```

`sympa-sendmail` is in [`../deploy/examples/`](../deploy/examples/). Restart
`sympa sympa-bulk sympa-archived sympa-bounced sympa-task_manager wwsympa`;
all of them load `Message.pm`.

The outbound signer must accept null body Recipes: `dkim2-milter` signs
such a message only when started with `--allow-null-body-recipe` (the
example outbound unit has it).

## Turning it on

Nothing changes until a list has the switch on. In the list's `config`
(or in the list's web admin, with the other DKIM parameters):

```
dkim2_message_instance on
```

The same line in `robot.conf` or `sympa.conf` sets the default for a robot
or the whole site. A message already in a spool when the switch is turned
on has no saved header block and goes out without a new instance.

## Regenerating the series

```bash
util/export-list-patches.sh          # from the fork checkouts
util/export-list-patches.sh --check  # apply-check against the base above
```
