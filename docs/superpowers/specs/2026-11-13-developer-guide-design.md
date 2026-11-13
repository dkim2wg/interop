# dkim2.com: a guide for developers

## Intent

Before the rebuilt site is published, add a page for people building their
own DKIM2: advice on building a signer and a validator, and — its own
section — the single-pass algorithm all five of our verifiers use to check
every Message-Instance in one forward read of the body. That algorithm is
documented today only in code comments (`Mail::DKIM2::BodyPlan`,
`HeaderPlan` and their ports).

## Approaches

1. **The page is the narrative guide; `docs/dkim2-implementer-guide.md`
   stays the reference** — *chosen* (Bron). The page gives what to build, in
   what order, the traps, and the algorithm; it links to the markdown guide
   for tag-by-tag detail and per-language APIs, and the guide links back.
   Nothing written twice.
2. Move the whole 645-line guide onto the site — one place, but the long
   page the redesign just removed.
3. A separate page repeating the essentials — two documents to keep in step.

## Design

`/developers/` — nav item "Developers" between Implementations and
Deployments; same static page style, relative links, in `stage-www.sh`,
covered by `www-links.t` / `www-content.t`. Sections:

1. **Start here** (`#start`) — the spec (-09), the implementer guide
   (reference + APIs), conformance vectors (Turscar `dkim2tests`, our
   `vectors/`), the reflectors and both verifiers to test against,
   `X-DKIM2-Info` for debugging interop.
2. **Building a signer** (`#signer`) — verify the incoming chain before you
   add to it; if you changed the message, add a Message-Instance with a
   Recipe; sign the envelope (`mf=`, `rt=`); `f=exploded` exactly as -09
   §12.5 (copies to more than one address, even if they differ; never on
   `i=1`); fold only where the grammar allows FWS; several algorithms at
   once; operational traps (MTA 8bit→7bit re-encoding after signing; fields
   such as Bcc stripped in transit).
   - **Recipe size:** a recommendation, not spec — keep a Recipe under about
     **100** literal lines; a bigger change is a rewrite.
   - **Null Recipes:** a PERMERROR under -09. Being worked on: allowing a
     null Recipe when the hop also changes the From — presented as a
     proposal, with the "significant changes ⇒ new From" rule.
3. **Building a validator** (`#validator`) — order: structure, Recipes,
   hashes top-down, all before any key is fetched; then signatures and the
   Chain of Custody; Authentic From (relaxed match both ways unless a Domain
   Policy Record forbids it); the 14-day limit; outcomes (PASS, PERMERROR,
   TEMPFAIL, NONE) and "first error found is the one reported";
   `Authentication-Results` (dkim2-authres).
4. **Verifying every instance in one pass** (`#one-pass`) — the problem (the
   undo walk rebuilds every earlier body in turn); the idea (each instance's
   body as a segment list — runs of current-body lines and Recipe literals —
   composed from its parent's by applying the parent's Recipe; copy ranges
   ascend, so every list is in body order); one streamed read, each line to
   every instance holding it; trailing blank lines held as a pending count;
   identical lists share digests; headers the same way per field name; key
   prefetch at end of headers. A worked three-instance HTML/CSS diagram,
   short pseudo-code, measured gains (~4x on a five-domain live chain; 10 MB
   bodies in milliseconds), pointers to the five implementations and their
   parity testing against the undo walk (~4780 corpus messages).
5. **Testing** (`#testing`) — vectors, reflectors, the cross-implementation
   matrix.

The implementer guide gains a link to the page, and its one-line streaming
mention points to `#one-pass`.

## Constraints

- -09 is the reference; anything beyond it (100-line Recipe guidance, null
  Recipe with From change, From rule) is labelled as recommendation or
  proposal.
- Our implementations keep their 1000-literal-line cap; not changed here.
- Ships with the site: previewed at `/preview/` first, then merged together
  with `review2-perl` to master and deployed.

## Left to the builder

Prose, diagram styling, pseudo-code language (plain, not a real language),
exact benchmark figures (from the memory/bench notes, rounded).
