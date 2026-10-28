#!/usr/bin/env python3
"""
DKIM2 message-instance undo - draft-ietf-dkim-dkim2-spec-08

Takes a signed email with Message-Instance headers containing recipes
and reconstructs the message as it was at a previous version.

The verifier's reference walk (dkim2verify walk="undo") rebuilds each
version with reconstruct_headers()/reconstruct_body(); its default planned
walk (dkim2plan) must give the same hashes and Recipe errors.
"""

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

from dkim2sign import (
    parse_message,
    _header_name,
    _extract_tag,
    _get_version_from_mi,
    compute_header_hash,
    compute_body_hash,
    b64,
)


# ---------------------------------------------------------------------------
# Recipe parsing
# ---------------------------------------------------------------------------

class Unrecoverable(ValueError):
    """The previous body cannot be reconstructed *by design*.

    -08 §5.2/§16.3: a present "b" that is JSON null is the upstream
    saying the previous body cannot be put back (a "null Recipe") -- distinct
    from an absent "b", which means the body was not modified. That is not a
    defect in the message, so it gets its own type: DSN propagation answers it
    by returning the header fields alone, while every other reconstruction
    failure stays a plain ValueError and must not be papered over.
    """


def decode_recipes(mi_hdr: str) -> dict | None:
    """Decode the r= tag from a Message-Instance header.

    Returns the parsed JSON object, or None if no r= tag.
    """
    colon = mi_hdr.find(":")
    value = mi_hdr[colon + 1:] if colon != -1 else mi_hdr
    r_b64 = _extract_tag(value, "r")
    if not r_b64:
        return None
    return loads_recipe(base64.b64decode(r_b64))


_UPPER = re.compile(r"[A-Z]")


def _strict_keys(pairs):
    """object_pairs_hook for Recipe JSON (-08 §5, contract D10): every key,
    at any level, MUST be lower case, and a key given twice in one object
    (compared exactly) is a duplicate.  Either is a ValueError, as for any
    invalid JSON.  "Lower case" is judged on ASCII letters: header field
    names are ASCII, and no other key is defined."""
    obj = {}
    for k, v in pairs:
        if _UPPER.search(k):
            raise ValueError(f"JSON object key {k!r} is not lower case")
        if k in obj:
            raise ValueError(f"duplicate JSON object key {k!r}")
        obj[k] = v
    return obj


def _no_float(text):
    """Contract D6: a JSON number with a fraction or an exponent, wherever
    it is ("1.5", "1e0", "1.0"), makes the whole Recipe invalid JSON.  JSON
    libraries disagree on whether 1e0 is an integer, so it is judged from
    the text: json calls this for exactly those numbers."""
    raise ValueError(f"JSON number {text!r} is not an integer")


def _no_constant(text):
    # NaN, Infinity and -Infinity are not JSON (RFC 8259 §6).
    raise ValueError(f"{text!r} is not JSON")


def loads_recipe(data):
    """json.loads for Recipe JSON.  A key that is not lower case, or an
    object that gives a key twice, is a ValueError, as for any invalid JSON:
    parsers disagree on which value wins, so {"b":[...],"b":null} would be a
    null body Recipe to some verifiers and signers and a real one to
    others."""
    if isinstance(data, (bytes, bytearray)):
        # JSON text is UTF-8 (RFC 8259 §8.1); json.loads would otherwise
        # guess UTF-16 or UTF-32 from the first bytes.
        data = bytes(data).decode("utf-8")
    try:
        return json.loads(data, object_pairs_hook=_strict_keys,
                          parse_float=_no_float, parse_constant=_no_constant)
    except RecursionError:
        # JSON nested deeper than the interpreter's stack: invalid JSON,
        # like any other we cannot parse, never a crash.
        raise ValueError("Recipe JSON nested too deeply") from None


class MalformedRecipe(ValueError):
    """The r= payload is valid JSON but is not a well-formed set of Recipes.

    draft -08 §5: each step is an object with exactly one key, "c", "d" or
    "u"; a "c" step is exactly two integers 1 <= start <= end <= the number
    of items present, and each "c" start is greater than every preceding "c"
    end in the same list; "d" items are text with no CR or LF; "u" items are
    canonical base64 of raw octets with no CR or LF.  Anything else cannot be
    applied and the message MUST NOT be accepted.  A ValueError so that
    existing callers (the dkim2undo CLI, DSN propagation) fail as before.

    `path` says where (contract D6): None for a problem with the whole
    document, which the verifier reports as "contains invalid JSON", or
    the step's path ("b[1]", "h.subject[0]", or "h.subject" for a header
    entry that is not an array), which it reports as "Recipe <path> is
    invalid".  A copy range past the items present is found only when the
    Recipe is applied, and is reported as invalid JSON, as in -07.
    """

    def __init__(self, msg: str, path: str | None = None):
        super().__init__(msg if path is None else f"{path}: {msg}")
        self.path = path


def _is_int(v) -> bool:
    # JSON true/false parse to bool, which is an int subclass in Python.
    return isinstance(v, int) and not isinstance(v, bool)


# draft -08 §5 schema: a "u" string must match all three patterns -- the
# base64 alphabet with at most two '=' at the end, a whole number of 4-char
# groups, and zero pad bits ("QR==" decodes, but is not canonical).
_U_PATTERNS = tuple(re.compile(p) for p in (
    r"[A-Za-z0-9+/]*={0,2}",
    r"(?:.{4})*",
    r"(?:[^=]*|.*[AQgw]==|.*[AEIMQUYcgkosw048]=)",
))


def _u_item(item: str, path) -> bytes:
    if not all(p.fullmatch(item) for p in _U_PATTERNS):
        raise MalformedRecipe('"u" item is not canonical base64', path)
    return base64.b64decode(item, validate=True)


def _d_item(item: str, path) -> bytes:
    try:
        return item.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate (\udcXX) is not a Unicode character.
        raise MalformedRecipe('"d" item is not valid UTF-8 text', path)


def recipe_name_path(name: str) -> str:
    """Contract D6: "h.<name>", the JSON key exactly as given, with every
    octet of its UTF-8 form outside 0x21-0x7E written as \\xHH (uppercase
    hex).  A lone surrogate from a JSON escape keeps its three octets."""
    out = []
    for o in name.encode("utf-8", errors="surrogatepass"):
        out.append(chr(o) if 0x21 <= o <= 0x7E else f"\\x{o:02X}")
    return "h." + "".join(out)


def compile_steps(steps, count: int | None, where: str = "b") -> list[tuple]:
    """Validate one Recipe step list and return it in applied form.

    `count` is the number of items currently present (header field instances
    of the name, or body lines); None skips only the upper-bound check, for
    callers that hold the JSON but not the message.  `where` is the list's
    path ("b" or "h.<name>", contract D6), for the errors.

    Returns a list of ("c", start, end) and ("lit", [bytes, ...]) items in
    step order.  Literal bytes are the exact octets to emit ("d" items
    UTF-8 encoded, "u" items base64-decoded), without the header name or
    the trailing CRLF.  Raises MalformedRecipe on any violation, with the
    path of the step (or of the list, if it is not an array).
    """
    if not isinstance(steps, list):
        raise MalformedRecipe("Recipe steps are not a JSON array",
                              where if where != "b" else None)
    out: list[tuple] = []
    prev_end = 0
    for n, step in enumerate(steps):
        path = f"{where}[{n}]"
        if (not isinstance(step, dict) or len(step) != 1
                or next(iter(step)) not in ("c", "d", "u")):
            raise MalformedRecipe(
                'Recipe step is not an object with exactly one of "c", "d", "u"',
                path)
        (kind, arg), = step.items()
        if kind == "c":
            if not (isinstance(arg, list) and len(arg) == 2
                    and all(_is_int(x) for x in arg)):
                raise MalformedRecipe('"c" step is not a pair of integers', path)
            start, end = arg
            if start < 1 or end < start:
                raise MalformedRecipe(
                    f'"c" range [{start}, {end}] is not 1 <= start <= end', path)
            if start <= prev_end:
                raise MalformedRecipe(
                    f'"c" range [{start}, {end}] does not ascend past the '
                    f'previous range ending at {prev_end}', path)
            if count is not None and end > count:
                # Past the items present: only applying finds this, and it
                # is reported as invalid JSON (no path).
                raise MalformedRecipe(
                    f'{path}: "c" range [{start}, {end}] exceeds the {count} '
                    f'item(s) present')
            prev_end = end
            out.append(("c", start, end))
        else:
            if not isinstance(arg, list) or not all(isinstance(x, str) for x in arg):
                raise MalformedRecipe(f'"{kind}" step is not an array of strings', path)
            if not arg:
                # Schema: minItems 1. An empty literal step emits nothing and
                # a producer has no reason to write one.
                raise MalformedRecipe(f'"{kind}" step is an empty array', path)
            vals: list[bytes] = []
            for item in arg:
                raw = _u_item(item, path) if kind == "u" else _d_item(item, path)
                if b"\r" in raw or b"\n" in raw:
                    raise MalformedRecipe(f'"{kind}" item contains CR or LF', path)
                vals.append(raw)
            out.append(("lit", vals))
    return out


def validate_recipes(recipes) -> None:
    """Check the shape of a decoded r= object without reference to a message.

    Everything compile_steps can decide from the JSON alone is checked here
    (so a verifier that is not undoing Recipes still rejects a malformed
    one); the per-list upper bound needs the message and is checked when the
    Recipe is applied.

    Contract D6: every whole-document check comes first (MalformedRecipe
    with no path): the object has "h" or "b" (or both); "h", when present,
    is an object with at least one header field name (a null "h" is the
    null header Recipe, which §5.1 does not allow); "b" is an array of
    steps or null (the null body Recipe).  Only then the steps, so the first
    bad one is reported: "b" first, then the "h" names in byte order, each
    list's steps in order.
    """
    if not isinstance(recipes, dict):
        raise MalformedRecipe("Recipe is not a JSON object")
    if "h" not in recipes and "b" not in recipes:
        raise MalformedRecipe('Recipe has neither "h" nor "b"')
    h = recipes.get("h")
    if "h" in recipes:
        if not isinstance(h, dict):
            raise MalformedRecipe('"h" is not a JSON object')
        if not h:
            raise MalformedRecipe('"h" names no header fields')
    b = recipes.get("b")
    if b is not None and not isinstance(b, list):
        raise MalformedRecipe('"b" is not an array or null')
    if b is not None:
        compile_steps(b, None, "b")
    for name in sorted(h or (), key=lambda k: k.encode("utf-8", "surrogatepass")):
        compile_steps(h[name], None, recipe_name_path(name))


# ---------------------------------------------------------------------------
# Header reconstruction (Section 5.1)
# ---------------------------------------------------------------------------

def get_headers_by_name(headers: list[bytes]) -> dict[str, list[bytes]]:
    """Group headers by lowercase field name, preserving order."""
    result: dict[str, list[bytes]] = {}
    for hdr in headers:
        name = _header_name(hdr).decode("utf-8", errors="surrogateescape")
        result.setdefault(name, []).append(hdr)
    return result


def apply_header_recipe(current_instances: list[bytes], field_name: str,
                        recipes: list[str]) -> list[bytes]:
    """Apply header recipes to reconstruct previous instances of a field.

    Args:
        current_instances: Current header instances (top-to-bottom order)
        field_name: The header field name
        recipes: List of recipe instructions

    Returns:
        Reconstructed header instances (top-to-bottom order).

    Header instances are numbered bottom-up: last instance = 1.
    Recipes are processed in order; later results appear above earlier ones.
    """
    # Build bottom-up index: instance 1 = last, instance 2 = second-to-last, etc.
    # current_instances is in top-to-bottom order, so reverse for bottom-up numbering
    bottom_up = list(reversed(current_instances))
    name = field_name.encode("utf-8", errors="surrogateescape")

    # Process Recipes in order; each Recipe emits header(s)
    # Results are collected so that later entries appear above earlier ones
    # i.e. we build the output top-to-bottom by reversing at the end
    emitted: list[bytes] = []

    for item in compile_steps(recipes, len(bottom_up)):
        if item[0] == "c":
            _, start, end = item
            # Emit instances numbered start through end (1-based, bottom-up)
            emitted.extend(bottom_up[start - 1:end])
        else:
            # §5.1: the header field name and a colon are prepended to each
            # value (the value carries its own leading whitespace, if any).
            for val in item[1]:
                emitted.append(name + b":" + val)

    # Recipes emit so "later header fields appear above earlier ones"
    # Since we processed in order and appended, reverse to get top-to-bottom
    emitted.reverse()
    return emitted


def reconstruct_headers(headers: list[bytes], header_recipes: dict) -> list[bytes]:
    """Reconstruct headers using header recipes.

    Args:
        headers: Current message headers (top-to-bottom order)
        header_recipes: Dict mapping field names to recipe arrays.
                       If None/null for the whole "h" key, reconstruction
                       is impossible.

    Returns:
        Reconstructed headers in top-to-bottom order.
    """
    if header_recipes is None:
        raise ValueError("Header recipes are null - cannot reconstruct previous state")
    if not isinstance(header_recipes, dict):
        raise MalformedRecipe('"h" is not a JSON object')

    if len(header_recipes) == 0:
        # Empty object means headers were unmodified
        return list(headers)

    # Group current headers by name
    by_name = get_headers_by_name(headers)

    # Track which names have Recipes
    recipe_names = {k.lower() for k in header_recipes}

    # Build output: walk through original header order, replacing
    # headers that have Recipes and keeping others
    result: list[bytes] = []
    processed_names: set[str] = set()

    for hdr in headers:
        name = _header_name(hdr).decode("utf-8", errors="surrogateescape")

        if name in recipe_names:
            if name not in processed_names:
                processed_names.add(name)
                # Find the Recipe for this name (case-insensitive)
                recipe_key = None
                for k in header_recipes:
                    if k.lower() == name:
                        recipe_key = k
                        break
                recipes = header_recipes[recipe_key]
                if recipes:
                    reconstructed = apply_header_recipe(
                        by_name.get(name, []), name, recipes
                    )
                    result.extend(reconstructed)
                # else: empty Recipes array = remove all instances
        else:
            # No Recipe for this name: retain as-is
            result.append(hdr)

    # Check for Recipe names that weren't in the original headers
    # (these are headers that were removed and need to be re-added)
    for k in header_recipes:
        name = k.lower()
        if name not in processed_names and header_recipes[k]:
            processed_names.add(name)
            # These are new headers to insert; apply Recipe with empty current list
            reconstructed = apply_header_recipe([], name, header_recipes[k])
            # Insert at the top (they were removed, so they were originally present)
            result = reconstructed + result

    return result


# ---------------------------------------------------------------------------
# Body reconstruction (Section 5.2)
# ---------------------------------------------------------------------------

def reconstruct_body(body: bytes, body_recipes: list[str]) -> bytes:
    """Reconstruct body using body recipes.

    Args:
        body: Current message body
        body_recipes: List of recipe instructions

    Returns:
        Reconstructed body.
    """
    if body_recipes is None:
        raise ValueError("Body recipes are null - cannot reconstruct previous state")

    # Normalise line endings and split into lines
    body = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = body.split(b"\n")
    # Remove trailing empty element from final newline
    if lines and lines[-1] == b"":
        lines.pop()

    # Lines are numbered top-down: first line = 1
    # Process Recipes in order; results emitted so later lines appear below earlier
    result_lines: list[bytes] = []

    for item in compile_steps(body_recipes, len(lines)):
        if item[0] == "c":
            _, start, end = item
            result_lines.extend(lines[start - 1:end])
        else:
            result_lines.extend(item[1])

    # Rejoin with CRLF
    return b"\r\n".join(result_lines) + b"\r\n" if result_lines else b"\r\n"


# ---------------------------------------------------------------------------
# Main undo logic
# ---------------------------------------------------------------------------

def undo_message_instance(raw: bytes, target_version: int | None = None,
                          verbose: bool = False) -> bytes:
    """Undo message-instance changes to reconstruct a previous message version.

    Args:
        raw: The raw signed message
        target_version: The MI version to reconstruct back to (default: one
                       version back from the highest)
        verbose: Print progress info

    Returns:
        The reconstructed message as raw bytes.
    """
    headers, body = parse_message(raw)

    # Find all Message-Instance headers
    mi_headers: list[tuple[int, str, bytes]] = []
    content_headers: list[bytes] = []
    sig_headers: list[bytes] = []

    for hdr in headers:
        name = _header_name(hdr)
        if name == b"message-instance":
            hdr_str = hdr.decode("utf-8", errors="surrogateescape")
            version = _get_version_from_mi(hdr_str)
            mi_headers.append((version, hdr_str, hdr))
        elif name == b"dkim2-signature":
            sig_headers.append(hdr)
        else:
            content_headers.append(hdr)

    if not mi_headers:
        raise ValueError("No Message-Instance headers found")

    mi_headers.sort(key=lambda x: x[0])
    highest_version = mi_headers[-1][0]

    if target_version is None:
        target_version = highest_version - 1

    if target_version < 0:
        raise ValueError(f"Target version {target_version} is invalid")

    if target_version >= highest_version:
        raise ValueError(
            f"Target version {target_version} >= highest version {highest_version}, "
            f"nothing to undo"
        )

    if verbose:
        print(f"Highest MI version: {highest_version}", file=sys.stderr)
        print(f"Target version: {target_version}", file=sys.stderr)

    # Work backwards from highest version to target
    current_content_headers = list(content_headers)
    current_body = body

    for version in range(highest_version, target_version, -1):
        # Find the MI header for this version
        mi_entry = None
        for v, hdr_str, hdr_raw in mi_headers:
            if v == version:
                mi_entry = (v, hdr_str, hdr_raw)
                break

        if mi_entry is None:
            raise ValueError(f"Message-Instance v={version} not found")

        recipes = decode_recipes(mi_entry[1])

        if recipes is None:
            if verbose:
                print(f"  v={version}: no recipes (r= tag absent), "
                      f"headers/body unchanged", file=sys.stderr)
            continue

        if verbose:
            print(f"  v={version}: applying recipes", file=sys.stderr)

        # Apply header Recipes
        # -08 §5.1 disallows the null header Recipe: a present "h" that is
        # null is a syntax error (distinct from an absent "h", which means
        # the header fields were unchanged).
        if "h" in recipes and recipes["h"] is None:
            raise ValueError(
                f"v={version}: header recipes are null — "
                f"not permitted (§5.1)"
            )
        h_recipes = recipes.get("h")
        if h_recipes is not None:
            if isinstance(h_recipes, dict) and len(h_recipes) == 0:
                if verbose:
                    print(f"    headers: unmodified", file=sys.stderr)
            else:
                if verbose:
                    print(f"    headers: {len(h_recipes)} field(s) modified",
                          file=sys.stderr)
                current_content_headers = reconstruct_headers(
                    current_content_headers, h_recipes
                )

        # Apply body Recipes. A present "b" that is null declares the previous
        # body unrecoverable by design; an ABSENT "b" means it was not
        # modified. (The old `elif b_recipes is None` inside the `is not None`
        # branch below could never run, so the null case fell through to the
        # hash check at the end and was reported as a plain mismatch.)
        if "b" in recipes and recipes["b"] is None:
            raise Unrecoverable(
                f"v={version}: body recipe is null, the previous body cannot "
                f"be reconstructed")
        b_recipes = recipes.get("b")
        if b_recipes is not None:
            if isinstance(b_recipes, dict) and len(b_recipes) == 0:
                if verbose:
                    print(f"    body: unmodified", file=sys.stderr)
            else:
                if verbose:
                    print(f"    body: {len(b_recipes)} recipe(s)",
                          file=sys.stderr)
                current_body = reconstruct_body(current_body, b_recipes)

    # Verify against target version's MI hashes if available.
    #
    # A mismatch here is an ERROR, not a warning: the reconstruction did not
    # produce the message the target instance recorded, so what we are about to
    # return is not that message. Returning it with a note on stderr means
    # every caller has to notice the note -- and none did. Mail::DKIM2's
    # Verifier and Go's Undo both fail here; this is the same rule.
    if target_version >= 1:
        target_mi = None
        for v, hdr_str, hdr_raw in mi_headers:
            if v == target_version:
                target_mi = (v, hdr_str, hdr_raw)
                break

        if target_mi:
            colon = target_mi[1].find(":")
            value = target_mi[1][colon + 1:]
            h_tag = _extract_tag(value, "h")
            if h_tag:
                # Parse h= tag: sha256:header_hash:body_hash
                parts = h_tag.split(":")
                if len(parts) == 3:
                    _alg, h_b64, b_b64 = parts

                    expected_h = base64.b64decode(h_b64)
                    actual_h = compute_header_hash(current_content_headers)
                    if expected_h != actual_h:
                        raise ValueError(
                            f"header hash mismatch after undo to v={target_version} "
                            f"(expected {h_b64}, got {b64(actual_h)})")
                    if verbose:
                        print(f"  Header hash matches v={target_version}",
                              file=sys.stderr)

                    expected_b = base64.b64decode(b_b64)
                    actual_b = compute_body_hash(current_body)
                    if expected_b != actual_b:
                        raise ValueError(
                            f"body hash mismatch after undo to v={target_version} "
                            f"(expected {b_b64}, got {b64(actual_b)})")
                    if verbose:
                        print(f"  Body hash matches v={target_version}",
                              file=sys.stderr)

    # Reassemble the message
    # Include MI and sig headers up to the target version
    output_parts: list[bytes] = []

    # Add DKIM2-Signature and MI headers for versions <= target
    for hdr in headers:
        name = _header_name(hdr)
        if name == b"dkim2-signature":
            # Include sigs that reference MI versions <= target
            hdr_str = hdr.decode("utf-8", errors="surrogateescape")
            colon = hdr_str.find(":")
            val = hdr_str[colon + 1:] if colon != -1 else hdr_str
            m_val = _extract_tag(val, "m")
            if (m_val and re.fullmatch(r"[0-9]{1,3}", m_val)
                    and int(m_val) <= target_version):
                output_parts.append(hdr)
        elif name == b"message-instance":
            hdr_str = hdr.decode("utf-8", errors="surrogateescape")
            v = _get_version_from_mi(hdr_str)
            if v <= target_version:
                output_parts.append(hdr)

    # Add reconstructed content headers
    output_parts.extend(current_content_headers)

    # Build output
    header_block = b"\r\n".join(output_parts)
    # Normalise body line endings
    current_body = current_body.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")

    return header_block + b"\r\n\r\n" + current_body


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Undo DKIM2 message-instance changes (draft-ietf-dkim-dkim2-spec-08)")
    parser.add_argument("message", help="Path to signed email file (- for stdin)")
    parser.add_argument("--target-version", type=int, default=None,
                        help="MI version to reconstruct back to (default: highest - 1)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print progress to stderr")
    args = parser.parse_args()

    if args.message == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = Path(args.message).read_bytes()

    try:
        result = undo_message_instance(raw, target_version=args.target_version,
                                       verbose=args.verbose)
        sys.stdout.buffer.write(result)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
