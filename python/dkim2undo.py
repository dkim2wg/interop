#!/usr/bin/env python3
"""
DKIM2 message-instance undo - draft-clayton-dkim2-spec-08

Takes a signed email with Message-Instance headers containing recipes
and reconstructs the message as it was at a previous version.
"""

import argparse
import base64
import json
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

def decode_recipes(mi_hdr: str) -> dict | None:
    """Decode the r= tag from a Message-Instance header.

    Returns the parsed JSON object, or None if no r= tag.
    """
    colon = mi_hdr.find(":")
    value = mi_hdr[colon + 1:] if colon != -1 else mi_hdr
    r_b64 = _extract_tag(value, "r")
    if not r_b64:
        return None
    return json.loads(base64.b64decode(r_b64))


def parse_range(recipe) -> tuple[int, int] | None:
    """Parse a range recipe. Accepts [start, end] arrays.
    Returns (start, end) or None if this is a text recipe."""
    if isinstance(recipe, list) and len(recipe) == 2:
        return int(recipe[0]), int(recipe[1])
    return None


# ---------------------------------------------------------------------------
# Header reconstruction (Section 4.1)
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

    # Process recipes in order; each recipe emits header(s)
    # Results are collected so that later entries appear above earlier ones
    # i.e. we build the output top-to-bottom by reversing at the end
    emitted: list[bytes] = []

    for recipe in recipes:
        rng = parse_range(recipe)
        if rng is not None:
            start, end = rng
            # Emit instances numbered start through end (1-based, bottom-up)
            for i in range(start, end + 1):
                idx = i - 1  # Convert to 0-based
                if idx < len(bottom_up):
                    emitted.append(bottom_up[idx])
        else:
            # Text string: prepend field name and colon
            line = f"{field_name}: {recipe}".encode("utf-8", errors="surrogateescape")
            emitted.append(line)

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

    if isinstance(header_recipes, dict) and len(header_recipes) == 0:
        # Empty object means headers were unmodified
        return list(headers)

    # Group current headers by name
    by_name = get_headers_by_name(headers)

    # Track which names have recipes
    recipe_names = {k.lower() for k in header_recipes}

    # Build output: walk through original header order, replacing
    # headers that have recipes and keeping others
    result: list[bytes] = []
    processed_names: set[str] = set()

    for hdr in headers:
        name = _header_name(hdr).decode("utf-8", errors="surrogateescape")

        if name in recipe_names:
            if name not in processed_names:
                processed_names.add(name)
                # Find the recipe for this name (case-insensitive)
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
                # else: empty recipes array = remove all instances
        else:
            # No recipe for this name: retain as-is
            result.append(hdr)

    # Check for recipe names that weren't in the original headers
    # (these are headers that were removed and need to be re-added)
    for k in header_recipes:
        name = k.lower()
        if name not in processed_names and header_recipes[k]:
            processed_names.add(name)
            # These are new headers to insert; apply recipe with empty current list
            reconstructed = apply_header_recipe([], name, header_recipes[k])
            # Insert at the top (they were removed, so they were originally present)
            result = reconstructed + result

    return result


# ---------------------------------------------------------------------------
# Body reconstruction (Section 4.2)
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
    # Process recipes in order; results emitted so later lines appear below earlier
    result_lines: list[bytes] = []

    for recipe in body_recipes:
        rng = parse_range(recipe)
        if rng is not None:
            start, end = rng
            for i in range(start, end + 1):
                idx = i - 1  # Convert to 0-based
                if idx < len(lines):
                    result_lines.append(lines[idx])
        else:
            # Text string: append as a line
            result_lines.append(recipe.encode("utf-8", errors="surrogateescape"))

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

        # Apply header recipes
        h_recipes = recipes.get("h")
        if h_recipes is not None:
            if isinstance(h_recipes, dict) and len(h_recipes) == 0:
                if verbose:
                    print(f"    headers: unmodified", file=sys.stderr)
            elif h_recipes is None:
                raise ValueError(
                    f"v={version}: header recipes are null, "
                    f"cannot reconstruct"
                )
            else:
                if verbose:
                    print(f"    headers: {len(h_recipes)} field(s) modified",
                          file=sys.stderr)
                current_content_headers = reconstruct_headers(
                    current_content_headers, h_recipes
                )

        # Apply body recipes
        b_recipes = recipes.get("b")
        if b_recipes is not None:
            if isinstance(b_recipes, dict) and len(b_recipes) == 0:
                if verbose:
                    print(f"    body: unmodified", file=sys.stderr)
            elif b_recipes is None:
                raise ValueError(
                    f"v={version}: body recipes are null, "
                    f"cannot reconstruct"
                )
            else:
                if verbose:
                    print(f"    body: {len(b_recipes)} recipe(s)",
                          file=sys.stderr)
                current_body = reconstruct_body(current_body, b_recipes)

    # Verify against target version's MI hashes if available
    if target_version >= 1:
        target_mi = None
        for v, hdr_str, hdr_raw in mi_headers:
            if v == target_version:
                target_mi = (v, hdr_str, hdr_raw)
                break

        if target_mi:
            colon = target_mi[1].find(":")
            value = target_mi[1][colon + 1:]
            h_b64 = _extract_tag(value, "h")
            if h_b64:
                h_obj = json.loads(base64.b64decode(h_b64))

                h_info = h_obj.get("h")
                if h_info:
                    expected_h = base64.b64decode(h_info[1])
                    actual_h = compute_header_hash(current_content_headers)
                    if expected_h == actual_h:
                        if verbose:
                            print(f"  Header hash matches v={target_version}",
                                  file=sys.stderr)
                    else:
                        print(f"WARNING: Header hash mismatch after undo!",
                              file=sys.stderr)
                        print(f"  expected: {h_info[1]}", file=sys.stderr)
                        print(f"  got:      {b64(actual_h)}", file=sys.stderr)

                b_info = h_obj.get("b")
                if b_info:
                    expected_b = base64.b64decode(b_info[1])
                    actual_b = compute_body_hash(current_body)
                    if expected_b == actual_b:
                        if verbose:
                            print(f"  Body hash matches v={target_version}",
                                  file=sys.stderr)
                    else:
                        print(f"WARNING: Body hash mismatch after undo!",
                              file=sys.stderr)
                        print(f"  expected: {b_info[1]}", file=sys.stderr)
                        print(f"  got:      {b64(actual_b)}", file=sys.stderr)

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
            v_val = _extract_tag(val, "v")
            if v_val and int(v_val) <= target_version:
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
        description="Undo DKIM2 message-instance changes (draft-clayton-dkim2-spec-08)")
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
