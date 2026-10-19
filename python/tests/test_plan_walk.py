"""Planned chain walk (BodyPlan + HeaderPlan) against the undo walk.

The planned walk works out every instance's header and body hashes from one
pass over the message, without rebuilding any previous version.  The undo
walk (walk="undo") rebuilds each version and is the reference: for every
case here both must give the same per-instance hashes (walk_trace), the same
Recipe errors and the same verdict, whether the message arrives whole, in
two chunks split anywhere, or one byte at a time.
"""
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
from dkim2sign import b64, compute_body_hash, compute_header_hash  # noqa: E402
from dkim2verify import MessageVerifier, verify_message  # noqa: E402

JUNK = b64(bytes(32))
BODY5 = b"".join(b"line%d\r\n" % i for i in range(1, 6))
HDRS = [b"From: a@example.com", b"To: b@example.com", b"Subject: hello",
        b"Date: Mon, 1 Jan 2024 00:00:00 +0000",
        b"Message-ID: <x@example.com>"]


def mi(version, recipe=None, hh=JUNK, bh=JUNK, m_text=None):
    value = f"m={m_text or version}; h=sha256:{hh}:{bh}"
    if recipe is not None:
        value += "; r=" + b64(json.dumps(recipe).encode())
    return f"Message-Instance: {value};".encode()


def message(headers, body, recipes, top=None, m_text=None):
    """Top message whose instances 1..top carry junk hashes (so every
    instance the walk reaches reports its computed hashes) and the given
    Recipes (recipes[m] for instance m)."""
    top = top or max(list(recipes) + [1])
    mis = [mi(m, recipes.get(m), m_text=(m_text or {}).get(m))
           for m in range(top, 0, -1)]
    return b"\r\n".join(mis + list(headers)) + b"\r\n\r\n" + body


def chain(states):
    """A chain whose hashes are right: states[k] = (headers, body, recipe)
    for instance k+1, the Recipe undoing it to the one below."""
    mis = []
    for k, (h, b, r) in enumerate(states):
        mis.append(mi(k + 1, r if k else None, b64(compute_header_hash(h)),
                      b64(compute_body_hash(b))))
    h, b, _ = states[-1]
    return b"\r\n".join(reversed(mis)) + b"\r\n" + b"\r\n".join(h) \
        + b"\r\n\r\n" + b


PLANNED = []


def _run(raw, walk, chunks=None):
    trace = []
    kw = dict(full_chain=True, skip_timestamp_check=True,
              allow_unsigned_mi=True, walk_trace=trace)
    try:
        if chunks is None:
            r = verify_message(raw, {}, walk=walk, **kw)
        else:
            v = MessageVerifier({}, **kw)
            for c in chunks:
                v.feed(c)
            try:
                r = v.close()
            finally:
                PLANNED.append(v._plan is not None)
    except Exception as e:  # the undo walk's own failures must match too
        return ("raised", type(e).__name__), trace
    return (r.ok, r.status, r.message, r.errors), trace


def same(raw, splits=True, planned=True):
    """Assert the planned walk matches the undo walk; return the result.
    planned=False: a message the plan hands back to the undo walk."""
    ref, ref_trace = _run(raw, "undo")
    got, got_trace = _run(raw, "plan")
    assert got_trace == ref_trace, (got_trace, ref_trace)
    assert got == ref, (got, ref)
    for chunks in ([raw[i:i + 1] for i in range(len(raw))],):
        assert _run(raw, "plan", chunks) == (ref, ref_trace)
        assert PLANNED[-1] is planned
    if splits:
        for i in range(len(raw) + 1):
            assert _run(raw, "plan", [raw[:i], raw[i:]]) == (ref, ref_trace), i
    return ref, ref_trace


def errors(raw):
    return same(raw)[0][3]


def malformed(m):
    return f"PERMERROR: Message-Instance m={m} contains invalid JSON"


# --- body -----------------------------------------------------------------

def test_no_recipe():
    same(message(HDRS, BODY5, {2: None}))


def test_footer_append_passes():
    raw = chain([(HDRS, BODY5, None),
                 (HDRS, BODY5 + b"--\r\nfooter\r\n", {"b": [{"c": [1, 5]}]})])
    res, trace = same(raw)
    assert res[0] is True, res
    assert len(trace) == 2


def test_mime_wrap_middle_range():
    wrapped = (b"--b\r\nContent-Type: text/plain\r\n\r\n" + BODY5
               + b"--b--\r\n")
    raw = chain([(HDRS, BODY5, None),
                 (HDRS, wrapped, {"b": [{"c": [4, 8]}]})])
    assert same(raw)[0][0] is True


def test_literals_before_between_after_copies():
    same(message(HDRS, BODY5, {2: {"b": [
        {"d": ["x"]}, {"c": [1, 2]}, {"d": ["y", "z"]}, {"c": [4, 5]},
        {"d": ["w"]}]}}))


def test_three_levels_lower_copies_literal_of_upper():
    same(message(HDRS, BODY5, {
        3: {"b": [{"c": [1, 2]}, {"d": ["L1", "L2"]}, {"c": [3, 3]}]},
        2: {"b": [{"c": [3, 4]}, {"d": ["tail"]}]}}))


def test_trailing_blank_lines():
    same(message(HDRS, BODY5 + b"\r\n\r\n", {2: {"b": [{"c": [1, 6]}]}}))


def test_blank_run_spanning_body_line_and_literal():
    same(message(HDRS, b"a\r\n\r\nb\r\n", {2: {"b": [
        {"c": [1, 2]}, {"d": ["", ""]}, {"d": ["x"]}]}}))


def test_blank_literals_at_end():
    same(message(HDRS, BODY5, {2: {"b": [{"c": [1, 3]}, {"d": ["", ""]}]}}))


def test_copy_into_trailing_blanks():
    # This undo walk counts trailing blank lines as lines a range may copy
    # (reconstruct_body splits the whole body); only past them is an error.
    body = b"a\r\nb\r\n\r\n\r\n"
    assert malformed(2) not in errors(
        message(HDRS, body, {2: {"b": [{"c": [1, 4]}]}}))
    assert malformed(2) in errors(
        message(HDRS, body, {2: {"b": [{"c": [1, 5]}]}}))


def test_copy_past_end():
    assert malformed(2) in errors(
        message(HDRS, BODY5, {2: {"b": [{"c": [1, 6]}]}}))
    assert malformed(2) in errors(
        message(HDRS, BODY5 + b"\r\n", {2: {"b": [{"c": [2, 7]}]}}))


def test_copy_past_end_of_rebuilt_body():
    errs = errors(message(HDRS, BODY5, {3: {"b": [{"c": [1, 2]}]},
                                        2: {"b": [{"c": [1, 3]}]}}))
    assert malformed(2) in errs and malformed(3) not in errs


def test_out_of_order_and_overlapping():
    assert malformed(2) in errors(message(HDRS, BODY5, {2: {"b": [
        {"c": [3, 4]}, {"c": [1, 2]}]}}))
    assert malformed(2) in errors(message(HDRS, BODY5, {2: {"b": [
        {"c": [1, 3]}, {"c": [3, 4]}]}}))


def test_non_integer_range():
    assert malformed(3) in errors(message(HDRS, BODY5, {
        3: {"b": [{"c": [1, "2"]}]}, 2: {"b": [{"c": [1, 2]}]}}))


def test_null_body_recipe():
    res, trace = same(message(HDRS, BODY5, {
        3: {"b": None}, 2: {"b": [{"c": [1, 99]}],
                            "h": {"subject": [{"d": [" old"]}]}}}))
    assert [t[2] is None for t in trace] == [False, True, True]


def test_unterminated_last_line():
    same(message(HDRS, b"a\r\nb", {2: {"b": [{"c": [1, 2]}, {"d": ["f"]}]}}))
    assert malformed(2) in errors(
        message(HDRS, b"a\r\nb", {2: {"b": [{"c": [1, 3]}]}}))


def test_empty_body():
    same(message(HDRS, b"", {2: {"b": [{"d": ["x"]}]}}))
    assert malformed(2) in errors(
        message(HDRS, b"", {2: {"b": [{"c": [1, 1]}]}}))


def test_body_of_only_blank_lines():
    same(message(HDRS, b"\r\n\r\n\r\n", {2: {"b": [{"c": [1, 3]}]}}))
    same(message(HDRS, b"\r\n\r\n\r\n", {2: {"b": [{"c": [2, 2]},
                                                     {"d": ["x"]}]}}))


def test_lone_cr_and_bare_lf():
    same(message(HDRS, b"a\rb\r\nc\r\n", {2: {"b": [{"c": [2, 3]}]}}))
    same(message(HDRS, b"a\nb\n\nc\r\r\n", {2: {"b": [{"c": [2, 4]}]}}))


def test_empty_recipe():
    same(message(HDRS, BODY5, {2: {"b": []}}))
    same(message(HDRS, BODY5, {2: {"b": {}}}))


def test_big_body_spans():
    body = b"".join(b"line %d of a longer body\r\n" % i for i in range(3000))
    raw = message(HDRS, body + b"\r\n\r\n", {
        3: {"b": [{"d": ["head"]}, {"c": [2, 2900]}, {"d": ["", "mid"]},
                  {"c": [2950, 3001]}]},
        2: {"b": [{"c": [1, 100]}, {"c": [2500, 2950]}]}})
    same(raw, splits=False)
    for size in (1, 7, 4096):
        chunks = [raw[i:i + size] for i in range(0, len(raw), size)]
        assert _run(raw, "plan", chunks) == _run(raw, "undo")


# --- headers ----------------------------------------------------------------

def _with(headers, *extra, drop=()):
    return [h for h in headers if h.split(b":")[0].lower() not in drop] \
        + list(extra)


def test_subject_tag_removed_passes():
    top = _with(HDRS, b"Subject: [list] hello", drop=(b"subject",))
    raw = chain([(HDRS, BODY5, None),
                 (top, BODY5, {"h": {"subject": [{"d": [" hello"]}]}})])
    assert same(raw)[0][0] is True


def test_fields_removed():
    same(message(_with(HDRS, b"List-Id: <l.example.com>"), BODY5,
                 {2: {"h": {"list-id": []}}}))


def test_repeated_fields_copies_and_literals():
    hs = _with(HDRS, b"Comments: one", b"Comments: two", b"Comments: three")
    same(message(hs, BODY5, {2: {"h": {"comments": [
        {"c": [1, 1]}, {"d": [" x"]}, {"c": [3, 3]}]}}}))


def test_field_added():
    same(message(HDRS, BODY5, {2: {"h": {"cc": [{"d": [" c@example.com"]}]}}}))


def test_three_levels_headers():
    hs = _with(HDRS, b"Comments: a", b"Comments: b")
    same(message(hs, BODY5, {
        3: {"h": {"comments": [{"c": [2, 2]}, {"d": [" lit"]}],
                  "subject": [{"d": [" s3"]}]}},
        2: {"h": {"comments": [{"c": [1, 2]}, {"d": [" more"]}]}}}))


def test_folded_values():
    hs = _with(HDRS, b"Subject: hello\r\n  world\r\n\tagain", drop=(b"subject",))
    same(message(hs, BODY5, {2: {"h": {"subject": [{"c": [1, 1]}]}}}))
    same(message(hs, BODY5, {2: {"h": {"subject": [{"d": ["  x  y "]}]}}}))


def test_mixed_case_names_and_keys():
    hs = _with(HDRS, b"SUBJECT: up", drop=())
    same(message(hs, BODY5, {2: {"h": {"subject": [{"c": [1, 1]}]}}}))
    same(message(hs, BODY5, {2: {"h": {"Subject": [{"c": [2, 2]}]}}}))
    same(message(hs, BODY5, {2: {"h": {"Subject": [{"c": [2, 2]}],
                                       "subject": [{"c": [1, 1]}]}}}))
    same(message(HDRS, BODY5, {2: {"h": {"CC": [{"d": [" a"]}],
                                         "cc": [{"d": [" b"]}]}}}))
    # An absent name takes the first key that adds something.
    same(message(HDRS, BODY5, {2: {"h": {"CC": [],
                                         "cc": [{"d": [" b"]}]}}}))
    # A present one takes the first key, even an empty (removing) one.
    same(message(HDRS, BODY5, {2: {"h": {"Subject": [],
                                         "subject": [{"d": [" b"]}]}}}))


def test_skipped_fields_with_recipes():
    hs = _with(HDRS, b"Received: from a", b"Received: from b", b"X-Foo: 1")
    same(message(hs, BODY5, {2: {"h": {"received": [{"c": [2, 2]}],
                                       "x-foo": [{"d": [" 2"]}]}}}))
    assert malformed(2) in errors(message(hs, BODY5, {2: {"h": {
        "received": [{"c": [1, 3]}]}}}))


def test_header_errors():
    assert malformed(2) in errors(message(HDRS, BODY5, {2: {"h": {
        "subject": [{"c": [1, 2]}]}}}))
    assert malformed(2) in errors(message(HDRS, BODY5, {2: {"h": {
        "cc": [{"c": [1, 1]}]}}}))
    hs = _with(HDRS, b"Comments: a", b"Comments: b")
    assert malformed(2) in errors(message(hs, BODY5, {2: {"h": {
        "comments": [{"c": [2, 2]}, {"c": [1, 1]}]}}}))
    assert malformed(2) in errors(message(HDRS, BODY5, {2: {"h": {
        "to": [{"c": [1, 9]}], "from": [{"c": [1, 9]}]}}}))
    assert malformed(2) in errors(message(HDRS, BODY5, {2: {"h": {
        "subject": "nope"}}}))


def test_header_falsy_recipe_removes():
    same(message(HDRS, BODY5, {2: {"h": {"subject": 0, "to": {}}}}))


def test_body_and_header_errors_same_instance():
    errs = errors(message(HDRS, BODY5, {2: {"h": {"subject": [{"c": [1, 2]}]},
                                            "b": [{"c": [1, 9]}]}}))
    assert errs.count(malformed(2)) == 1


def test_header_recipes_checked_below_null_body():
    assert malformed(2) in errors(message(HDRS, BODY5, {
        3: {"b": None}, 2: {"h": {"subject": [{"c": [1, 2]}]}}}))


def test_null_header_recipe():
    same(message(HDRS, BODY5, {2: {"h": None, "b": [{"c": [1, 2]}]}}))


def test_m01():
    same(message(HDRS, BODY5, {2: {"b": [{"c": [1, 4]}]}},
                 m_text={1: "01", 2: "02"}))


def test_message_instance_and_odd_keys_fall_back():
    for key in ("message-instance", "dkim2-signature", " subject", "a:b",
                "subject "):
        same(message(HDRS, BODY5, {2: {"h": {key: [{"d": [" v"]}]},
                                       "b": [{"c": [1, 2]}]}}), splits=False,
             planned=key == "dkim2-signature")


def test_non_object_recipes():
    for r in ([1], "abc", 5):
        same(message(HDRS, BODY5, {2: r}), splits=False, planned=False)


def test_bad_r_values():
    raw = message(HDRS, BODY5, {2: {"b": [{"c": [1, 2]}]}})
    same(raw.replace(b"; r=", b"; r=!!", 1), splits=False)
    bad_json = b64(b"{not json")
    same(message(HDRS, BODY5, {}, top=2).replace(
        b"m=2; h=sha256:" + JUNK.encode() + b":" + JUNK.encode(),
        b"m=2; h=sha256:" + JUNK.encode() + b":" + JUNK.encode()
        + b"; r=" + bad_json.encode()), splits=False)


def test_sha512_and_both_algs():
    raw = message(HDRS, BODY5, {2: {"b": [{"c": [1, 3]}]}})
    raw512 = raw.replace(b"h=sha256:", b"h=sha512:")
    same(raw512, splits=False)
    both = raw.replace(b"h=sha256:" + JUNK.encode() + b":" + JUNK.encode(),
                       b"h=sha256:" + JUNK.encode() + b":" + JUNK.encode()
                       + b",sha512:" + JUNK.encode() + b":" + JUNK.encode())
    same(both, splits=False)


def test_no_blank_separator():
    same(b"\r\n".join([mi(2, {"b": [{"c": [1, 1]}]}), mi(1)] + HDRS), splits=True)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok:", name)
