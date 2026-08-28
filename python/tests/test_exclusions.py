import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2sign import _should_exclude_header  # noqa: E402


def test_delivered_to_excluded():
    # draft-03 §4.1: Delivered-To is ignored in the header hash
    assert _should_exclude_header(b"delivered-to")


def test_received_still_excluded():
    assert _should_exclude_header(b"received")


import pytest


# spec-06 §4: names added by the HDRMAINT survey
@pytest.mark.parametrize("name", [
    b"apparently-to", b"auto-submitted", b"dl-expansion-history",
    b"original-recipient", b"sio-label-history", b"vbr-info",
    b"x400-received", b"x400-trace",
])
def test_spec05_names_excluded(name):
    assert _should_exclude_header(name)


# spec-06 §4: any Received-* field is a trace field
def test_received_prefix_excluded():
    assert _should_exclude_header(b"received-spf")
    assert _should_exclude_header(b"received-anything")


# spec-05 §4: the ARC- prefix narrowed to exactly three names
def test_arc_narrowed_to_three_names():
    assert _should_exclude_header(b"arc-seal")
    assert _should_exclude_header(b"arc-message-signature")
    assert _should_exclude_header(b"arc-authentication-results")
    assert not _should_exclude_header(b"arc-something-else")


def test_x400_not_matched_by_x_prefix():
    # "x400-trace" must be excluded by its own entry, not by the "x-" prefix
    assert not b"x400-trace".startswith(b"x-")
    assert _should_exclude_header(b"x400-trace")
