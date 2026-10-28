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


# -07 §4: names added by the HDRMAINT survey (Auto-Submitted and VBR-Info
# were on this list until -08 removed them: see the test below)
@pytest.mark.parametrize("name", [
    b"apparently-to", b"dl-expansion-history",
    b"original-recipient", b"sio-label-history",
    b"x400-received", b"x400-trace",
])
def test_spec05_names_excluded(name):
    assert _should_exclude_header(name)


# -08 §4 (contract D1): Auto-Submitted and VBR-Info are hashed now.
@pytest.mark.parametrize("name", [b"auto-submitted", b"vbr-info"])
def test_spec08_auto_submitted_and_vbr_info_hashed(name):
    assert not _should_exclude_header(name)


# -07 §4: any Received-* field is a trace field
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
