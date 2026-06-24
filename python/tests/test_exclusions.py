import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2sign import _should_exclude_header  # noqa: E402


def test_delivered_to_excluded():
    # draft-03 §4.1: Delivered-To is ignored in the header hash
    assert _should_exclude_header(b"delivered-to")


def test_received_still_excluded():
    assert _should_exclude_header(b"received")
