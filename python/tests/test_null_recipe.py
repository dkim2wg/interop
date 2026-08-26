import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2undo import undo_message_instance  # noqa: E402


def _b64(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _msg(r_tag):
    return (
        b"Message-Instance: m=2; h=sha256:AAA:BBB; r=" + r_tag.encode() + b"\r\n"
        b"Message-Instance: m=1; h=sha256:CCC:DDD;\r\n"
        b"Subject: hi\r\n"
        b"\r\n"
        b"body line\r\n"
    )


def test_null_header_recipe_rejected():
    # draft-03 §5.1: a present "h": null is no longer permitted.
    raised = False
    try:
        undo_message_instance(_msg(_b64({"h": None})))
    except ValueError as e:
        raised = True
        assert "null" in str(e).lower()
    assert raised, "expected ValueError for null header recipe"


def test_null_body_recipe_still_allowed():
    # A null body Recipe is still valid; undo should not raise a *parse* error
    # for it (it may still fail later for unrelated reasons, but not on "h").
    try:
        undo_message_instance(_msg(_b64({"b": None})))
    except ValueError as e:
        assert "header recipes are null" not in str(e).lower()


if __name__ == "__main__":
    test_null_header_recipe_rejected()
    test_null_body_recipe_still_allowed()
    print("python null-recipe tests OK")
