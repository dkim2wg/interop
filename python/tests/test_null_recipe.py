import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2undo import undo_message_instance, Unrecoverable  # noqa: E402


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


def test_null_body_recipe_is_unrecoverable_not_a_defect():
    # A null body Recipe is valid: it is the upstream declaring that the
    # previous body cannot be put back. That must be distinguishable from a
    # reconstruction that went wrong, because DSN propagation answers the
    # first by returning header fields alone and MUST NOT answer the second
    # that way -- so it has its own exception type.
    raised = False
    try:
        undo_message_instance(_msg(_b64({"b": None})))
    except Unrecoverable as e:
        raised = True
        assert "body recipe is null" in str(e).lower(), str(e)
        assert "header recipes are null" not in str(e).lower()
    assert raised, "expected Unrecoverable for a null body recipe"


def test_null_header_recipe_is_not_unrecoverable():
    # §5.1 makes a null "h" a syntax error, not a declaration -- it must not
    # come back as Unrecoverable, or propagation would paper over it.
    try:
        undo_message_instance(_msg(_b64({"h": None})))
        assert False, "expected ValueError for null header recipe"
    except Unrecoverable:
        assert False, "a null header recipe is a syntax error, not Unrecoverable"
    except ValueError:
        pass


if __name__ == "__main__":
    test_null_header_recipe_rejected()
    test_null_body_recipe_is_unrecoverable_not_a_defect()
    test_null_header_recipe_is_not_unrecoverable()
    print("python null-recipe tests OK")
