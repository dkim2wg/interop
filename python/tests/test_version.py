import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent
MODULES = ("dkim2sign.py", "dkim2verify.py", "dkim2undo.py", "dkim2dsn.py",
           "dkim2plan.py", "dkim2dns.py", "dkim2domain.py")

# Lines that may still name -07: notes about what the -07 contract did, kept
# as history (contract D13).  Each is (module, a fragment of the line).
HISTORY = (
    ("dkim2sign.py", "reversing -07 decision 2"),
    ("dkim2undo.py", "reported as invalid JSON, as in -07."),
    ("dkim2verify.py", "-07 removed donotmodify and"),
)


def test_no_stale_spec_versions():
    stale = []
    for f in MODULES:
        text = (SRC / f).read_text()
        for token in ("spec-01", "spec-02", "spec-03", "spec-06", "spec-07",
                      "draft-01", "draft-02", "draft-03", "draft-06", "draft-07"):
            if token in text:
                stale.append(f"{f}:{token}")
    assert not stale, f"stale version strings: {stale}"


def test_no_minus_07_pointers():
    """-08 renumbered §13 and §16, so a "-07 §" pointer is wrong or stale;
    every mention of -07 must be a named history note."""
    stale = []
    for f in MODULES:
        for n, line in enumerate((SRC / f).read_text().splitlines(), 1):
            if re.search(r"(?<![\d.])-07\b|draft 07|Validly Signed", line) and not any(
                    f == hf and frag in line for hf, frag in HISTORY):
                stale.append(f"{f}:{n}: {line.strip()}")
    assert not stale, "\n".join(stale)


def test_history_exceptions_still_exist():
    for f, frag in HISTORY:
        assert frag in (SRC / f).read_text(), (f, frag)


def test_modules_name_spec_08():
    for f in ("dkim2sign.py", "dkim2verify.py", "dkim2undo.py", "dkim2dsn.py",
              "dkim2plan.py", "dkim2dns.py"):
        assert "draft-ietf-dkim-dkim2-spec-08" in (SRC / f).read_text(), f


if __name__ == "__main__":
    test_no_stale_spec_versions()
    test_no_minus_07_pointers()
    test_history_exceptions_still_exist()
    test_modules_name_spec_08()
    print("ok test_version")
