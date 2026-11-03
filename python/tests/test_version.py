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

# Lines that may still name -08: statements of what -08 changed (contract
# E7), kept as history.
HISTORY_08 = (
    ("dkim2sign.py", "-08 took"),
    ("dkim2verify.py", "-08 dropped \"more selectors than allowed\""),
    ("dkim2verify.py", "signature since -08 (contract D3 amends C9)"),
)


def test_no_stale_spec_versions():
    stale = []
    for f in MODULES:
        text = (SRC / f).read_text()
        for token in ("spec-01", "spec-02", "spec-03", "spec-06", "spec-07",
                      "spec-08", "draft-01", "draft-02", "draft-03", "draft-06",
                      "draft-07", "draft-08"):
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


def test_no_minus_08_pointers():
    """Section numbers did not move from -08 to -09, so every "-08 §"
    pointer is stale; every mention of -08 must be a named history note."""
    stale = []
    for f in MODULES:
        for n, line in enumerate((SRC / f).read_text().splitlines(), 1):
            if re.search(r"(?<![\d.])-08\b|draft 08", line) and not any(
                    f == hf and frag in line for hf, frag in HISTORY_08):
                stale.append(f"{f}:{n}: {line.strip()}")
    assert not stale, "\n".join(stale)


def test_history_exceptions_still_exist():
    for f, frag in HISTORY + HISTORY_08:
        assert frag in (SRC / f).read_text(), (f, frag)


def test_modules_name_spec_09():
    for f in ("dkim2sign.py", "dkim2verify.py", "dkim2undo.py", "dkim2dsn.py",
              "dkim2plan.py", "dkim2dns.py", "dkim2domain.py"):
        assert "draft-ietf-dkim-dkim2-spec-09" in (SRC / f).read_text(), f


if __name__ == "__main__":
    test_no_stale_spec_versions()
    test_no_minus_07_pointers()
    test_no_minus_08_pointers()
    test_history_exceptions_still_exist()
    test_modules_name_spec_09()
    print("ok test_version")
