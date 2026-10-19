from pathlib import Path

SRC = Path(__file__).resolve().parent.parent
MODULES = ("dkim2sign.py", "dkim2verify.py", "dkim2undo.py", "dkim2dsn.py",
           "dkim2plan.py", "dkim2dns.py", "dkim2domain.py")


def test_no_stale_spec_versions():
    stale = []
    for f in MODULES:
        text = (SRC / f).read_text()
        for token in ("spec-01", "spec-02", "spec-03", "spec-06",
                      "draft-01", "draft-02", "draft-03", "draft-06"):
            if token in text:
                stale.append(f"{f}:{token}")
    assert not stale, f"stale version strings: {stale}"


def test_modules_name_spec_07():
    for f in ("dkim2sign.py", "dkim2verify.py", "dkim2undo.py", "dkim2dsn.py",
              "dkim2plan.py", "dkim2dns.py"):
        assert "draft-ietf-dkim-dkim2-spec-07" in (SRC / f).read_text(), f


if __name__ == "__main__":
    test_no_stale_spec_versions()
    test_modules_name_spec_07()
    print("ok test_version")
