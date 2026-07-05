from pathlib import Path

SRC = Path(__file__).resolve().parent.parent


def test_no_stale_spec_versions():
    stale = []
    for f in ("dkim2sign.py", "dkim2verify.py", "dkim2undo.py", "dkim2dsn.py"):
        text = (SRC / f).read_text()
        for token in ("spec-01", "spec-02", "spec-03", "draft-01", "draft-02", "draft-03"):
            if token in text:
                stale.append(f"{f}:{token}")
    assert not stale, f"stale version strings: {stale}"


if __name__ == "__main__":
    test_no_stale_spec_versions()
    print("ok test_no_stale_spec_versions")
