import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dkim2verify import _check_signature_duplicates  # noqa: E402


def test_clean_signature_list_has_no_errors():
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "ed25519-sha256", "BBB")]
    assert _check_signature_duplicates(items, "1") == []


def test_duplicate_selector_is_permerror():
    # spec-05 §8.9: a Selector MUST NOT be present more than once
    items = [("sel1", "rsa-sha256", "AAA"), ("sel1", "ed25519-sha256", "BBB")]
    errs = _check_signature_duplicates(items, "3")
    assert errs == ["PERMERROR DKIM2-Signature i=3 has a duplicate selector"]


def test_duplicate_selector_is_case_insensitive():
    # Selector is a Domain (§3.5); DNS names are case-insensitive
    items = [("Sel1", "rsa-sha256", "AAA"), ("sel1", "ed25519-sha256", "BBB")]
    assert "has a duplicate selector" in _check_signature_duplicates(items, "1")[0]


def test_same_algorithm_twice_with_distinct_selectors_is_allowed():
    # spec-05 §8.9: one additional signature using the same algorithm MAY be
    # present provided a different Selector is used
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "rsa-sha256", "BBB")]
    assert _check_signature_duplicates(items, "1") == []


def test_same_algorithm_three_times_is_too_many():
    items = [("sel1", "rsa-sha256", "AAA"), ("sel2", "rsa-sha256", "BBB"),
             ("sel3", "rsa-sha256", "CCC")]
    errs = _check_signature_duplicates(items, "2")
    assert errs == ["PERMERROR DKIM2-Signature i=2 has too many signatures"]


def test_duplicate_selector_and_too_many_are_independent():
    # two sigs sharing an algorithm AND a selector is a duplicate-selector
    # error but NOT too-many-signatures (the count is 2, not 3+)
    items = [("sel1", "rsa-sha256", "AAA"), ("sel1", "rsa-sha256", "BBB")]
    errs = _check_signature_duplicates(items, "1")
    assert any("duplicate selector" in e for e in errs)
    assert not any("too many signatures" in e for e in errs)
