"""Tests for rules."""

from api_finder.rules import get_default_rules, match_rule, get_language_from_file
from pathlib import Path


def test_default_rules_exist():
    """Default rules should exist."""
    rules = get_default_rules()
    assert len(rules) > 0


def test_requests_timeout_rule():
    """Match requests without timeout."""
    rules = get_default_rules()
    rule = next(r for r in rules if r.id == "requests-no-timeout")

    # Should match
    assert match_rule(rule, "requests.get(url)", [])

    # Should not match when timeout present
    assert not match_rule(rule, "requests.get(url)", ["requests.get(url, timeout=30)"])


def test_language_detection():
    """Detect language from file extension."""
    assert get_language_from_file(Path("test.py")) == "python"
    assert get_language_from_file(Path("test.js")) == "javascript"
    assert get_language_from_file(Path("test.tsx")) == "javascript"
    assert get_language_from_file(Path("test.txt")) == "any"


def test_eval_rule():
    """Match eval calls."""
    rules = get_default_rules()
    rule = next(r for r in rules if r.id == "eval-dangerous" and r.language == "python")

    assert match_rule(rule, "result = eval(user_input)", [])
    assert rule.severity == "error"
