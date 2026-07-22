from ironveil.core.entropy import candidate_is_secret, looks_like_placeholder, shannon_entropy
from ironveil.core.fingerprint import fingerprint
from ironveil.core.masking import mask_secret, safe_line_evidence


def test_masking_never_returns_input() -> None:
    for value in ("", "x", "abcd", "abcdef", "synthetic-value-1234567890"):
        masked = mask_secret(value)
        assert masked != value
        if value:
            assert value not in masked


def test_safe_line_evidence_replaces_only_match() -> None:
    line = 'token = "synthetic-random-value-1234567890"'
    start = line.index("synthetic")
    rendered = safe_line_evidence(line, start, len(line) - 1)

    assert "token" in rendered
    assert "synthetic-random-value" not in rendered


def test_fingerprint_is_stable_and_path_sensitive() -> None:
    first = fingerprint("RULE-1", "a/file.py", "value", "context")
    assert first == fingerprint("RULE-1", "a/file.py", "value", "context")
    assert first != fingerprint("RULE-1", "b/file.py", "value", "context")
    assert "value" not in first
    assert first == fingerprint("RULE-1", "./a/file.py", "value", "context")


def test_entropy_context_and_placeholders() -> None:
    assert shannon_entropy("aaaaaaaa") == 0
    assert looks_like_placeholder("your-token-here")
    candidate = "aB7dE9gH2kL4mN6pQ8rT0vX3zC5f"
    assert candidate_is_secret(candidate, "api_token =", "settings.py")
    assert not candidate_is_secret("x" * 32, "api_token =", "settings.py")
