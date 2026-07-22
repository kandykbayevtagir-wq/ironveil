from __future__ import annotations

from ironveil.rules.secrets import (
    SECRET_RULES,
    detect_secret_matches,
    is_obvious_placeholder,
    shannon_entropy,
)

_SYNTHETIC_ALPHANUM = "Ab3Cd5Ef7Gh9Jk2Lm4Np6Qr8St1Uv0WxYz"
_SYNTHETIC_HEX = "a3f91c7e5b2d8046"


def _synthetic(length: int, alphabet: str = _SYNTHETIC_ALPHANUM) -> str:
    """Build unmistakably synthetic, non-production credential-shaped fixtures."""

    return (alphabet * ((length // len(alphabet)) + 1))[:length]


def test_all_requested_secret_categories_have_positive_synthetic_cases() -> None:
    cases = {
        "IV-SEC-001": f'AWS_KEY="AKIA{_synthetic(16).upper()}"',
        "IV-SEC-002": f'GITHUB_TOKEN="ghp_{_synthetic(36)}"',
        "IV-SEC-003": f'GITHUB_TOKEN="github_pat_{_synthetic(48)}"',
        "IV-SEC-004": f'GITLAB_TOKEN="glpat-{_synthetic(24)}"',
        "IV-SEC-005": f'GOOGLE_KEY="AIza{_synthetic(35)}"',
        "IV-SEC-006": '"private_key": "-----BEGIN PRIVATE KEY-----\\nSYNTHETIC FIXTURE ONLY"',
        "IV-SEC-007": f"AccountKey={_synthetic(86)}==",
        "IV-SEC-008": f'OPENAI_KEY="sk-proj-{_synthetic(32)}"',
        "IV-SEC-009": f'ANTHROPIC_KEY="sk-ant-api03-{_synthetic(32)}"',
        "IV-SEC-010": f'STRIPE_KEY="sk_live_{_synthetic(24)}"',
        "IV-SEC-011": f'SLACK_TOKEN="xoxb-{_synthetic(12)}-{_synthetic(24)}"',
        "IV-SEC-012": f"https://hooks.slack.com/services/{_synthetic(10).upper()}/{_synthetic(10).upper()}/{_synthetic(28)}",
        "IV-SEC-013": f"https://discord.com/api/webhooks/123456789012345678/{_synthetic(40)}",
        "IV-SEC-014": f"123456789:{_synthetic(35)}",
        "IV-SEC-015": f"TWILIO_AUTH_TOKEN={_synthetic(32, _SYNTHETIC_HEX)}",
        "IV-SEC-016": f'SENDGRID_KEY="SG.{_synthetic(22)}.{_synthetic(43)}"',
        "IV-SEC-017": f'FIREBASE_TOKEN="{_synthetic(32)}"',
        "IV-SEC-018": f'JWT="eyJ{_synthetic(12)}.{_synthetic(16)}.{_synthetic(16)}"',
        "IV-SEC-019": f"Authorization: Bearer {_synthetic(36)}",
        "IV-SEC-020": f'DATABASE_URL="postgresql://synthetic:{_synthetic(18)}@db.invalid/app"',
        "IV-SEC-021": "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC FIXTURE ONLY",
        "IV-SEC-022": "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC FIXTURE ONLY",
        "IV-SEC-023": "-----BEGIN EC PRIVATE KEY-----\nSYNTHETIC FIXTURE ONLY",
        "IV-SEC-024": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETIC FIXTURE ONLY",
        "IV-SEC-025": f'password = "{_synthetic(24)}"',
        "IV-SEC-026": f'api_token = "{_synthetic(30)}"',
        "IV-SEC-027": f'deployment_credential = "{_synthetic(32)}"',
    }

    assert len(cases) == len(SECRET_RULES)
    for expected_rule, text in cases.items():
        detected = {match.rule.id for match in detect_secret_matches(text, "synthetic_fixture.py")}
        assert expected_rule in detected, (expected_rule, detected)


def test_every_secret_rule_has_a_provider_or_context_negative_case() -> None:
    cases = {
        "IV-SEC-001": f'AWS_KEY="AKIB{_synthetic(16).upper()}"',
        "IV-SEC-002": f'GITHUB_TOKEN="ghp_{_synthetic(35)}"',
        "IV-SEC-003": f'GITHUB_TOKEN="github_pot_{_synthetic(48)}"',
        "IV-SEC-004": f'GITLAB_TOKEN="glpat-{_synthetic(12)}"',
        "IV-SEC-005": f'GOOGLE_KEY="AIzb{_synthetic(35)}"',
        "IV-SEC-006": '"public_key": "-----BEGIN PRIVATE KEY-----"',
        "IV-SEC-007": f"AccountKey={_synthetic(85)}==",
        "IV-SEC-008": f'OPENAI_KEY="pk-proj-{_synthetic(32)}"',
        "IV-SEC-009": f'ANTHROPIC_KEY="sk-ang-api03-{_synthetic(32)}"',
        "IV-SEC-010": f'STRIPE_KEY="pk_live_{_synthetic(24)}"',
        "IV-SEC-011": f'SLACK_TOKEN="yoxb-{_synthetic(12)}-{_synthetic(24)}"',
        "IV-SEC-012": f"https://hooks.slack.invalid/services/{_synthetic(48)}",
        "IV-SEC-013": f"https://discord.com/api/webhooks/1234/{_synthetic(40)}",
        "IV-SEC-014": f"1234567:{_synthetic(35)}",
        "IV-SEC-015": f"TWILIO_AUTH_TOKEN={_synthetic(32, 'G7H9')}",
        "IV-SEC-016": f'SENDGRID_KEY="SH.{_synthetic(22)}.{_synthetic(43)}"',
        "IV-SEC-017": f'FIREBASE_PROJECT="{_synthetic(32)}"',
        "IV-SEC-018": f'JWT="eyK{_synthetic(12)}.{_synthetic(16)}.{_synthetic(16)}"',
        "IV-SEC-019": f"Authorization: Token {_synthetic(36)}",
        "IV-SEC-020": "DATABASE_URL=postgresql://synthetic@db.invalid/app",
        "IV-SEC-021": "-----BEGIN RSA PUBLIC KEY-----",
        "IV-SEC-022": "-----BEGIN OPENSSH PUBLIC KEY-----",
        "IV-SEC-023": "-----BEGIN EC PUBLIC KEY-----",
        "IV-SEC-024": "-----BEGIN PGP PUBLIC KEY BLOCK-----",
        "IV-SEC-025": f'username = "{_synthetic(24)}"',
        "IV-SEC-026": f'api_identifier = "{_synthetic(30)}"',
        "IV-SEC-027": f'cache_identifier = "{_synthetic(32)}"',
    }

    assert len(cases) == len(SECRET_RULES)
    for expected_rule, text in cases.items():
        detected = {match.rule.id for match in detect_secret_matches(text, "negative_fixture.py")}
        assert expected_rule not in detected, (expected_rule, detected)


def test_detected_secret_evidence_is_masked_before_returning() -> None:
    synthetic_value = f"sk-proj-{_synthetic(32)}"
    matches = detect_secret_matches(f'api_key = "{synthetic_value}"', "settings.py")

    assert {match.rule.id for match in matches} >= {"IV-SEC-008"}
    assert all(synthetic_value not in match.evidence for match in matches)
    assert any("…" in match.evidence for match in matches)


def test_explicit_placeholder_values_are_not_generic_secrets() -> None:
    placeholders = (
        "example",
        "changeme",
        "your-token-here",
        "test-token",
        "dummy",
        "placeholder",
        "redacted",
        "xxxxx",
        "synthetic-fixture-42",
    )

    for placeholder in placeholders:
        text = f'password = "{placeholder}"\napi_token = "{placeholder}"'
        detected = {match.rule.id for match in detect_secret_matches(text, "fixture.py")}
        assert not detected.intersection({"IV-SEC-025", "IV-SEC-026", "IV-SEC-027"})
        assert is_obvious_placeholder(placeholder)


def test_placeholders_inside_database_urls_are_not_reported() -> None:
    text = 'DATABASE_URL="postgresql://synthetic-user:changeme@db.invalid/app"'

    assert "IV-SEC-020" not in {match.rule.id for match in detect_secret_matches(text, "config.py")}


def test_unquoted_environment_assignments_are_detected_and_masked() -> None:
    synthetic_value = _synthetic(28)
    matches = detect_secret_matches(f"API_TOKEN={synthetic_value}", ".env")

    assert "IV-SEC-026" in {match.rule.id for match in matches}
    assert all(synthetic_value not in match.evidence for match in matches)


def test_entropy_detector_uses_variable_and_file_context() -> None:
    moderate_entropy = "Ab3dEf5hIj7lMn9p" * 2
    text = f'deployment_credential = "{moderate_entropy}"'

    source_ids = {match.rule.id for match in detect_secret_matches(text, "config.py")}
    documentation_ids = {match.rule.id for match in detect_secret_matches(text, "guide.md")}
    unrelated_ids = {
        match.rule.id
        for match in detect_secret_matches(f'cache_identifier = "{moderate_entropy}"', "config.py")
    }

    assert "IV-SEC-027" in source_ids
    assert "IV-SEC-027" not in documentation_ids
    assert "IV-SEC-027" not in unrelated_ids
    assert 3.6 <= shannon_entropy(moderate_entropy) < 4.15
