from __future__ import annotations

from ironveil.rules.docker import analyze_dockerfile
from ironveil.rules.github_actions import analyze_workflow
from ironveil.rules.kubernetes import analyze_kubernetes, analyze_kubernetes_fragment
from ironveil.rules.terraform import analyze_terraform


def _ids(matches: object) -> set[str]:
    return {match.rule.id for match in matches}  # type: ignore[attr-defined]


def test_dockerfile_rules_correlate_structural_and_line_issues() -> None:
    text = """\
FROM ubuntu
RUN curl https://downloads.invalid/installer | sh
RUN chmod 777 /app && apt-get update && apt-get install -y curl
COPY .env /app/.env
ADD src/ /app/
"""

    matches = analyze_dockerfile(text)

    assert _ids(matches) >= {
        "IV-DOCKER-002",
        "IV-DOCKER-003",
        "IV-DOCKER-004",
        "IV-DOCKER-005",
        "IV-DOCKER-006",
        "IV-DOCKER-007",
        "IV-DOCKER-008",
        "IV-DOCKER-009",
    }


def test_hardened_dockerfile_avoids_contextual_findings() -> None:
    text = """\
FROM python:3.12@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
USER 10001
HEALTHCHECK CMD ["python", "-c", "raise SystemExit(0)"]
COPY src/ /app/
"""

    assert not _ids(analyze_dockerfile(text)).intersection(
        {"IV-DOCKER-001", "IV-DOCKER-002", "IV-DOCKER-003", "IV-DOCKER-008", "IV-DOCKER-009"}
    )


def test_partial_dockerfile_does_not_invent_missing_instructions() -> None:
    matches = analyze_dockerfile("RUN echo safe\n", partial=True)

    assert not _ids(matches).intersection({"IV-DOCKER-002", "IV-DOCKER-008"})


def test_dockerfile_continuations_preserve_high_signal_line_rules() -> None:
    text = "RUN curl https://downloads.invalid/installer \\\n+  | sh\n"

    assert "IV-DOCKER-004" in _ids(analyze_dockerfile(text, partial=True))


def test_workflow_rules_detect_privileged_untrusted_flow() -> None:
    text = """\
on:
  pull_request_target:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: outside/example-action@v1
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: true
      - run: echo "${{ github.event.pull_request.title }}"
        env:
          TOKEN: ${{ secrets.SYNTHETIC_FIXTURE }}
"""

    matches = analyze_workflow(text)

    assert _ids(matches) == {
        "IV-GHA-001",
        "IV-GHA-002",
        "IV-GHA-003",
        "IV-GHA-004",
        "IV-GHA-005",
        "IV-GHA-006",
        "IV-GHA-007",
    }


def test_full_sha_for_third_party_action_is_accepted() -> None:
    sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
    text = f"steps:\n  - uses: outside/example-action@{sha}  # v1\n"

    assert "IV-GHA-004" not in _ids(analyze_workflow(text))


def test_inline_pull_request_target_trigger_is_correlated() -> None:
    text = """\
on: [pull_request_target]
jobs:
  unsafe:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
"""

    assert "IV-GHA-002" in _ids(analyze_workflow(text))


def test_partial_workflow_skips_whole_document_correlations() -> None:
    fragment = """\
pull_request_target:
- uses: actions/checkout@v4
  ref: ${{ github.event.pull_request.head.sha }}
"""

    assert "IV-GHA-002" not in _ids(analyze_workflow(fragment, partial=True))


def test_terraform_rules_keep_correlations_inside_resource_blocks() -> None:
    # The assigned literal is synthetic test data; evidence must be masked.
    synthetic_credential = "Q7m2N9p4R6t8V3w5Y1k7D4s2"
    text = f'''\
resource "aws_security_group_rule" "admin" {{
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}}
resource "aws_iam_policy" "all" {{
  policy = <<POLICY
  {{"Action":"*","Resource":"*"}}
POLICY
}}
resource "aws_s3_bucket_public_access_block" "unsafe" {{
  block_public_policy = false
}}
storage_encrypted = false
secret_key = "{synthetic_credential}"
'''

    matches = analyze_terraform(text)

    assert _ids(matches) >= {"IV-TF-001", "IV-TF-002", "IV-TF-003", "IV-TF-004", "IV-TF-005"}
    assert all(synthetic_credential not in match.evidence for match in matches)


def test_terraform_open_all_protocols_has_distinct_rule() -> None:
    text = """\
resource "aws_security_group_rule" "all" {
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
"""

    assert "IV-TF-006" in _ids(analyze_terraform(text))


def test_terraform_public_like_value_outside_storage_is_not_flagged() -> None:
    text = """\
resource "example_service" "documented" {
  access_type = "container"
}
"""

    assert "IV-TF-002" not in _ids(analyze_terraform(text))


def test_terraform_json_high_signal_values_are_detected() -> None:
    text = '{"resource": {"example": {"storage_encrypted": false}}}'

    assert "IV-TF-003" in _ids(analyze_terraform(text, "main.tf.json"))


def test_kubernetes_rules_detect_pod_and_container_risks() -> None:
    text = """\
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      volumes:
        - name: host
          hostPath:
            path: /var/run
      containers:
        - name: app
          image: example/app
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
            capabilities:
              add:
                - SYS_ADMIN
"""

    matches = analyze_kubernetes(text)

    assert _ids(matches) == {
        "IV-K8S-001",
        "IV-K8S-002",
        "IV-K8S-003",
        "IV-K8S-004",
        "IV-K8S-005",
        "IV-K8S-006",
        "IV-K8S-007",
        "IV-K8S-008",
        "IV-K8S-009",
    }


def test_kubernetes_pinned_limited_container_avoids_context_findings() -> None:
    text = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      resources:
        limits:
          cpu: 500m
          memory: 256Mi
"""

    assert not _ids(analyze_kubernetes(text)).intersection({"IV-K8S-007", "IV-K8S-008"})


def test_non_kubernetes_yaml_is_not_treated_as_a_manifest() -> None:
    text = "privileged: true\nhostNetwork: true\n"

    assert analyze_kubernetes(text, "application.yaml") == ()


def test_kubernetes_fragment_requires_likely_path_and_skips_structural_absence() -> None:
    text = "privileged: true\n"

    assert "IV-K8S-001" in _ids(analyze_kubernetes_fragment(text, "k8s/deployment.yaml"))
    assert analyze_kubernetes_fragment(text, "application.yaml") == ()
    assert "IV-K8S-007" not in _ids(
        analyze_kubernetes_fragment("containers:\n- image: app:latest\n", "k8s/deployment.yaml")
    )
