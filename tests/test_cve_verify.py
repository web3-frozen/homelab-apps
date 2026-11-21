from __future__ import annotations

from pathlib import Path

from cve_verify import verify


def marker(repo: str = "nginx") -> dict:
    return {
        "version": 1,
        "kind": "gitops-chart",
        "applications": ["web"],
        "repositories": [repo],
        "changes": [
            {
                "kind": "helm-chart",
                "app": "web",
                "chart": "web-chart",
                "file": "apps/web.yaml",
                "from": "1.2.3",
                "to": "1.2.4",
            }
        ],
    }


def baseline_plan(repo: str = "nginx") -> dict:
    return {
        "baseline_findings": [
            {
                "id": "CVE-2026-86144",
                "pkg": "libxml2",
                "fixed_version": "2.13.9-r3",
                "repository": repo,
                "severity": "HIGH",
            }
        ]
    }


def write_app(root: Path, revision: str = "1.2.4") -> None:
    path = root / "apps" / "web.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(
        f"""apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: web
spec:
  source:
    repoURL: https://charts.example.test
    chart: web-chart
    targetRevision: \"{revision}\"
""",
        encoding="utf-8",
    )


def candidate(repo: str, findings: list[dict] | None = None) -> dict:
    return {
        "images": [
            {
                "image": f"{repo}:1.2.4",
                "repository": repo,
                "vulnerabilities": findings or [],
            }
        ]
        if findings
        else [],
        "errors": [],
    }


def test_verification_fails_when_baseline_fixable_remains(tmp_path: Path) -> None:
    write_app(tmp_path)
    report = candidate(
        "nginx",
        [
            {
                "id": "CVE-2026-86144",
                "pkg": "libxml2",
                "installed_version": "2.13.9-r2",
                "severity": "HIGH",
            }
        ],
    )
    result = verify(marker(), report, baseline_plan(), tmp_path)
    assert not result["passed"]
    assert any("remains" in failure for failure in result["failures"])


def test_verification_rejects_new_critical(tmp_path: Path) -> None:
    write_app(tmp_path)
    report = candidate(
        "nginx",
        [
            {
                "id": "CVE-NEW",
                "pkg": "openssl",
                "installed_version": "1",
                "severity": "CRITICAL",
            }
        ],
    )
    result = verify(marker(), report, baseline_plan(), tmp_path)
    assert not result["passed"]
    assert any("new CRITICAL" in failure for failure in result["failures"])


def test_verification_rejects_non_patch_or_protected_chart(tmp_path: Path) -> None:
    write_app(tmp_path, "1.3.0")
    bad = marker()
    bad["changes"][0]["to"] = "1.3.0"
    result = verify(bad, candidate("nginx"), baseline_plan(), tmp_path)
    assert not result["passed"]
    assert any("non-patch" in failure for failure in result["failures"])

    bad = marker()
    bad["changes"][0]["chart"] = "longhorn"
    result = verify(bad, candidate("nginx"), baseline_plan(), tmp_path)
    assert any("protected chart" in failure for failure in result["failures"])


def test_verification_passes_clean_patch(tmp_path: Path) -> None:
    write_app(tmp_path)
    result = verify(marker(), candidate("nginx"), baseline_plan(), tmp_path)
    assert result["passed"], result["failures"]


def test_private_image_requires_pinned_digest_and_pin_file(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    workload = tmp_path / "workloads" / "web"
    workload.mkdir(parents=True)
    (workload / "kustomization.yaml").write_text(
        f"""apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
images:
  - name: ghcr.io/example/web
    digest: {digest}
""",
        encoding="utf-8",
    )
    private_marker = {
        "version": 1,
        "kind": "private-image",
        "applications": ["web"],
        "repositories": ["ghcr.io/example/web"],
        "image": f"ghcr.io/example/web@{digest}",
        "changes": [
            {
                "kind": "digest-pin",
                "file": "workloads/web/kustomization.yaml",
                "image": "ghcr.io/example/web",
                "digest": digest,
            }
        ],
    }
    plan = baseline_plan("ghcr.io/example/web")
    result = verify(private_marker, candidate("ghcr.io/example/web"), plan, tmp_path)
    assert result["passed"], result["failures"]

    private_marker["image"] = "ghcr.io/example/web:latest"
    result = verify(private_marker, candidate("ghcr.io/example/web"), plan, tmp_path)
    assert not result["passed"]
    assert any("sha256" in failure for failure in result["failures"])
