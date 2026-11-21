from __future__ import annotations

from pathlib import Path

import cve_remediate


def app_file(tmp_path: Path, chart: str, revision: str) -> Path:
    root = tmp_path / "repo"
    apps = root / "apps"
    apps.mkdir(parents=True)
    path = apps / "test.yaml"
    path.write_text(
        f"""apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: {chart}-app
  namespace: argocd
spec:
  source:
    repoURL: https://charts.example.test
    chart: {chart}
    targetRevision: \"{revision}\"
  destination:
    namespace: {chart}
""",
        encoding="utf-8",
    )
    return root


def report_for_chart(image: str, app: str, chart: str) -> dict:
    return {
        "images": [
            {
                "image": image,
                "repository": image.split(":", 1)[0],
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-86144",
                        "pkg": "libxml2",
                        "installed_version": "2.13.9-r2",
                        "fixed_version": "2.13.9-r3",
                        "severity": "HIGH",
                    }
                ],
                "workloads": [
                    {
                        "namespace": "demo",
                        "kind": "Deployment",
                        "name": "web",
                        "container": "web",
                        "application": app,
                        "chart": chart,
                    }
                ],
            }
        ]
    }


def test_protected_chart_never_gets_a_bump(tmp_path: Path, monkeypatch) -> None:
    root = app_file(tmp_path, "longhorn", "1.8.2")
    monkeypatch.setattr(cve_remediate, "all_helm_versions", lambda app: ["1.8.3"])
    plan = cve_remediate.build_plan(
        report_for_chart("longhorn/manager:v1.8.2", "longhorn-app", "longhorn"),
        root,
        apply=False,
    )
    assert plan["bumps"] == []
    assert plan["protected"][0]["chart"] == "longhorn"


def test_chart_bump_is_same_minor_latest_patch(tmp_path: Path, monkeypatch) -> None:
    root = app_file(tmp_path, "metrics-server", "1.8.2")
    monkeypatch.setattr(
        cve_remediate,
        "all_helm_versions",
        lambda app: ["1.8.3", "1.8.9", "1.9.0", "2.0.0"],
    )
    plan = cve_remediate.build_plan(
        report_for_chart("registry.example/metrics-server:v1.8.2", "metrics-server-app", "metrics-server"),
        root,
        apply=False,
    )
    assert len(plan["bumps"]) == 1
    assert plan["bumps"][0]["from"] == "1.8.2"
    assert plan["bumps"][0]["to"] == "1.8.9"


def test_private_image_is_rebuild_not_manifest_edit(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "apps").mkdir(parents=True)
    report = report_for_chart(
        "ghcr.io/web3-frozen/demo-frontend:3d683c8",
        None,
        None,
    )
    report["images"][0]["workloads"][0]["application"] = None
    plan = cve_remediate.build_plan(report, root, apply=False)
    assert plan["bumps"] == []
    assert plan["rebuilds"][0]["git_repository"] == "web3-frozen/demo-frontend"
    assert plan["rebuilds"][0]["cve_ids"] == ["CVE-2026-86144"]


def test_chart_marker_scope_excludes_private_rebuilds(tmp_path: Path, monkeypatch) -> None:
    root = app_file(tmp_path, "metrics-server", "1.8.2")
    monkeypatch.setattr(cve_remediate, "all_helm_versions", lambda app: ["1.8.3"])
    report = report_for_chart(
        "registry.example/metrics-server:v1.8.2", "metrics-server-app", "metrics-server"
    )
    report["images"].append(
        {
            "image": "ghcr.io/web3-frozen/demo-frontend:3d683c8",
            "repository": "ghcr.io/web3-frozen/demo-frontend",
            "vulnerabilities": [
                {
                    "id": "CVE-PRIVATE",
                    "pkg": "libxml2",
                    "installed_version": "1",
                    "fixed_version": "2",
                    "severity": "HIGH",
                }
            ],
            "workloads": [
                {
                    "namespace": "demo-app",
                    "kind": "Deployment",
                    "name": "demo-frontend",
                    "container": "demo-frontend",
                    "application": None,
                    "chart": None,
                }
            ],
        }
    )
    plan = cve_remediate.build_plan(report, root, apply=False)
    marker = cve_remediate.build_marker(plan, "web3-frozen/homelab-apps", 42)
    assert marker["repositories"] == ["registry.example/metrics-server"]
