#!/usr/bin/env python3
"""Verify that a CVE remediation PR actually removes the baseline risk.

The workflow that opens the PR uploads the complete baseline artifact.  This
job downloads it, scans the candidate image(s), and fails closed if the artifact
is missing, a fixable baseline CVE survives, a new CRITICAL appears, or the Git
change is anything other than a protected-chart-safe patch update.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from cve_policy import is_patch_update, is_protected, repository


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def baseline_findings(plan: dict[str, Any], repositories: set[str]) -> list[dict[str, Any]]:
    return [
        finding
        for finding in plan.get("baseline_findings") or []
        if str(finding.get("repository", "")) in repositories
    ]


def current_report_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for image in report.get("images") or []:
        image_repository = str(image.get("repository") or repository(str(image.get("image", ""))))
        for vuln in image.get("vulnerabilities") or []:
            finding = dict(vuln)
            finding["repository"] = image_repository
            finding["image"] = image.get("image")
            findings.append(finding)
    return findings


def current_target_revision(root: Path, app_name: str, relative_file: str) -> str | None:
    path = root / relative_file
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise ValueError(f"failed to parse {path}: {exc}") from exc
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != "Application":
            continue
        if str((document.get("metadata") or {}).get("name", "")) != app_name:
            continue
        source = (document.get("spec") or {}).get("source") or {}
        return str(source.get("targetRevision", ""))
    return None


def current_kustomization_tag(root: Path, relative_file: str, image: str) -> str | None:
    path = root / relative_file
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise ValueError(f"failed to parse {path}: {exc}") from exc
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != "Kustomization":
            continue
        for item in document.get("images") or []:
            if isinstance(item, dict) and str(item.get("name", "")) == image:
                return str(item.get("newTag", ""))
    return None


def current_kustomization_digest(root: Path, relative_file: str, image: str) -> str | None:
    path = root / relative_file
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise ValueError(f"failed to parse {path}: {exc}") from exc
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != "Kustomization":
            continue
        for item in document.get("images") or []:
            if isinstance(item, dict) and str(item.get("name", "")) == image:
                return str(item.get("digest", ""))
    return None


def verify_change(marker: dict[str, Any], root: Path) -> list[str]:
    failures: list[str] = []
    changes = marker.get("changes") or []
    if marker.get("kind") == "gitops-chart" and not changes:
        failures.append("GitOps marker contains no attributable file changes")
    for change in changes:
        kind = str(change.get("kind", ""))
        current = str(change.get("from", ""))
        candidate = str(change.get("to", ""))
        if is_protected(change.get("chart"), change.get("app")):
            failures.append(
                f"protected chart cannot be auto-remediated: {change.get('app') or change.get('chart')}"
            )
        if kind in {"helm-chart", "image-tag"} and not is_patch_update(current, candidate):
            failures.append(
                f"non-patch change rejected: {change.get('file')} {current} -> {candidate}"
            )
        if kind == "helm-chart":
            actual = current_target_revision(
                root, str(change.get("app", "")), str(change.get("file", ""))
            )
            if actual != candidate:
                failures.append(
                    f"{change.get('file')}: expected {change.get('app')} at {candidate}, found {actual!r}"
                )
        elif kind == "image-tag":
            actual = current_kustomization_tag(
                root, str(change.get("file", "")), str(change.get("image", ""))
            )
            if actual != candidate:
                failures.append(
                    f"{change.get('file')}: expected {change.get('image')} tag {candidate}, found {actual!r}"
                )
        elif kind == "digest-pin":
            digest = str(change.get("digest", ""))
            if not digest.startswith("sha256:") or len(digest.removeprefix("sha256:")) != 64:
                failures.append(f"invalid digest pin: {digest!r}")
            actual = current_kustomization_digest(
                root, str(change.get("file", "")), str(change.get("image", ""))
            )
            if actual != digest:
                failures.append(
                    f"{change.get('file')}: expected {change.get('image')} digest {digest}, found {actual!r}"
                )
        else:
            failures.append(f"unsupported remediation change kind: {kind!r}")
    return failures


def verify(
    marker: dict[str, Any], report: dict[str, Any], plan: dict[str, Any], root: Path
) -> dict[str, Any]:
    failures: list[str] = []
    repositories = {
        str(value)
        for value in (marker.get("repositories") or [])
        if str(value).strip()
    }
    if not repositories:
        failures.append("marker has no repositories; cannot bind verification to the baseline")
    if marker.get("kind") == "private-image":
        image = str(marker.get("image", ""))
        if "@sha256:" not in image:
            failures.append("private-image marker must pin a sha256 digest")
        if repository(image) not in repositories:
            failures.append("private-image marker repository does not match its image")

    baseline = baseline_findings(plan, repositories)
    baseline_ids = {str(item.get("id")) for item in baseline if item.get("id")}
    fixable = [item for item in baseline if item.get("fixed_version")]
    if not baseline:
        failures.append("baseline artifact contains no findings for the affected repositories")

    candidate_findings = current_report_findings(report)
    for expected in fixable:
        expected_id = str(expected.get("id", ""))
        for current in candidate_findings:
            if current["repository"] != expected.get("repository"):
                continue
            if str(current.get("id", "")) == expected_id:
                failures.append(
                    f"baseline CVE {expected_id} remains in "
                    f"{current.get('image')} ({current.get('pkg')} {current.get('installed_version')})"
                )
                break

    scoped_candidate_findings = [
        current for current in candidate_findings if current["repository"] in repositories
    ]
    for current in scoped_candidate_findings:
        if str(current.get("severity", "")).upper() == "CRITICAL" and str(
            current.get("id", "")
        ) not in baseline_ids:
            failures.append(
                f"new CRITICAL {current.get('id')} in {current.get('image')} "
                f"({current.get('pkg')})"
            )

    failures.extend(verify_change(marker, root))
    if report.get("errors"):
        failures.append(f"candidate scan had {len(report['errors'])} image error(s)")

    return {
        "verification_version": 1,
        "passed": not failures,
        "failures": failures,
        "marker_kind": marker.get("kind"),
        "applications": marker.get("applications") or [],
        "repositories": sorted(repositories),
        "baseline_findings": len(baseline),
        "baseline_fixable": len(fixable),
        "candidate_findings": len(candidate_findings),
        "candidate_critical": sum(
            1
            for item in candidate_findings
            if str(item.get("severity", "")).upper() == "CRITICAL"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--baseline-plan", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--out", type=Path, default=Path(".validation-renders/verification-result.json")
    )
    args = parser.parse_args()

    result = verify(
        load_json(args.marker),
        load_json(args.report),
        load_json(args.baseline_plan),
        args.root.resolve(),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
