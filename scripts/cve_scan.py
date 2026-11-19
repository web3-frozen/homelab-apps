#!/usr/bin/env python3
"""Scan the rendered GitOps container images for CVEs with Trivy.

Input:  .validation-renders/images.txt (produced by validate_gitops.py)
Output: .validation-renders/cve-report.json  - machine readable findings for remediation
        .validation-renders/cve-results.sarif - SARIF for GitHub code scanning upload

Only third-party images are scanned. Private images under ghcr.io/web3-frozen/
are already scanned at build time by ci-container.yaml, so they are skipped here
(and cannot be pulled anonymously anyway).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SKIP_PREFIXES = ("ghcr.io/web3-frozen/",)
DEFAULT_SEVERITY = "CRITICAL,HIGH"


def run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def scan_image(trivy: str, image: str, severity: str, timeout: int) -> list[dict]:
    """Return the list of relevant vulnerabilities for one image."""
    result = run(
        [
            trivy,
            "image",
            "--format",
            "json",
            "--severity",
            severity,
            "--quiet",
            "--no-progress",
            image,
        ],
        timeout=timeout,
    )
    if result is None:
        print(f"WARN scan timed out for {image} after {timeout}s", file=sys.stderr)
        return []
    if result.returncode != 0 or not result.stdout.strip():
        detail = (result.stderr or result.stdout).strip().replace("\n", " ")[:300]
        print(f"WARN scan failed for {image}: {detail}", file=sys.stderr)
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"WARN bad Trivy JSON for {image}: {exc}", file=sys.stderr)
        return []

    vulns: list[dict] = []
    for target in data.get("Results") or []:
        for v in target.get("Vulnerabilities") or []:
            vulns.append(
                {
                    "id": v.get("VulnerabilityID", ""),
                    "pkg": v.get("PkgName", ""),
                    "installed_version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion", ""),
                    "severity": v.get("Severity", ""),
                    "title": v.get("Title", ""),
                    "primary_url": v.get("PrimaryURL", "")
                    or f"https://nvd.nist.gov/vuln/detail/{v.get('VulnerabilityID', '')}",
                }
            )
    return vulns


def build_sarif(report: dict) -> dict:
    """Build a minimal, GitHub-compatible SARIF 2.1.0 document."""
    rules: list[dict] = []
    results: list[dict] = []
    rule_index_by_id: dict[str, int] = {}

    for image in report["images"]:
        for v in image["vulnerabilities"]:
            vuln_id = v["id"] or "UNKNOWN"
            if vuln_id not in rule_index_by_id:
                rule_index_by_id[vuln_id] = len(rules)
                rules.append(
                    {
                        "id": vuln_id,
                        "name": vuln_id,
                        "shortDescription": {"text": v["title"] or vuln_id},
                        "helpUri": v["primary_url"],
                        "properties": {"tags": ["security", "vulnerability"]},
                    }
                )
            rule_index = rule_index_by_id[vuln_id]

            level = "error" if v["severity"] in ("CRITICAL", "HIGH") else "warning"
            fix = f" Fixed in {v['fixed_version']}." if v["fixed_version"] else " No fix available yet."
            results.append(
                {
                    "ruleId": vuln_id,
                    "ruleIndex": rule_index,
                    "level": level,
                    "message": {
                        "text": (
                            f"{v['severity']} {vuln_id} in {image['image']}: "
                            f"{v['pkg']} {v['installed_version']}.{fix}"
                        )
                    },
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": image["image"]}}}
                    ],
                }
            )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "informationUri": "https://github.com/aquasecurity/trivy",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", type=Path, default=Path(".validation-renders/images.txt"))
    parser.add_argument("--trivy", default="trivy")
    parser.add_argument("--severity", default=DEFAULT_SEVERITY)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument(
        "--skip-prefix",
        action="append",
        default=[],
        help="Additional image prefixes to skip (repeatable)",
    )
    parser.add_argument("--report", type=Path, default=Path(".validation-renders/cve-report.json"))
    parser.add_argument("--sarif", type=Path, default=Path(".validation-renders/cve-results.sarif"))
    args = parser.parse_args()

    skip_prefixes = (*DEFAULT_SKIP_PREFIXES, *args.skip_prefix)
    images = [
        line.strip()
        for line in args.images.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith(skip_prefixes)
    ]

    results = []
    total = 0
    for image in images:
        vulns = scan_image(args.trivy, image, args.severity, args.timeout)
        if vulns:
            results.append({"image": image, "vulnerabilities": vulns})
            total += len(vulns)

    report = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "severity_filter": args.severity,
        "images_scanned": len(images),
        "images_affected": len(results),
        "total_findings": total,
        "images": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.sarif.write_text(json.dumps(build_sarif(report), indent=2) + "\n", encoding="utf-8")

    print(
        f"CVE scan complete: scanned={len(images)} "
        f"affected={len(results)} findings={total}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
