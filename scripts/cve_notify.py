#!/usr/bin/env python3
"""Publish CVE results to Telegram and keep one GitHub issue per workload/image."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from cve_policy import issue_key, repository


ISSUE_MARKER_RE = re.compile(r"<!--\s*cve-issue:v1:([A-Za-z0-9_\-=]+)\s*-->")


def encode_issue_key(key: str) -> str:
    return base64.urlsafe_b64encode(key.encode("utf-8")).decode("ascii").rstrip("=")


def decode_issue_key(text: str) -> str | None:
    match = ISSUE_MARKER_RE.search(text or "")
    if not match:
        return None
    token = match.group(1)
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")


def issue_records(
    report: dict[str, Any], summary: bool = False
) -> list[dict[str, Any]]:
    if summary:
        return [
            {
                "key": "summary|homelab-apps",
                "summary": True,
                "repository": "summary",
                "report": report,
                "vulnerabilities": [],
            }
        ]
    records: list[dict[str, Any]] = []
    for image in report.get("images") or []:
        workloads = image.get("workloads") or [None]
        for workload in workloads:
            record = {
                "image": image.get("image"),
                "repository": image.get("repository")
                or repository(str(image.get("image", ""))),
                "digest": image.get("digest"),
                "workload": workload,
                "vulnerabilities": image.get("vulnerabilities") or [],
            }
            record["key"] = issue_key(record)
            records.append(record)
    return records


def issue_title(record: dict[str, Any]) -> str:
    if record.get("summary"):
        return "[CVE] Daily scan summary"
    workload = record.get("workload") or {}
    suffix = f"::{workload.get('container')}" if workload.get("container") else ""
    if workload:
        location = (
            f"{workload.get('namespace')}/{str(workload.get('kind', '')).lower()}/"
            f"{workload.get('name')}{suffix}"
        )
    else:
        location = "image"
    title = f"[CVE] {location}: {record.get('repository')}"
    return title[:240]


def render_summary_body(record: dict[str, Any]) -> str:
    report = record.get("report") or {}
    repositories: dict[str, dict[str, int]] = {}
    for image in report.get("images") or []:
        repo = str(
            image.get("repository") or repository(str(image.get("image", "")))
        )
        entry = repositories.setdefault(
            repo, {"images": 0, "critical": 0, "high": 0, "fixable": 0}
        )
        entry["images"] += 1
        for vuln in image.get("vulnerabilities") or []:
            severity = str(vuln.get("severity", "")).upper()
            if severity == "CRITICAL":
                entry["critical"] += 1
            elif severity == "HIGH":
                entry["high"] += 1
            if vuln.get("fixed_version"):
                entry["fixable"] += 1
    rows = sorted(
        repositories.items(),
        key=lambda item: (-item[1]["critical"], -item[1]["high"], item[0]),
    )
    lines = [
        f"<!-- cve-issue:v1:{encode_issue_key(str(record['key']))} -->",
        "# CVE scan summary",
        "",
        f"- Images scanned: {report.get('images_scanned', 0)}/{report.get('images_requested', 0)}",
        f"- Affected images: {report.get('images_affected', 0)}",
        f"- Findings: {report.get('total_findings', 0)} "
        f"(fixable {report.get('fixable_findings', 0)})",
        f"- Scan errors: {len(report.get('errors') or [])}",
        "",
        "| Repository | Images | Critical | High | Fixable |",
        "|---|---|---|---|---|",
    ]
    for repo, entry in rows[:30]:
        lines.append(
            f"| `{repo}` | {entry['images']} | {entry['critical']} | "
            f"{entry['high']} | {entry['fixable']} |"
        )
    if len(rows) > 30:
        lines.append(f"| … | | | | {len(rows) - 30} more repositories |")
    lines += [
        "",
        "Full findings are in the private `cve-scan` workflow artifact. "
        "This summary replaces the per-image issues; those are closed automatically.",
    ]
    return "\n".join(lines) + "\n"


def render_issue_body(record: dict[str, Any]) -> str:
    if record.get("summary"):
        return render_summary_body(record)
    vulnerabilities = sorted(
        record.get("vulnerabilities") or [],
        key=lambda item: (0 if item.get("severity") == "CRITICAL" else 1, item.get("id", "")),
    )
    critical = sum(1 for item in vulnerabilities if item.get("severity") == "CRITICAL")
    high = sum(1 for item in vulnerabilities if item.get("severity") == "HIGH")
    fixable = sum(1 for item in vulnerabilities if item.get("fixed_version"))
    workload = record.get("workload") or {}
    lines = [
        f"<!-- cve-issue:v1:{encode_issue_key(str(record['key']))} -->",
        f"# CVE remediation: `{record.get('repository')}`",
        "",
        f"- Image: `{record.get('image')}`",
    ]
    if record.get("digest"):
        lines.append(f"- Digest: `{record['digest']}`")
    if workload:
        lines.append(
            "- Workload: "
            f"`{workload.get('namespace')}/{workload.get('kind')}/{workload.get('name')}` "
            f"container `{workload.get('container')}`"
        )
        if workload.get("application"):
            lines.append(f"- Argo CD Application: `{workload['application']}`")
    lines += [
        "",
        f"CRITICAL: **{critical}**, HIGH: **{high}**, fix available: **{fixable}**",
        "",
        "| CVE | Severity | Package | Installed | Fixed |",
        "|---|---|---|---|---|",
    ]
    for item in vulnerabilities[:150]:
        lines.append(
            "| [{id}]({url}) | {severity} | {pkg} | {installed} | {fixed} |".format(
                id=item.get("id", ""),
                url=item.get("primary_url")
                or f"https://nvd.nist.gov/vuln/detail/{item.get('id', '')}",
                severity=item.get("severity", ""),
                pkg=item.get("pkg", ""),
                installed=item.get("installed_version", ""),
                fixed=item.get("fixed_version", "") or "no fix yet",
            )
        )
    if len(vulnerabilities) > 150:
        lines.append(f"| … | | | | {len(vulnerabilities) - 150} more findings |")
    lines += [
        "",
        "This issue is maintained by the four-hourly `cve-remediation` workflow. "
        "It is closed automatically after the image no longer appears in a scan.",
    ]
    return "\n".join(lines) + "\n"


def summary_text(report: dict[str, Any], plan: dict[str, Any]) -> str:
    findings = [
        vuln
        for image in report.get("images") or []
        for vuln in image.get("vulnerabilities") or []
    ]
    critical_fixable = [
        vuln
        for vuln in findings
        if vuln.get("severity") == "CRITICAL" and vuln.get("fixed_version")
    ]
    high_fixable = [
        vuln
        for vuln in findings
        if vuln.get("severity") == "HIGH" and vuln.get("fixed_version")
    ]
    critical_details: list[str] = []
    for image in report.get("images") or []:
        for vuln in image.get("vulnerabilities") or []:
            if vuln.get("severity") == "CRITICAL" and vuln.get("fixed_version"):
                critical_details.append(
                    f"- {vuln.get('id')} in {image.get('repository')} "
                    f"({vuln.get('pkg')} {vuln.get('installed_version')} -> {vuln.get('fixed_version')})"
                )
    lines = [
        "Home Labs CVE scan",
        f"Images scanned: {report.get('images_scanned', 0)}/{report.get('images_requested', 0)}",
        f"Affected images: {report.get('images_affected', 0)}",
        f"Findings: {report.get('total_findings', 0)} (fixable {report.get('fixable_findings', 0)})",
        f"CRITICAL with fix: {len(critical_fixable)}",
        f"HIGH with fix: {len(high_fixable)}",
        f"Patch PR candidates: {len(plan.get('bumps') or [])}",
        f"Private rebuild requests: {len(plan.get('rebuilds') or [])}",
        f"Protected/manual alerts: {len(plan.get('alerts') or [])}",
    ]
    if report.get("errors"):
        lines.append(f"SCAN ERRORS: {len(report['errors'])}")
    if critical_details:
        lines.append("")
        lines.append("CRITICAL with an available fix:")
        lines.extend(sorted(critical_details)[:10])
        if len(critical_details) > 10:
            lines.append(f"- …and {len(critical_details) - 10} more; see security/cve issues")
    return "\n".join(lines)


def _run_gh(args: list[str], timeout: int = 60) -> str:
    result = subprocess.run(
        ["gh", *args], text=True, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"gh {' '.join(args)} failed: {detail}")
    return result.stdout


def should_close_missing_issues(report: dict[str, Any]) -> bool:
    """Only close issues when every requested image was scanned successfully."""
    return not report.get("errors")


def sync_github_issues(
    repo: str, records: list[dict[str, Any]], close_missing: bool = True
) -> dict[str, Any]:
    labels = json.loads(
        _run_gh(["label", "list", "--repo", repo, "--search", "security/cve", "--json", "name"])
        or "[]"
    )
    if not any(item.get("name") == "security/cve" for item in labels):
        _run_gh(
            [
                "label",
                "create",
                "security/cve",
                "--repo",
                repo,
                "--color",
                "b60205",
                "--description",
                "Automated CVE remediation",
            ]
        )

    raw = _run_gh(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--label",
            "security/cve",
            "--state",
            "open",
            "--limit",
            "500",
            "--json",
            "number,title,body",
        ]
    )
    existing = json.loads(raw or "[]")
    by_key: dict[str, dict[str, Any]] = {}
    for issue in existing:
        key = decode_issue_key(str(issue.get("body", "")))
        if key:
            by_key[key] = issue

    current_keys: set[str] = set()
    created = 0
    updated = 0
    for record in records:
        key = str(record["key"])
        current_keys.add(key)
        body = render_issue_body(record)
        title = issue_title(record)
        issue = by_key.get(key)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as handle:
            handle.write(body)
            body_path = handle.name
        try:
            if issue:
                _run_gh(
                    [
                        "issue",
                        "edit",
                        str(issue["number"]),
                        "--repo",
                        repo,
                        "--title",
                        title,
                        "--body-file",
                        body_path,
                    ]
                )
                updated += 1
            else:
                _run_gh(
                    [
                        "issue",
                        "create",
                        "--repo",
                        repo,
                        "--title",
                        title,
                        "--body-file",
                        body_path,
                        "--label",
                        "security/cve",
                    ]
                )
                created += 1
        finally:
            Path(body_path).unlink(missing_ok=True)

    closed = 0
    if close_missing:
        for key, issue in by_key.items():
            if key in current_keys:
                continue
            _run_gh(
                [
                    "issue",
                    "close",
                    str(issue["number"]),
                    "--repo",
                    repo,
                    "--comment",
                    "No longer present in the latest CVE scan; closing automatically.",
                ]
            )
            closed += 1
    return {
        "created": created,
        "updated": updated,
        "closed": closed,
        "closure_skipped": not close_missing,
    }


def send_telegram(token: str, chat_id: str, text: str) -> None:
    chunks: list[str] = []
    remaining = text
    while remaining:
        chunks.append(remaining[:3800])
        remaining = remaining[3800:]
    for chunk in chunks:
        payload = json.dumps({"chat_id": chat_id, "text": chunk, "disable_web_page_preview": True}).encode()
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status >= 300:
                    raise RuntimeError(f"Telegram returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise RuntimeError(f"Telegram returned HTTP {exc.code}: {detail}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--repo", default="web3-frozen/homelab-apps")
    parser.add_argument("--summary-out", type=Path, default=Path(".validation-renders/notification-summary.txt"))
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Maintain one scan-summary issue instead of one issue per image",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    summary = summary_text(report, plan)
    records = issue_records(report, summary=args.summary)
    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    args.summary_out.write_text(summary + "\n", encoding="utf-8")
    print(summary)

    if args.dry_run:
        print(json.dumps([issue_title(record) for record in records], indent=2))
        return 0

    close_missing = should_close_missing_issues(report) or args.summary
    issue_result = sync_github_issues(args.repo, records, close_missing=close_missing)
    summary += (
        f"\nIssues created: {issue_result['created']}, updated: {issue_result['updated']}, "
        f"closed: {issue_result['closed']}"
    )
    if issue_result["closure_skipped"]:
        summary += "\nIssue closure skipped because the scan was incomplete."
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_ALERT_CHAT_ID", "")
    if not token or not chat_id:
        raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_ALERT_CHAT_ID are required")
    send_telegram(token, chat_id, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
