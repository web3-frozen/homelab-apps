from __future__ import annotations

from cve_notify import (
    decode_issue_key,
    issue_records,
    issue_title,
    render_issue_body,
    should_close_missing_issues,
    summary_text,
)


def report() -> dict:
    return {
        "images_scanned": 1,
        "images_requested": 1,
        "images_affected": 1,
        "total_findings": 1,
        "fixable_findings": 1,
        "images": [
            {
                "image": "ghcr.io/web3-frozen/demo-frontend:3d683c8",
                "repository": "ghcr.io/web3-frozen/demo-frontend",
                "digest": "sha256:" + "a" * 64,
                "workloads": [
                    {
                        "namespace": "demo-app",
                        "kind": "Deployment",
                        "name": "demo-frontend",
                        "container": "demo-frontend",
                        "application": "demo-app",
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-86144",
                        "pkg": "libxml2",
                        "installed_version": "2.13.9-r2",
                        "fixed_version": "2.13.9-r3",
                        "severity": "HIGH",
                        "primary_url": "https://example.test/CVE-2026-86144",
                    }
                ],
            }
        ],
    }


def test_issue_is_one_per_workload_and_has_stable_marker() -> None:
    records = issue_records(report())
    assert len(records) == 1
    assert issue_title(records[0]).startswith("[CVE] demo-app/deployment/demo-frontend")
    body = render_issue_body(records[0])
    assert decode_issue_key(body) == records[0]["key"]
    assert "CVE-2026-86144" in body


def test_summary_mentions_fixable_critical_counts() -> None:
    text = summary_text(report(), {"bumps": [{}], "rebuilds": [{}], "alerts": []})
    assert "Affected images: 1" in text
    assert "Patch PR candidates: 1" in text


def test_issue_closure_is_disabled_for_incomplete_scans() -> None:
    complete = report()
    incomplete = report()
    incomplete["errors"] = [{"image": "ghcr.io/example/private:tag", "error": "pull denied"}]
    assert should_close_missing_issues(complete)
    assert not should_close_missing_issues(incomplete)
