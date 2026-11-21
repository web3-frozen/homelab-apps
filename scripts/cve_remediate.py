#!/usr/bin/env python3
"""Turn CVE findings into safe, attributable remediation actions.

Safety rules:
* Helm charts may only move to a newer patch on the same major/minor line.
* Protected platform charts are alert-only.
* Private GHCR images are never tag-edited in Git; their source repository is
  asked to rebuild, and the resulting deploy PR pins the new digest.
* A raw/unknown image is reported for manual review instead of guessed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from cve_policy import (
    is_patch_update,
    is_private_image,
    is_protected,
    parse_semver,
    protected_reason,
    repository,
    same_repository,
    select_latest_patch,
    split_image,
)


MANIFEST_ROOTS = ("apps", "platform", "workloads")
REBUILD_TARGETS = {
    "ghcr.io/web3-frozen/btc-tqqq-signal": {
        "repository": "web3-frozen/btc-tqqq-signal",
        "workflow": "build-container.yaml",
        "ref": "master",
    },
    "ghcr.io/web3-frozen/demo-api": {
        "repository": "web3-frozen/demo-api",
        "workflow": "ci.yaml",
        "ref": "main",
    },
    "ghcr.io/web3-frozen/demo-frontend": {
        "repository": "web3-frozen/demo-frontend",
        "workflow": "ci.yaml",
        "ref": "main",
    },
    "ghcr.io/web3-frozen/demo-inventory": {
        "repository": "web3-frozen/demo-api",
        "workflow": "ci.yaml",
        "ref": "main",
    },
    "ghcr.io/web3-frozen/demo-pricing": {
        "repository": "web3-frozen/demo-api",
        "workflow": "ci.yaml",
        "ref": "main",
    },
    "ghcr.io/web3-frozen/defi-lending-api": {
        "repository": "web3-frozen/defi-lending-api",
        "workflow": "ci.yaml",
        "ref": "main",
    },
    "ghcr.io/web3-frozen/defi-lending-frontend": {
        "repository": "web3-frozen/defi-lending-frontend",
        "workflow": "ci.yaml",
        "ref": "main",
    },
    "ghcr.io/web3-frozen/onchain-monitor": {
        "repository": "web3-frozen/onchain-monitor",
        "workflow": "ci.yaml",
        "ref": "main",
    },
    "ghcr.io/web3-frozen/onchain-monitor-frontend": {
        "repository": "web3-frozen/onchain-monitor-frontend",
        "workflow": "ci.yaml",
        "ref": "main",
    },
}


def run(
    cmd: list[str], timeout: int = 180, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=timeout,
        cwd=cwd,
        check=False,
    )


def safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-")


def helm_repo_alias(repo_url: str) -> str:
    digest = hashlib.sha256(repo_url.encode("utf-8")).hexdigest()[:10]
    return f"validation-{digest}"


def load_applications(root: Path) -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    for root_name in MANIFEST_ROOTS:
        base = root / root_name
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.yaml")):
            try:
                documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
            except Exception as exc:
                raise ValueError(f"failed to parse {path}: {exc}") from exc
            for document in documents:
                if not isinstance(document, dict) or document.get("kind") != "Application":
                    continue
                source = (document.get("spec") or {}).get("source") or {}
                name = str((document.get("metadata") or {}).get("name", ""))
                if not name or not source.get("repoURL"):
                    continue
                applications.append(
                    {
                        "name": name,
                        "path": path,
                        "file": str(path.relative_to(root)),
                        "repo_url": str(source.get("repoURL")),
                        "chart": source.get("chart"),
                        "target_revision": str(source.get("targetRevision", "")),
                    }
                )
    return applications


def all_helm_versions(app: dict[str, Any]) -> list[str]:
    repo_url = str(app["repo_url"])
    chart = str(app.get("chart") or "")
    if not chart:
        return []
    if repo_url.startswith("oci://"):
        result = run(["crane", "ls", repo_url.removeprefix("oci://")])
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    alias = helm_repo_alias(repo_url)
    add = run(["helm", "repo", "add", alias, repo_url, "--force-update"])
    if add.returncode != 0:
        return []
    update = run(["helm", "repo", "update", alias])
    if update.returncode != 0:
        return []
    result = run(
        ["helm", "search", "repo", f"{alias}/{chart}", "--versions", "--output", "json"]
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        versions = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return [
        str(item["version"])
        for item in versions
        if isinstance(item, dict) and item.get("version")
    ]


def bump_target_revision(app: dict[str, Any], new_version: str) -> bool:
    path: Path = app["path"]
    text = path.read_text(encoding="utf-8")
    old = app["target_revision"]
    name = app["name"]
    parts = re.split(r"(^---[ \t]*$\n?)", text, flags=re.MULTILINE)
    changed = False
    for index, part in enumerate(parts):
        if part.strip() in ("---", "") or "kind: Application" not in part:
            continue
        if not re.search(rf"(?m)^\s+name:\s*{re.escape(name)}\s*$", part):
            continue
        pattern = re.compile(
            rf"(?m)^(\s+targetRevision:\s*)(['\"]?){re.escape(old)}\2(\s*)$"
        )
        replacement, count = pattern.subn(
            rf"\g<1>\g<2>{new_version}\g<2>\g<3>", part, count=1
        )
        if count:
            parts[index] = replacement
            changed = True
            break
    if changed:
        path.write_text("".join(parts), encoding="utf-8")
    return changed


def kustomization_images(path: Path) -> list[dict[str, Any]]:
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise ValueError(f"failed to parse {path}: {exc}") from exc
    for document in documents:
        if isinstance(document, dict) and document.get("kind") == "Kustomization":
            return [item for item in document.get("images") or [] if isinstance(item, dict)]
    return []


def find_kustomization_image(
    root: Path, image_repository: str
) -> tuple[Path, dict[str, Any]] | None:
    for root_name in MANIFEST_ROOTS:
        base = root / root_name
        if not base.exists():
            continue
        for path in sorted(base.rglob("kustomization.yaml")):
            for item in kustomization_images(path):
                if same_repository(str(item.get("name", "")), image_repository):
                    return path, item
    return None


def select_latest_image_patch(image_repository: str, current_tag: str) -> str | None:
    result = run(["crane", "ls", image_repository])
    if result.returncode != 0:
        return None
    return select_latest_patch(result.stdout.splitlines(), current_tag)


def update_kustomization_tag(path: Path, image_repository: str, new_tag: str, apply: bool) -> bool:
    if not apply:
        return False
    result = run(
        [
            "kustomize",
            "edit",
            "set",
            "image",
            f"{image_repository}={image_repository}:{new_tag}",
        ],
        cwd=path.parent,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"kustomize edit failed for {path}: {detail}")
    return True


def finding_records(image_entry: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for vuln in image_entry.get("vulnerabilities") or []:
        record = dict(vuln)
        record.update(
            {
                "image": image_entry.get("image"),
                "repository": image_entry.get("repository")
                or repository(str(image_entry.get("image", ""))),
            }
        )
        records.append(record)
    return records


def enrich_report_from_inventory(report: dict[str, Any], inventory: Path | None) -> None:
    """Attach inventory workload ownership when a report predates scan context."""
    if not inventory or not inventory.exists():
        return
    data = json.loads(inventory.read_text(encoding="utf-8"))
    by_repository: dict[str, list[dict[str, Any]]] = {}
    for record in data.get("records") or []:
        if not isinstance(record, dict):
            continue
        image_repository = str(record.get("repository") or repository(str(record.get("scan_image", ""))))
        by_repository.setdefault(image_repository, []).extend(record.get("workloads") or [])
    for image_entry in report.get("images") or []:
        image_repository = str(
            image_entry.get("repository") or repository(str(image_entry.get("image", "")))
        )
        image_entry.setdefault("repository", image_repository)
        if not image_entry.get("workloads"):
            image_entry["workloads"] = by_repository.get(image_repository, [])


def workload_applications(image_entry: dict[str, Any]) -> set[str]:
    applications: set[str] = set()
    for workload in image_entry.get("workloads") or []:
        value = workload.get("application") or workload.get("namespace")
        if value and value != "argocd":
            applications.add(str(value))
    return applications


def build_plan(report: dict[str, Any], root: Path, apply: bool) -> dict[str, Any]:
    apps = load_applications(root)
    app_by_name = {app["name"]: app for app in apps}
    app_by_chart = {
        str(app["chart"]): app for app in apps if app.get("chart")
    }

    chart_findings: dict[str, dict[str, Any]] = {}
    rebuild_findings: dict[str, dict[str, Any]] = {}
    manual: list[dict[str, Any]] = []
    protected: list[dict[str, Any]] = []
    direct_updates: dict[str, dict[str, Any]] = {}
    all_findings: list[dict[str, Any]] = []
    scope_repositories: set[str] = set()

    for image_entry in report.get("images") or []:
        image = str(image_entry.get("image", ""))
        image_repository = str(image_entry.get("repository") or repository(image))
        scope_repositories.add(image_repository)
        findings = finding_records(image_entry)
        all_findings.extend(findings)

        chart_workloads = [
            workload
            for workload in image_entry.get("workloads") or []
            if workload.get("application") and workload.get("chart")
        ]
        if chart_workloads:
            for workload in chart_workloads:
                app_name = str(workload["application"])
                entry = chart_findings.setdefault(
                    app_name,
                    {"image": image, "images": set(), "findings": [], "workloads": []},
                )
                entry["images"].add(image)
                entry["findings"].extend(findings)
                entry["workloads"].append(workload)
            continue

        if is_private_image(image):
            target = REBUILD_TARGETS.get(image_repository)
            if not target:
                manual.append(
                    {
                        "image": image,
                        "reason": "private image has no registered source rebuild workflow",
                    }
                )
                continue
            entry = rebuild_findings.setdefault(
                image_repository,
                {
                    "repository": image_repository,
                    "target": target,
                    "image": image,
                    "previous_image": image_entry.get("image_reference") or image,
                    "cves": set(),
                    "findings": [],
                    "workloads": [],
                    "applications": set(),
                },
            )
            entry["cves"].update(
                str(vuln.get("id")) for vuln in findings if vuln.get("id")
            )
            entry["findings"].extend(findings)
            entry["workloads"].extend(image_entry.get("workloads") or [])
            entry["applications"].update(workload_applications(image_entry))
            continue

        found = find_kustomization_image(root, image_repository)
        if not found:
            manual.append(
                {
                    "image": image,
                    "reason": "not attributable to a pinned Helm chart or Kustomize image entry",
                }
            )
            continue
        path, item = found
        current_tag = str(item.get("newTag", ""))
        if not current_tag or parse_semver(current_tag) is None:
            manual.append(
                {
                    "image": image,
                    "reason": f"{path}: image tag {current_tag!r} is not safely patchable",
                }
            )
            continue
        candidate = select_latest_image_patch(image_repository, current_tag)
        if not candidate or not is_patch_update(current_tag, candidate):
            manual.append(
                {
                    "image": image,
                    "reason": (
                        f"{path}: no newer patch on the {current_tag} major/minor line; "
                        "minor/major changes require review"
                    ),
                }
            )
            continue
        entry = direct_updates.setdefault(
            f"{path}:{image_repository}",
            {
                "kind": "image-tag",
                "file": str(path.relative_to(root)),
                "image": image_repository,
                "from": current_tag,
                "to": candidate,
                "trigger_images": set(),
                "findings": [],
                "applications": workload_applications(image_entry),
                "scope_repositories": [image_repository],
            },
        )
        entry["trigger_images"].add(image)
        entry["findings"].extend(findings)

    version_cache: dict[str, list[str]] = {}
    bumps: list[dict[str, Any]] = []
    for app_name, affected in sorted(chart_findings.items()):
        app = app_by_name.get(app_name) or app_by_chart.get(app_name)
        if not app or not app.get("chart"):
            manual.append(
                {
                    "image": sorted(affected["images"])[0],
                    "reason": f"chart Application {app_name!r} could not be resolved",
                }
            )
            continue
        chart = str(app["chart"])
        if is_protected(chart, app_name):
            protected.append(
                {
                    "application": app_name,
                    "chart": chart,
                    "file": app["file"],
                    "reason": protected_reason(chart, app_name),
                    "images": sorted(affected["images"]),
                    "findings": affected["findings"],
                }
            )
            continue
        current = str(app["target_revision"])
        cache_key = f"{app['repo_url']}|{chart}"
        if cache_key not in version_cache:
            version_cache[cache_key] = all_helm_versions(app)
        candidate = select_latest_patch(version_cache[cache_key], current)
        if not candidate or not is_patch_update(current, candidate):
            manual.append(
                {
                    "image": sorted(affected["images"])[0],
                    "application": app_name,
                    "chart": chart,
                    "reason": (
                        f"{chart} {current}: no newer stable patch on the same "
                        "major/minor line; minor/major changes require review"
                    ),
                }
            )
            continue
        bump = {
            "kind": "helm-chart",
            "app": app_name,
            "chart": chart,
            "file": app["file"],
            "from": current,
            "to": candidate,
            "trigger_images": sorted(affected["images"]),
            "scope_repositories": sorted(
                {repository(image) for image in affected["images"]}
            ),
            "findings": affected["findings"],
            "applications": [app_name],
        }
        if apply:
            bump["written"] = bump_target_revision(app, candidate)
        else:
            bump["written"] = False
        bumps.append(bump)

    for key, update in sorted(direct_updates.items()):
        path = root / update["file"]
        update["trigger_images"] = sorted(update["trigger_images"])
        update["applications"] = sorted(update["applications"])
        update["written"] = update_kustomization_tag(
            path, update["image"], update["to"], apply
        )
        bumps.append(update)

    rebuilds: list[dict[str, Any]] = []
    for image_repository, entry in sorted(rebuild_findings.items()):
        target = entry["target"]
        rebuilds.append(
            {
                "repository": image_repository,
                "git_repository": target["repository"],
                "workflow": target["workflow"],
                "ref": target["ref"],
                "image": entry["image"],
                "previous_image": entry["previous_image"],
                "cve_ids": sorted(entry["cves"]),
                "applications": sorted(entry["applications"]),
                "workloads": entry["workloads"],
                "baseline_findings": entry["findings"],
            }
        )

    applications = sorted(
        {
            str(app)
            for bump in bumps
            for app in bump.get("applications") or []
            if app
        }
        | {
            str(app)
            for rebuild in rebuilds
            for app in rebuild.get("applications") or []
            if app
        }
    )
    return {
        "plan_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "apply": apply,
        "total_cve_images": len(report.get("images") or []),
        "bumps": bumps,
        "rebuilds": rebuilds,
        "manual": manual,
        "protected": protected,
        "alerts": [*protected, *manual],
        "applications": applications,
        "scope_repositories": sorted(scope_repositories),
        "baseline_findings": all_findings,
    }


def build_marker(
    plan: dict[str, Any], source_repo: str, run_id: int | None
) -> dict[str, Any]:
    changes = [
        {
            key: bump.get(key)
            for key in ("kind", "app", "chart", "file", "image", "from", "to")
            if bump.get(key) is not None
        }
        for bump in plan.get("bumps") or []
    ]
    repositories = sorted(
        {
            repository_name
            for bump in plan.get("bumps") or []
            for repository_name in bump.get("scope_repositories") or []
        }
    )
    return {
        "version": 1,
        "kind": "gitops-chart",
        "source_run": {
            "repo": source_repo,
            "run_id": run_id,
            "artifact": "cve-scan",
        },
        "applications": plan.get("applications") or [],
        "repositories": repositories,
        "changes": changes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=Path(".validation-renders/cve-report.json"))
    parser.add_argument("--inventory", type=Path, default=Path(".validation-renders/image-inventory.json"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--apply", action="store_true", help="Write safe patch bumps")
    parser.add_argument("--out", type=Path, default=Path(".validation-renders/remediation-plan.json"))
    parser.add_argument("--marker-out", type=Path)
    parser.add_argument("--source-repo", default="web3-frozen/homelab-apps")
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    enrich_report_from_inventory(report, args.inventory)
    plan = build_plan(report, args.root.resolve(), args.apply)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.marker_out:
        marker = build_marker(plan, args.source_repo, args.run_id)
        args.marker_out.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"remediation plan: bumps={len(plan['bumps'])} rebuilds={len(plan['rebuilds'])} "
        f"protected={len(plan['protected'])} manual={len(plan['manual'])} apply={args.apply}"
    )
    for bump in plan["bumps"]:
        name = bump.get("app") or bump.get("image")
        print(f"  {bump['kind']} {name}: {bump['from']} -> {bump['to']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
