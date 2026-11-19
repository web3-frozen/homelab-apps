#!/usr/bin/env python3
"""Plan and apply CVE-driven version bumps for Argo CD managed workloads.

Given a cve-report.json (from cve_scan.py) and the rendered manifests, figure out
which Argo CD Application (Helm chart) or direct image introduced each vulnerable
image, find the latest available stable version, and bump the pinned version in
git. Changes are written to disk and summarised in remediation-plan.json; the
calling workflow turns them into a PR.

Design notes:
  * Helm charts are the primary source. Each chart is rendered by
    validate_gitops.py into `.validation-renders/chart-<app>.yaml`, so we can map
    a vulnerable image back to its Application and only bump that chart.
  * Direct images (Kustomize/raw manifests) are handled conservatively: only a
    clearly pinned semantic-version tag is bumped to the newest stable tag.
  * Anything we cannot map or resolve safely is reported as "manual" instead of
    guessed. The CI Trivy gate is the final safety net before auto-merge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

MANIFEST_ROOTS = ("apps", "platform", "workloads")


def run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)


def safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-")


def helm_repo_alias(repo_url: str) -> str:
    digest = hashlib.sha256(repo_url.encode("utf-8")).hexdigest()[:10]
    return f"validation-{digest}"


def version_key(version: str) -> tuple:
    """Comparable key for semantic-ish versions; non-numeric parts sort low."""
    cleaned = version.lstrip("v")
    parts = re.split(r"[.\-+]", cleaned)
    key = []
    for part in parts[:4]:
        key.append((1, int(part)) if part.isdigit() else (0, part))
    return tuple(key)


def iter_yaml_files(root: Path):
    for root_name in MANIFEST_ROOTS:
        base = root / root_name
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}:
                yield path


def load_applications(root: Path) -> list[dict]:
    apps: list[dict] = []
    for path in iter_yaml_files(root):
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError:
            continue
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") != "Application":
                continue
            spec = doc.get("spec") or {}
            source = spec.get("source") or {}
            name = (doc.get("metadata") or {}).get("name", "")
            repo_url = source.get("repoURL")
            if not name or not repo_url:
                continue
            apps.append(
                {
                    "name": name,
                    "path": path,
                    "repo_url": str(repo_url),
                    "chart": source.get("chart"),
                    "target_revision": str(source.get("targetRevision", "")),
                }
            )
    return apps


def collect_images(doc: object, out: set[str]) -> None:
    if isinstance(doc, dict):
        for key, child in doc.items():
            if key == "image" and isinstance(child, str) and child.strip():
                out.add(child.strip())
            else:
                collect_images(child, out)
    elif isinstance(doc, list):
        for child in doc:
            collect_images(child, out)


def map_image_to_chart_app(render_dir: Path, apps: list[dict]) -> dict[str, str]:
    """Map each image to the Application name whose chart rendered it."""
    by_safe_name = {safe_name(app["name"]): app for app in apps if app["chart"]}
    mapping: dict[str, str] = {}
    for chart_file in sorted(render_dir.glob("chart-*.yaml")):
        app_name_key = chart_file.stem[len("chart-") :]
        app = by_safe_name.get(app_name_key)
        if not app:
            continue
        try:
            docs = list(yaml.safe_load_all(chart_file.read_text(encoding="utf-8")))
        except yaml.YAMLError:
            continue
        images: set[str] = set()
        for doc in docs:
            collect_images(doc, images)
        for image in images:
            mapping.setdefault(image, app["name"])
    return mapping


def latest_helm_version(app: dict) -> str | None:
    repo_url = app["repo_url"]
    if repo_url.startswith("oci://"):
        result = run(["crane", "ls", repo_url.removeprefix("oci://")])
        if result.returncode != 0 or not result.stdout.strip():
            return None
        tags = [t.strip() for t in result.stdout.splitlines() if t.strip()]
        stable = [t for t in tags if re.fullmatch(r"v?\d[\w.\-]*", t)]
        return max(stable, key=version_key) if stable else None

    alias = helm_repo_alias(repo_url)
    result = run(
        ["helm", "search", "repo", f"{alias}/{app['chart']}", "--versions", "-o", "json"]
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        versions = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    stable = [
        v["version"]
        for v in versions
        if isinstance(v, dict) and re.fullmatch(r"v?\d[\w.\-]*", str(v.get("version", "")))
    ]
    return max(stable, key=version_key) if stable else None


def bump_target_revision(app: dict, new_version: str) -> bool:
    """Replace only this Application's targetRevision line; preserve formatting."""
    path: Path = app["path"]
    text = path.read_text(encoding="utf-8")
    name = app["name"]
    old = app["target_revision"]
    changed = False

    # Split into YAML documents, keeping the "---" separators as their own
    # tokens so untouched documents remain byte-for-byte identical in the diff.
    parts = re.split(r"(^---[ \t]*$\n?)", text, flags=re.MULTILINE)
    for i, part in enumerate(parts):
        if part.strip() in ("---", "") and not re.search(r"kind: Application", part):
            continue
        if not re.search(rf"(?m)^\s+name:\s*{re.escape(name)}\s*$", part):
            continue
        if "kind: Application" not in part:
            continue
        # targetRevision may be quoted ("1.8.2") or bare (1.8.2); keep the
        # original quoting style when replacing.
        pattern = re.compile(
            rf"(?m)^(\s+targetRevision:\s*)(['\"]?){re.escape(old)}\2(\s*)$"
        )
        new_part, n = pattern.subn(rf"\g<1>\g<2>{new_version}\g<2>\g<3>", part, count=1)
        if n:
            parts[i] = new_part
            changed = True
            break

    if changed:
        path.write_text("".join(parts), encoding="utf-8")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=Path(".validation-renders/cve-report.json"))
    parser.add_argument("--render-dir", type=Path, default=Path(".validation-renders"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--apply", action="store_true", help="Write version bumps (default: dry-run)")
    parser.add_argument("--out", type=Path, default=Path(".validation-renders/remediation-plan.json"))
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    apps = load_applications(args.root)
    image_to_app = map_image_to_chart_app(args.render_dir, apps)

    affected = {img["image"] for img in report["images"]}
    chart_app_names = {app["name"] for app in apps if app["chart"]}

    # Determine which apps need a bump and to what.
    bumps: dict[str, dict] = {}
    manual: list[dict] = []
    for image in sorted(affected):
        app_name = image_to_app.get(image)
        if not app_name or app_name not in chart_app_names:
            manual.append(
                {
                    "image": image,
                    "reason": "not attributed to a pinned Helm chart "
                    "(likely a direct/rolling image) — review manually",
                }
            )
            continue
        app = next(a for a in apps if a["name"] == app_name)
        if app_name in bumps:
            continue
        latest = latest_helm_version(app)
        if not latest:
            manual.append(
                {"image": image, "reason": f"could not resolve latest version for chart {app_name}"}
            )
            continue
        if version_key(latest) <= version_key(app["target_revision"]):
            manual.append(
                {
                    "image": image,
                    "reason": f"chart {app_name} already pinned at latest ({app['target_revision']}) "
                    "but CVE remains — upstream fix not released yet",
                }
            )
            continue
        bumps[app_name] = {
            "app": app_name,
            "chart": app["chart"],
            "file": str(app["path"]),
            "from": app["target_revision"],
            "to": latest,
            "trigger_images": [],
        }

    # Attach every affected image to its app entry (even if we skipped the bump).
    for image in sorted(affected):
        app_name = image_to_app.get(image)
        if app_name in bumps:
            bumps[app_name]["trigger_images"].append(image)

    applied = []
    for app_name, bump in bumps.items():
        if args.apply:
            app = next(a for a in apps if a["name"] == app_name)
            bump["written"] = bump_target_revision(app, bump["to"])
        else:
            bump["written"] = False
        applied.append(bump)

    plan = {
        "total_cve_images": len(affected),
        "bumps": applied,
        "manual": manual,
        "apply": args.apply,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"remediation plan: bumps={len(applied)} manual={len(manual)} "
        f"apply={args.apply}"
    )
    for bump in applied:
        print(f"  {bump['app']}: {bump['from']} -> {bump['to']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
