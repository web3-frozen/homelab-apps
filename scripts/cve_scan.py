#!/usr/bin/env python3
"""Scan every image deployed by Argo CD, including private GHCR images.

Inputs are either a plain ``images.txt`` or the richer ``image-inventory.json``
produced by ``cve_inventory.py``.  A scan failure is a hard failure: silently
treating an unreachable image as clean would hide exactly the kind of exposure
this workflow exists to prevent.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cve_policy import canonical_image, repository


DEFAULT_SEVERITY = "CRITICAL,HIGH"


def _trivy_env() -> dict[str, str]:
    env = os.environ.copy()
    if env.get("TRIVY_USERNAME") and not env.get("TRIVY_PASSWORD"):
        raise RuntimeError("TRIVY_USERNAME is set but TRIVY_PASSWORD is missing")
    return env


def _digest_from_trivy(data: dict[str, Any]) -> str | None:
    metadata = data.get("Metadata") or {}
    for digest in metadata.get("RepoDigests") or []:
        if isinstance(digest, str) and "@sha256:" in digest:
            return digest.rsplit("@", 1)[1]
    image_id = metadata.get("ImageID")
    if isinstance(image_id, str) and image_id.startswith("sha256:"):
        return image_id
    return None


def scan_image(
    trivy: str,
    image: str,
    severity: str,
    timeout: int,
    workload_context: list[dict[str, Any]] | None = None,
    cache_dir: Path | None = None,
    skip_db_update: bool = False,
    skip_java_db_update: bool = False,
) -> dict[str, Any]:
    command = [
        trivy,
        "image",
        "--format",
        "json",
        "--severity",
        severity,
        "--quiet",
        "--no-progress",
        "--image-src",
        "remote",
        "--parallel",
        "1",
    ]
    if cache_dir is not None:
        command += ["--cache-dir", str(cache_dir)]
    if skip_db_update:
        command.append("--skip-db-update")
    if skip_java_db_update:
        command.append("--skip-java-db-update")
    command.append(image)
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=_trivy_env(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "image": image,
            "repository": repository(image),
            "workloads": workload_context or [],
            "error": f"scan timed out after {timeout}s",
            "vulnerabilities": [],
        }

    if result.returncode != 0 or not result.stdout.strip():
        detail = (result.stderr or result.stdout).strip().replace("\n", " ")[:500]
        return {
            "image": image,
            "repository": repository(image),
            "workloads": workload_context or [],
            "error": f"Trivy failed with exit {result.returncode}: {detail}",
            "vulnerabilities": [],
        }

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {
            "image": image,
            "repository": repository(image),
            "workloads": workload_context or [],
            "error": f"invalid Trivy JSON: {exc}",
            "vulnerabilities": [],
        }

    vulnerabilities: list[dict[str, Any]] = []
    for target in data.get("Results") or []:
        for item in target.get("Vulnerabilities") or []:
            vuln_id = str(item.get("VulnerabilityID", ""))
            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "pkg": str(item.get("PkgName", "")),
                    "installed_version": str(item.get("InstalledVersion", "")),
                    "fixed_version": str(item.get("FixedVersion", "")),
                    "severity": str(item.get("Severity", "")).upper(),
                    "title": str(item.get("Title", "")),
                    "target": str(target.get("Target", "")),
                    "primary_url": str(item.get("PrimaryURL", ""))
                    or f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
                }
            )

    digest = _digest_from_trivy(data)
    return {
        "image": image,
        "repository": repository(image),
        "digest": digest,
        "image_reference": canonical_image(image, digest),
        "workloads": workload_context or [],
        "vulnerabilities": vulnerabilities,
    }


def _inventory_records(path: Path) -> tuple[list[str], dict[str, list[dict[str, Any]]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    records = data.get("records")
    if not isinstance(records, list):
        raise ValueError(f"{path}: inventory must contain a records list")
    images: list[str] = []
    contexts: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        image = str(record.get("scan_image", "")).strip()
        if not image:
            continue
        images.append(image)
        contexts[image] = list(record.get("workloads") or [])
    return images, contexts


def load_images(
    images_file: Path | None,
    inventory: Path | None,
    repositories: set[str] | None = None,
) -> tuple[list[str], dict[str, list[dict[str, Any]]]]:
    images: list[str] = []
    contexts: dict[str, list[dict[str, Any]]] = {}
    if inventory:
        inventory_images, inventory_contexts = _inventory_records(inventory)
        images.extend(inventory_images)
        contexts.update(inventory_contexts)
    if images_file:
        images.extend(
            line.strip()
            for line in images_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    unique = sorted(dict.fromkeys(images))
    if repositories:
        unique = [image for image in unique if repository(image) in repositories]
    if not unique:
        raise ValueError("no container images were supplied for scanning")
    return unique, contexts


def build_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Build GitHub-compatible SARIF with explicit severity bands."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_index_by_id: dict[str, int] = {}

    for image in report["images"]:
        for vuln in image.get("vulnerabilities") or []:
            vuln_id = vuln.get("id") or "UNKNOWN"
            severity = str(vuln.get("severity", "")).upper()
            if vuln_id not in rule_index_by_id:
                rule_index_by_id[vuln_id] = len(rules)
                rules.append(
                    {
                        "id": vuln_id,
                        "name": vuln_id,
                        "shortDescription": {"text": vuln.get("title") or vuln_id},
                        "helpUri": vuln.get("primary_url"),
                        "properties": {
                            "tags": ["security", "vulnerability"],
                            "security-severity": "9.0" if severity == "CRITICAL" else "8.0",
                        },
                    }
                )
            fixed = vuln.get("fixed_version")
            fix_text = f" Fixed in {fixed}." if fixed else " No fix available yet."
            results.append(
                {
                    "ruleId": vuln_id,
                    "ruleIndex": rule_index_by_id[vuln_id],
                    "level": "error" if severity == "CRITICAL" else "warning",
                    "message": {
                        "text": (
                            f"{severity} {vuln_id} in {image['image']}: "
                            f"{vuln.get('pkg', '')} {vuln.get('installed_version', '')}."
                            f"{fix_text}"
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": image["image"]}
                            }
                        }
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


def _make_worker_caches(
    db_cache_dir: Path, workers: int
) -> tuple[list[Path], tempfile.TemporaryDirectory, bool]:
    """Create isolated fs caches that share one warm, read-only Trivy DB.

    Trivy takes an exclusive lock on its fs cache. Parallel processes pointed at
    the same ``--cache-dir`` fail with ``cache may be in use by another
    process``. Each worker therefore gets its own fs cache, while ``db`` is a
    symlink to the single warm database so the ~1.7 GiB DB is not copied.
    """
    temp = tempfile.TemporaryDirectory(prefix="trivy-scan-")
    shared_db = (db_cache_dir / "db").resolve()
    shared_java_db = (db_cache_dir / "java-db").resolve()
    caches: list[Path] = []
    try:
        for index in range(workers):
            worker = Path(temp.name) / f"worker-{index}"
            worker.mkdir()
            (worker / "db").symlink_to(shared_db, target_is_directory=True)
            if shared_java_db.is_dir():
                (worker / "java-db").symlink_to(shared_java_db, target_is_directory=True)
            caches.append(worker)
    except OSError:
        temp.cleanup()
        raise
    return caches, temp, shared_java_db.is_dir()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", type=Path)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--trivy", default="trivy")
    parser.add_argument("--severity", default=DEFAULT_SEVERITY)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--db-cache-dir",
        type=Path,
        help="Warm Trivy cache created with --download-db-only; required for parallel scans",
    )
    parser.add_argument(
        "--repository",
        action="append",
        default=[],
        help="Only scan this image repository (repeatable)",
    )
    parser.add_argument("--report", type=Path, default=Path(".validation-renders/cve-report.json"))
    parser.add_argument("--sarif", type=Path, default=Path(".validation-renders/cve-results.sarif"))
    args = parser.parse_args()

    if not args.images and not args.inventory:
        parser.error("at least one of --images or --inventory is required")
    images, contexts = load_images(
        args.images, args.inventory, {item for item in args.repository if item}
    )

    workers = max(1, args.workers)
    cache_dirs: list[Path | None] = [None]
    skip_db_update = False
    skip_java_db_update = False
    temp_cache = None
    if args.db_cache_dir is not None:
        db_cache = args.db_cache_dir.expanduser().resolve()
        if not (db_cache / "db" / "trivy.db").is_file():
            parser.error(
                f"--db-cache-dir {db_cache} is missing db/trivy.db; run: "
                f"trivy image --download-db-only --cache-dir {db_cache}"
            )
        skip_db_update = True
        try:
            cache_dirs, temp_cache, has_java_db = _make_worker_caches(db_cache, workers)
        except OSError as exc:
            print(
                f"WARN cannot create isolated Trivy caches ({exc}); serializing scans",
                file=sys.stderr,
            )
            workers = 1
            cache_dirs = [db_cache]
            skip_java_db_update = (db_cache / "java-db").is_dir()
        else:
            skip_java_db_update = has_java_db
    elif workers > 1:
        print(
            "WARN --workers > 1 needs --db-cache-dir to isolate the Trivy fs cache; "
            "running with one worker",
            file=sys.stderr,
        )
        workers = 1

    cache_pool: queue.Queue[Path | None] = queue.Queue()
    for cache in cache_dirs:
        cache_pool.put(cache)

    def scan_with_cache(image: str) -> dict[str, Any]:
        cache = cache_pool.get()
        try:
            return scan_image(
                args.trivy,
                image,
                args.severity,
                args.timeout,
                contexts.get(image, []),
                cache_dir=cache,
                skip_db_update=skip_db_update,
                skip_java_db_update=skip_java_db_update,
            )
        finally:
            cache_pool.put(cache)

    results: list[dict[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(scan_with_cache, image) for image in images]
            for future in as_completed(futures):
                results.append(future.result())
    finally:
        if temp_cache is not None:
            temp_cache.cleanup()

    results.sort(key=lambda item: item["image"])
    successful = [item for item in results if not item.get("error")]
    affected = [item for item in successful if item.get("vulnerabilities")]
    errors = [
        {"image": item["image"], "error": item["error"]}
        for item in results
        if item.get("error")
    ]
    total = sum(len(item.get("vulnerabilities") or []) for item in successful)

    report = {
        "scan_version": 1,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "severity_filter": args.severity,
        "images_requested": len(images),
        "images_scanned": len(successful),
        "images_failed": len(errors),
        "images_affected": len(affected),
        "total_findings": total,
        "fixable_findings": sum(
            1
            for image in affected
            for vuln in image["vulnerabilities"]
            if vuln.get("fixed_version")
        ),
        "errors": errors,
        "scanned_images": [
            {
                "image": item["image"],
                "repository": item["repository"],
                "digest": item.get("digest"),
                "image_reference": item.get("image_reference"),
                "vulnerabilities": len(item.get("vulnerabilities") or []),
            }
            for item in successful
        ],
        "images": affected,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.sarif.parent.mkdir(parents=True, exist_ok=True)
    args.sarif.write_text(json.dumps(build_sarif(report), indent=2) + "\n", encoding="utf-8")

    print(
        "CVE scan complete: "
        f"requested={len(images)} scanned={len(successful)} failed={len(errors)} "
        f"affected={len(affected)} findings={total}"
    )
    for error in errors:
        print(f"ERROR {error['image']}: {error['error']}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
