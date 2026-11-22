from __future__ import annotations

import json
import sys
import subprocess
from pathlib import Path

import cve_scan


def test_scan_failure_is_an_error_not_clean(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 1, stdout="", stderr="pull access denied")

    monkeypatch.setattr(cve_scan.subprocess, "run", fake_run)
    result = cve_scan.scan_image("trivy", "ghcr.io/example/private:tag", "HIGH", 10)
    assert result["error"]
    assert result["vulnerabilities"] == []


def test_sarif_maps_critical_error_and_high_warning() -> None:
    report = {
        "images": [
            {
                "image": "nginx:1",
                "vulnerabilities": [
                    {
                        "id": "CVE-1",
                        "pkg": "libxml2",
                        "installed_version": "2.13.9-r2",
                        "fixed_version": "2.13.9-r3",
                        "severity": "CRITICAL",
                        "title": "critical",
                        "primary_url": "https://example.test/CVE-1",
                    },
                    {
                        "id": "CVE-2",
                        "pkg": "pkg",
                        "installed_version": "1",
                        "fixed_version": "",
                        "severity": "HIGH",
                        "title": "high",
                        "primary_url": "https://example.test/CVE-2",
                    },
                ],
            }
        ]
    }
    sarif = cve_scan.build_sarif(report)
    levels = {item["ruleId"]: item["level"] for item in sarif["runs"][0]["results"]}
    rules = {item["id"]: item for item in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert levels == {"CVE-1": "error", "CVE-2": "warning"}
    assert rules["CVE-1"]["properties"]["security-severity"] == "9.0"
    assert rules["CVE-2"]["properties"]["security-severity"] == "8.0"


def test_inventory_scan_filters_by_repository(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "records": [
                    {"scan_image": "nginx:1", "workloads": []},
                    {"scan_image": "ghcr.io/example/app:abc", "workloads": []},
                ]
            }
        ),
        encoding="utf-8",
    )
    images, _ = cve_scan.load_images(None, inventory, {"nginx"})
    assert images == ["nginx:1"]


def test_scan_uses_isolated_cache_and_skips_db_updates(monkeypatch, tmp_path: Path) -> None:
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(
            command, 0, stdout=json.dumps({"Results": []}), stderr=""
        )

    monkeypatch.setattr(cve_scan.subprocess, "run", fake_run)
    result = cve_scan.scan_image(
        "trivy",
        "nginx:1",
        "HIGH",
        10,
        cache_dir=tmp_path,
        skip_db_update=True,
        skip_java_db_update=True,
    )
    command = captured["command"]
    assert command[command.index("--cache-dir") + 1] == str(tmp_path)
    assert "--skip-db-update" in command
    assert "--skip-java-db-update" in command
    assert "error" not in result


def test_worker_caches_share_db_and_isolate_fanal(tmp_path: Path) -> None:
    db_cache = tmp_path / "db-cache"
    (db_cache / "db").mkdir(parents=True)
    (db_cache / "db" / "trivy.db").write_bytes(b"database")

    caches, temp_cache, has_java_db = cve_scan._make_worker_caches(db_cache, 3)
    try:
        assert len(caches) == 3
        assert len({str(cache) for cache in caches}) == 3
        assert not has_java_db
        for cache in caches:
            assert (cache / "db" / "trivy.db").read_bytes() == b"database"
            assert (cache / "db").is_symlink()
    finally:
        temp_cache.cleanup()


def test_parallel_scan_without_db_cache_serializes(tmp_path: Path, monkeypatch, capfd) -> None:
    trivy = tmp_path / "trivy"
    trivy.write_text("#!/bin/sh\necho '{\"Results\": []}'\n", encoding="utf-8")
    trivy.chmod(0o755)
    images = tmp_path / "images.txt"
    images.write_text("nginx:1\nredis:1\n", encoding="utf-8")
    report = tmp_path / "report.json"
    sarif = tmp_path / "report.sarif"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cve_scan.py",
            "--images",
            str(images),
            "--trivy",
            str(trivy),
            "--report",
            str(report),
            "--sarif",
            str(sarif),
            "--workers",
            "2",
        ],
    )
    assert cve_scan.main() == 0
    assert "--workers > 1 needs --db-cache-dir" in capfd.readouterr().err


def test_scan_main_returns_nonzero_when_an_image_fails(tmp_path: Path, monkeypatch) -> None:
    trivy = tmp_path / "trivy"
    trivy.write_text("#!/bin/sh\necho 'registry unavailable' >&2\nexit 1\n", encoding="utf-8")
    trivy.chmod(0o755)
    images = tmp_path / "images.txt"
    images.write_text("nginx:broken\n", encoding="utf-8")
    report = tmp_path / "report.json"
    sarif = tmp_path / "report.sarif"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cve_scan.py",
            "--images",
            str(images),
            "--trivy",
            str(trivy),
            "--report",
            str(report),
            "--sarif",
            str(sarif),
        ],
    )
    assert cve_scan.main() == 1
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["images_failed"] == 1
    assert data["errors"][0]["image"] == "nginx:broken"
