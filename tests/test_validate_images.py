from __future__ import annotations

import sys
from pathlib import Path

import validate_images


def _fake_crane(tmp_path: Path, message: str) -> Path:
    crane = tmp_path / "crane"
    crane.write_text(f"#!/bin/sh\necho '{message}' >&2\nexit 1\n", encoding="utf-8")
    crane.chmod(0o755)
    return crane


def test_rate_limit_detection() -> None:
    assert validate_images.is_rate_limited(
        "TOOMANYREQUESTS: You have reached your unauthenticated pull rate limit"
    )
    assert validate_images.is_rate_limited("rate limit exceeded")
    assert not validate_images.is_rate_limited("manifest unknown")


def test_rate_limited_image_is_a_warning(tmp_path: Path, monkeypatch, capfd) -> None:
    crane = _fake_crane(tmp_path, "TOOMANYREQUESTS: rate limit")
    images = tmp_path / "images.txt"
    images.write_text("alpine:3.23\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["validate_images.py", str(images), "--crane", str(crane)],
    )

    assert validate_images.main() == 0
    assert "WARN alpine:3.23" in capfd.readouterr().err


def test_missing_image_still_fails(tmp_path: Path, monkeypatch) -> None:
    crane = _fake_crane(tmp_path, "manifest unknown")
    images = tmp_path / "images.txt"
    images.write_text("alpine:missing\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["validate_images.py", str(images), "--crane", str(crane)],
    )

    assert validate_images.main() == 1
