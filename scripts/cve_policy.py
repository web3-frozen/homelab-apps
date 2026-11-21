#!/usr/bin/env python3
"""Pure policy helpers shared by the CVE scan, planning and verification jobs.

Keeping these rules here makes the safety boundary testable without Helm,
Trivy or a live cluster.  In particular, automated remediation may only move a
Helm chart to a newer patch release on the same major/minor line.  Major and
minor upgrades always require a human.
"""

from __future__ import annotations

import base64
import json
import re
import zlib
from dataclasses import dataclass
from typing import Any, Iterable


PROTECTED_CHARTS = frozenset(
    {
        "argo-cd",
        "cert-manager",
        "cloudnative-pg",
        "external-secrets",
        "kyverno",
        "linkerd-control-plane",
        "longhorn",
    }
)

PRIVATE_IMAGE_PREFIX = "ghcr.io/web3-frozen/"
MARKER_PREFIX = "cve-remediation:v1:"
MARKER_COMMENT_RE = re.compile(
    r"<!--\s*cve-remediation:v1:([A-Za-z0-9_\-=]+)\s*-->"
)
COMMIT_MARKER_RE = re.compile(
    r"(?m)^CVE-Remediation:\s*([A-Za-z0-9_\-=]+)\s*$"
)

_SEMVER_RE = re.compile(
    r"^[vV]?(?P<major>0|[1-9]\d*)\."
    r"(?P<minor>0|[1-9]\d*)\."
    r"(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)


@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: str | None
    raw: str

    @property
    def stable(self) -> bool:
        return self.prerelease is None

    @property
    def precedence(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


def parse_semver(value: str) -> SemVer | None:
    match = _SEMVER_RE.fullmatch(str(value).strip())
    if not match:
        return None
    return SemVer(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch")),
        prerelease=match.group("prerelease"),
        raw=str(value).strip(),
    )


def update_type(current: str, candidate: str) -> str:
    """Return ``major``, ``minor``, ``patch``, ``none`` or ``invalid``."""
    old = parse_semver(current)
    new = parse_semver(candidate)
    if old is None or new is None:
        return "invalid"
    if new.precedence == old.precedence:
        return "none"
    if new.major != old.major:
        return "major"
    if new.minor != old.minor:
        return "minor"
    return "patch" if new.patch > old.patch else "none"


def is_patch_update(current: str, candidate: str) -> bool:
    """True only for a stable, forward patch on the exact same major/minor."""
    old = parse_semver(current)
    new = parse_semver(candidate)
    return bool(
        old
        and new
        and old.stable
        and new.stable
        and old.major == new.major
        and old.minor == new.minor
        and new.patch > old.patch
    )


def select_latest_patch(versions: Iterable[str], current: str) -> str | None:
    """Choose the newest stable patch on ``current``'s major/minor line."""
    current_version = parse_semver(current)
    if current_version is None or not current_version.stable:
        return None

    eligible: list[SemVer] = []
    for raw in versions:
        candidate = parse_semver(raw)
        if candidate is None or not candidate.stable:
            continue
        if (
            candidate.major == current_version.major
            and candidate.minor == current_version.minor
            and candidate.patch > current_version.patch
        ):
            eligible.append(candidate)
    if not eligible:
        return None
    latest = max(eligible, key=lambda item: item.precedence)
    return latest.raw


def normalize_component(value: str) -> str:
    return str(value).strip().lower().replace("_", "-")


def is_protected(chart: str | None = None, application: str | None = None) -> bool:
    for value in (chart, application):
        if value and normalize_component(value) in PROTECTED_CHARTS:
            return True
    return False


def protected_reason(chart: str | None = None, application: str | None = None) -> str:
    name = chart or application or "unknown"
    return (
        f"{name} is a protected platform chart; automated CVE remediation may "
        "alert, but may not open or merge a revision PR"
    )


def is_private_image(image: str) -> bool:
    return split_image(image)[0].startswith(PRIVATE_IMAGE_PREFIX)


def split_image(image: str) -> tuple[str, str | None, str | None]:
    """Return ``(repository, tag, digest)`` without relying on Docker.

    Registry ports are handled correctly because a colon only starts a tag
    after the final slash in the reference.
    """
    value = str(image).strip()
    digest: str | None = None
    if "@" in value:
        value, digest = value.rsplit("@", 1)
        digest = f"sha256:{digest.split(':', 1)[-1]}" if ":" not in digest else digest

    tag: str | None = None
    last_slash = value.rfind("/")
    last_colon = value.rfind(":")
    if last_colon > last_slash:
        value, tag = value[:last_colon], value[last_colon + 1 :]
    return value, tag, digest


def repository(image: str) -> str:
    return split_image(image)[0]


def canonical_repository(value: str) -> str:
    """Normalize Docker Hub aliases for comparison (not for image references)."""
    repo = split_image(str(value))[0].lower()
    for prefix in ("index.docker.io/", "registry-1.docker.io/"):
        if repo.startswith(prefix):
            repo = "docker.io/" + repo.removeprefix(prefix)
    first = repo.split("/", 1)[0]
    if "/" not in repo:
        return f"docker.io/library/{repo}"
    if "." not in first and ":" not in first and first != "localhost":
        return f"docker.io/{repo}"
    return repo


def same_repository(left: str, right: str) -> bool:
    return canonical_repository(left) == canonical_repository(right)


def canonical_image(image: str, digest: str | None = None) -> str:
    """Return a digest-pinned image reference when a digest is available."""
    repo, _tag, existing_digest = split_image(image)
    selected = digest or existing_digest
    return f"{repo}@{selected}" if selected else str(image).strip()


def _b64encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _b64decode(token: str) -> bytes:
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


def encode_marker(data: dict[str, Any]) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64encode(zlib.compress(raw, level=9))


def decode_marker_token(token: str) -> dict[str, Any]:
    decoded = zlib.decompress(_b64decode(token))
    payload = json.loads(decoded.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("CVE remediation marker must be a JSON object")
    if payload.get("version") != 1:
        raise ValueError(f"unsupported CVE remediation marker version: {payload.get('version')!r}")
    return payload


def decode_marker(text: str) -> dict[str, Any] | None:
    match = MARKER_COMMENT_RE.search(text or "")
    return decode_marker_token(match.group(1)) if match else None


def decode_commit_marker(message: str) -> dict[str, Any] | None:
    match = COMMIT_MARKER_RE.search(message or "")
    return decode_marker_token(match.group(1)) if match else None


def commit_marker_line(data: dict[str, Any]) -> str:
    return f"CVE-Remediation: {encode_marker(data)}"


def marker_comment(data: dict[str, Any]) -> str:
    return f"<!-- {MARKER_PREFIX}{encode_marker(data)} -->"


def issue_key(record: dict[str, Any]) -> str:
    """Stable key for one vulnerable image used by one workload."""
    workload = record.get("workload") or {}
    if workload:
        return "|".join(
            [
                str(workload.get("namespace", "")),
                str(workload.get("kind", "")).lower(),
                str(workload.get("name", "")),
                str(workload.get("container", "")),
                repository(str(record.get("image", ""))),
            ]
        )
    return f"image|{repository(str(record.get('image', '')))}"
