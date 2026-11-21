from __future__ import annotations

from cve_policy import (
    commit_marker_line,
    decode_commit_marker,
    decode_marker,
    encode_marker,
    is_patch_update,
    is_private_image,
    is_protected,
    marker_comment,
    parse_semver,
    same_repository,
    select_latest_patch,
    split_image,
    update_type,
)


def test_semver_parsing_and_patch_boundary() -> None:
    assert parse_semver("v1.8.2").major == 1
    assert update_type("1.8.2", "1.13.0") == "minor"
    assert is_patch_update("1.8.2", "1.8.3")
    assert not is_patch_update("1.8.2", "1.13.0")
    assert not is_patch_update("1.8.2", "2.0.0")
    assert not is_patch_update("1.8.2", "1.8.3-rc.1")


def test_select_latest_patch_never_crosses_minor() -> None:
    assert select_latest_patch(
        ["1.8.2", "1.8.3", "1.8.5", "1.9.0", "1.13.0", "v1.8.6-rc.1"],
        "1.8.2",
    ) == "1.8.5"


def test_protected_platform_charts() -> None:
    assert is_protected("longhorn")
    assert is_protected(chart="linkerd-control-plane")
    assert is_protected(application="cert-manager")
    assert not is_protected("argo-rollouts")


def test_marker_round_trip_for_pr_and_commit() -> None:
    payload = {"version": 1, "kind": "gitops-chart", "applications": ["demo-app"]}
    assert decode_marker(marker_comment(payload)) == payload
    assert decode_commit_marker(commit_marker_line(payload)) == payload
    assert decode_marker("no marker") is None
    token = encode_marker(payload)
    assert token and "=" not in token


def test_image_parsing_handles_registry_ports_and_digests() -> None:
    assert split_image("registry.example:5000/team/app:1.2.3") == (
        "registry.example:5000/team/app",
        "1.2.3",
        None,
    )
    assert split_image("ghcr.io/web3-frozen/demo@sha256:" + "a" * 64)[0] == (
        "ghcr.io/web3-frozen/demo"
    )
    assert is_private_image("ghcr.io/web3-frozen/demo-frontend:abc")
    assert not is_private_image("nginx/nginx-unprivileged:1.31.9-alpine")
    assert same_repository("longhornio/longhorn-manager:v1", "docker.io/longhornio/longhorn-manager@sha256:" + "a" * 64)
    assert same_repository("nginx:1", "docker.io/library/nginx:2")
