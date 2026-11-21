#!/usr/bin/env python3
"""Build a workload-aware image inventory from rendered and live manifests.

Rendered manifests describe what Git would deploy.  Live pod data describes what
is actually running, including digest-resolved private images.  The scanner uses
the live reference when it is safe to do so, while the remediation planner keeps
the rendered source attribution needed to edit the correct file.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from cve_policy import repository, same_repository, split_image


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_ROOTS = ("apps", "platform", "workloads")
IGNORED_PARTS = {".git", ".archify", "__pycache__", "node_modules"}
WORKLOAD_KINDS = {
    "CronJob",
    "DaemonSet",
    "Deployment",
    "Job",
    "Pod",
    "StatefulSet",
}


class KubernetesLoader(yaml.SafeLoader):
    """Safe loader that tolerates Kubernetes' YAML 1.1 ``=`` value token."""


KubernetesLoader.add_constructor(
    "tag:yaml.org,2002:value",
    lambda loader, node: loader.construct_scalar(node),
)


def safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-")


def iter_manifest_files(root: Path = ROOT) -> Iterable[Path]:
    for root_name in MANIFEST_ROOTS:
        base = root / root_name
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
                continue
            if IGNORED_PARTS.intersection(path.parts):
                continue
            yield path


def load_yaml_documents(path: Path) -> list[dict[str, Any]]:
    try:
        loaded = list(
            yaml.load_all(path.read_text(encoding="utf-8"), Loader=KubernetesLoader)
        )
    except Exception as exc:
        raise ValueError(f"failed to parse YAML {path}: {exc}") from exc
    documents: list[dict[str, Any]] = []
    for index, document in enumerate(loaded):
        if document is None:
            continue
        if not isinstance(document, dict):
            raise ValueError(f"{path}[{index}] is not a YAML mapping")
        documents.append(document)
    return documents


def load_applications(root: Path) -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    for path in iter_manifest_files(root):
        for document in load_yaml_documents(path):
            if document.get("kind") != "Application":
                continue
            spec = document.get("spec") or {}
            source = spec.get("source") or {}
            metadata = document.get("metadata") or {}
            name = str(metadata.get("name", ""))
            if not name:
                continue
            applications.append(
                {
                    "name": name,
                    "chart": source.get("chart"),
                    "repo_url": source.get("repoURL"),
                    "target_revision": str(source.get("targetRevision", "")),
                    "path": str(source.get("path", "")),
                    "file": str(path.relative_to(root)),
                }
            )
    return applications


def _pod_spec(kind: str, document: dict[str, Any]) -> dict[str, Any] | None:
    spec = document.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    if kind in {"Deployment", "DaemonSet", "Job", "StatefulSet"}:
        return ((spec.get("template") or {}).get("spec"))
    return None


def workload_records(documents: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for document in documents:
        kind = str(document.get("kind", ""))
        if kind not in WORKLOAD_KINDS:
            continue
        metadata = document.get("metadata") or {}
        namespace = str(metadata.get("namespace", "default") or "default")
        name = str(metadata.get("name", ""))
        if not name:
            continue
        pod_spec = _pod_spec(kind, document)
        if not isinstance(pod_spec, dict):
            continue
        for field in ("initContainers", "containers", "ephemeralContainers"):
            for container in pod_spec.get(field) or []:
                if not isinstance(container, dict):
                    continue
                image = str(container.get("image", "")).strip()
                if not image:
                    continue
                records.append(
                    {
                        "namespace": namespace,
                        "kind": kind,
                        "name": name,
                        "container": str(container.get("name", "")),
                        "container_type": field,
                        "image": image,
                    }
                )
    return records


def _application_for_path(apps: list[dict[str, Any]], relative_path: str) -> dict[str, Any] | None:
    for app in apps:
        if app.get("path") and str(app["path"]).strip("/") == relative_path.strip("/"):
            return app
    return None


def _application_for_kustomize_path(
    apps: list[dict[str, Any]], relative_path: str
) -> dict[str, Any] | None:
    app = _application_for_path(apps, relative_path)
    if app:
        return app

    parts = Path(relative_path).parts
    if len(parts) == 2 and parts[0] == "workloads":
        root_app = next((item for item in apps if item.get("name") == "root"), None)
        return {
            "name": parts[1],
            "target_revision": root_app.get("target_revision") if root_app else None,
        }

    return next((item for item in apps if item.get("name") == "root"), None)


def rendered_inventory(render_dir: Path, root: Path) -> list[dict[str, Any]]:
    apps = load_applications(root)
    chart_apps = {safe_name(str(app["name"])): app for app in apps if app.get("chart")}
    records: list[dict[str, Any]] = []

    for path in sorted(render_dir.glob("chart-*.yaml")):
        app = chart_apps.get(path.stem[len("chart-") :])
        for record in workload_records(load_yaml_documents(path)):
            record.update(
                {
                    "source_kind": "helm-chart",
                    "source_path": app.get("file") if app else str(path),
                    "application": app.get("name") if app else None,
                    "chart": app.get("chart") if app else None,
                    "target_revision": app.get("target_revision") if app else None,
                }
            )
            records.append(record)

    for root_name in MANIFEST_ROOTS:
        base = root / root_name
        if not base.exists():
            continue
        for kustomization in sorted(base.rglob("kustomization.yaml")):
            relative = kustomization.parent.relative_to(root)
            output = render_dir / f"kustomize-{safe_name('__'.join(relative.parts))}.yaml"
            if not output.exists():
                raise ValueError(f"missing rendered Kustomization output: {output}")
            app = _application_for_kustomize_path(apps, str(relative))
            for record in workload_records(load_yaml_documents(output)):
                record.update(
                    {
                        "source_kind": "kustomize",
                        "source_path": str(relative),
                        "application": app.get("name") if app else None,
                        "chart": None,
                        "target_revision": app.get("target_revision") if app else None,
                    }
                )
                records.append(record)
    return records


def _resolved_live_image(container: dict[str, Any], status: dict[str, Any]) -> str:
    image = str(container.get("image", "")).strip()
    image_id = str(status.get("imageID", "")).strip()
    if "@" in image:
        return image
    if "@sha256:" in image_id:
        digest_ref = image_id.rsplit("://", 1)[-1]
        if same_repository(digest_ref, repository(image)):
            return digest_ref
    if image_id.startswith("sha256:"):
        return f"{repository(image)}@{image_id}"
    return image


def live_inventory(live_json: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(live_json.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to parse live workload JSON {live_json}: {exc}") from exc
    items = data.get("items") if isinstance(data, dict) and data.get("kind") == "List" else None
    if not isinstance(items, list):
        raise ValueError(f"{live_json}: expected a Kubernetes List with an items array")

    items = [item for item in items if isinstance(item, dict)]
    replica_owners: dict[tuple[str, str], tuple[str, str]] = {}
    for item in items:
        if item.get("kind") != "ReplicaSet":
            continue
        metadata = item.get("metadata") or {}
        owner = next(
            (
                ref
                for ref in metadata.get("ownerReferences") or []
                if isinstance(ref, dict) and ref.get("kind") == "Deployment"
            ),
            None,
        )
        if owner:
            replica_owners[(str(metadata.get("namespace", "default")), str(metadata.get("name", "")))] = (
                "Deployment",
                str(owner.get("name", "")),
            )

    resolved_pod_images: dict[tuple[str, str, str, str], str] = {}
    for item in items:
        if item.get("kind") != "Pod":
            continue
        metadata = item.get("metadata") or {}
        namespace = str(metadata.get("namespace", "default") or "default")
        owner_ref = next(
            (ref for ref in metadata.get("ownerReferences") or [] if isinstance(ref, dict)),
            None,
        )
        if not owner_ref:
            continue
        owner_kind = str(owner_ref.get("kind", ""))
        owner_name = str(owner_ref.get("name", ""))
        if owner_kind == "ReplicaSet":
            mapped = replica_owners.get((namespace, owner_name))
            if not mapped:
                continue
            owner_kind, owner_name = mapped
        elif owner_kind not in {"DaemonSet", "StatefulSet"}:
            continue

        pod_spec = _pod_spec("Pod", item)
        if not isinstance(pod_spec, dict):
            continue
        containers = {
            str(container.get("name", "")): container
            for field in ("initContainers", "containers")
            for container in pod_spec.get(field) or []
            if isinstance(container, dict)
        }
        statuses = {
            str(status.get("name", "")): status
            for status in (item.get("status") or {}).get("containerStatuses") or []
            if isinstance(status, dict)
        }
        for container_name, container in containers.items():
            status = statuses.get(container_name, {})
            resolved_pod_images[
                (namespace, owner_kind, owner_name, container_name)
            ] = _resolved_live_image(container, status)

    records: list[dict[str, Any]] = []
    for item in items:
        kind = str(item.get("kind", ""))
        if kind == "Pod" or kind not in WORKLOAD_KINDS:
            continue
        for record in workload_records([item]):
            key = (
                record["namespace"],
                record["kind"],
                record["name"],
                record["container"],
            )
            record["live_image"] = resolved_pod_images.get(key, record["image"])
            record["source_kind"] = "live"
            record["source_path"] = None
            record["application"] = None
            record["chart"] = None
            record["target_revision"] = None
            records.append(record)
    return records


def _workload_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(record.get("namespace", "")),
        str(record.get("kind", "")),
        str(record.get("name", "")),
        str(record.get("container", "")),
    )


def merge_inventory(
    rendered: list[dict[str, Any]], live: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    live_by_key = {_workload_key(record): record for record in live}
    rendered_keys = {_workload_key(record) for record in rendered}
    drift: list[dict[str, Any]] = []
    merged_records: dict[str, dict[str, Any]] = {}

    for record in rendered:
        key = _workload_key(record)
        live_record = live_by_key.get(key)
        scan_image = str(record["image"])
        rendered_repo = repository(scan_image)
        workload = {
            "namespace": record["namespace"],
            "kind": record["kind"],
            "name": record["name"],
            "container": record["container"],
            "container_type": record["container_type"],
            "application": record.get("application"),
            "source_kind": record.get("source_kind"),
            "source_path": record.get("source_path"),
            "chart": record.get("chart"),
            "target_revision": record.get("target_revision"),
            "rendered_image": scan_image,
        }
        if live_record:
            live_image = str(live_record.get("live_image") or live_record.get("image") or "")
            workload["live_image"] = live_image
            if same_repository(live_image, rendered_repo):
                scan_image = live_image
                _, rendered_tag, rendered_digest = split_image(str(record["image"]))
                _, live_tag, live_digest = split_image(live_image)
                changed_tag = bool(live_tag and rendered_tag and live_tag != rendered_tag)
                changed_digest = bool(
                    not live_tag
                    and not rendered_tag
                    and live_digest
                    and rendered_digest
                    and live_digest != rendered_digest
                )
                if changed_tag or changed_digest:
                    drift.append(
                        {
                            "type": "image_drift",
                            "workload": key,
                            "rendered_image": record["image"],
                            "live_image": live_image,
                        }
                    )
            else:
                drift.append(
                    {
                        "type": "repository_mismatch",
                        "workload": key,
                        "rendered_image": scan_image,
                        "live_image": live_image,
                    }
                )
        else:
            drift.append(
                {
                    "type": "rendered_not_live",
                    "workload": key,
                    "rendered_image": scan_image,
                }
            )

        entry = merged_records.setdefault(
            scan_image,
            {
                "scan_image": scan_image,
                "repository": repository(scan_image),
                "rendered_image": record["image"],
                "live_image": workload.get("live_image"),
                "workloads": [],
            },
        )
        entry["workloads"].append(workload)

    for key, live_record in live_by_key.items():
        if key in rendered_keys:
            continue
        live_image = str(live_record.get("live_image") or live_record.get("image") or "")
        drift.append({"type": "live_not_rendered", "workload": key, "live_image": live_image})
        entry = merged_records.setdefault(
            live_image,
            {
                "scan_image": live_image,
                "repository": repository(live_image),
                "rendered_image": None,
                "live_image": live_image,
                "workloads": [],
            },
        )
        entry["workloads"].append(
            {
                "namespace": live_record["namespace"],
                "kind": live_record["kind"],
                "name": live_record["name"],
                "container": live_record["container"],
                "container_type": live_record["container_type"],
                "application": None,
                "source_kind": "live",
                "source_path": None,
                "chart": None,
                "target_revision": None,
                "rendered_image": None,
                "live_image": live_image,
            }
        )

    records = sorted(merged_records.values(), key=lambda item: item["scan_image"])
    return records, drift


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--render-dir", type=Path, default=Path(".validation-renders"))
    parser.add_argument("--live-json", type=Path)
    parser.add_argument("--out", type=Path, default=Path(".validation-renders/image-inventory.json"))
    parser.add_argument("--images-out", type=Path, default=Path(".validation-renders/images.txt"))
    args = parser.parse_args()

    rendered = rendered_inventory(args.render_dir, args.root)
    live = live_inventory(args.live_json) if args.live_json else []
    records, drift = merge_inventory(rendered, live)
    if not args.live_json:
        drift = []
    output = {
        "inventory_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rendered_workloads": len(rendered),
        "live_workloads": len(live),
        "images": len(records),
        "drift": drift,
        "records": records,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.images_out.write_text(
        "\n".join(record["scan_image"] for record in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    print(
        f"image inventory: rendered_workloads={len(rendered)} live_workloads={len(live)} "
        f"images={len(records)} drift={len(drift)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
