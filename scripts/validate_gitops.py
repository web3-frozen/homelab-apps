#!/usr/bin/env python3
"""Render and validate GitOps candidates before ArgoCD can deploy them."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_ROOTS = ("apps", "platform", "workloads")
IGNORED_PARTS = {".git", ".archify", "__pycache__", "node_modules"}


class KubernetesLoader(yaml.SafeLoader):
    """Safe loader that tolerates Kubernetes' YAML 1.1 value token."""


KubernetesLoader.add_constructor(
    "tag:yaml.org,2002:value",
    lambda loader, node: loader.construct_scalar(node),
)


def log(message: str) -> None:
    print(message, flush=True)


def run(command: list[str], *, cwd: Path = ROOT) -> str:
    log("+ " + " ".join(command))
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}")
    return result.stdout


def safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-")


def iter_manifest_files() -> Iterable[Path]:
    for root_name in MANIFEST_ROOTS:
        root = ROOT / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
                continue
            if IGNORED_PARTS.intersection(path.parts):
                continue
            yield path


def load_documents(path: Path) -> list[dict[str, Any]]:
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise RuntimeError(f"YAML parse failed: {path.relative_to(ROOT)}: {exc}") from exc

    parsed: list[dict[str, Any]] = []
    for index, document in enumerate(documents):
        if document is None:
            continue
        if not isinstance(document, dict):
            raise RuntimeError(
                f"YAML document must be a mapping: {path.relative_to(ROOT)}[{index}]"
            )
        if "apiVersion" not in document or "kind" not in document:
            raise RuntimeError(
                f"Kubernetes manifest missing apiVersion/kind: "
                f"{path.relative_to(ROOT)}[{index}]"
            )
        parsed.append(document)
    return parsed


def dump_documents(path: Path, documents: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump_all(list(documents), handle, sort_keys=False)


def object_key(document: dict[str, Any]) -> tuple[str, str, str]:
    metadata = document.get("metadata") or {}
    return (
        str(document.get("kind", "")),
        str(metadata.get("namespace", "")),
        str(metadata.get("name", "")),
    )


def collect_images(documents: Iterable[dict[str, Any]]) -> set[str]:
    images: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "image" and isinstance(child, str) and child.strip():
                    images.add(child.strip())
                else:
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for document in documents:
        visit(document)
    return images


def helm_repo_alias(repo_url: str) -> str:
    digest = hashlib.sha256(repo_url.encode("utf-8")).hexdigest()[:10]
    return f"validation-{digest}"


def extract_application_documents() -> list[dict[str, Any]]:
    applications: list[dict[str, Any]] = []
    for path in iter_manifest_files():
        for document in load_documents(path):
            if document.get("kind") == "Application" and document.get(
                "apiVersion", ""
            ).startswith("argoproj.io/"):
                applications.append(document)
    return applications


def write_raw_manifests(output_dir: Path, applications: list[dict[str, Any]]) -> list[dict[str, Any]]:
    application_keys = {
        (
            document.get("kind"),
            (document.get("metadata") or {}).get("namespace"),
            (document.get("metadata") or {}).get("name"),
        )
        for document in applications
    }
    raw_documents: list[dict[str, Any]] = []
    for path in iter_manifest_files():
        for document in load_documents(path):
            key = (
                document.get("kind"),
                (document.get("metadata") or {}).get("namespace"),
                (document.get("metadata") or {}).get("name"),
            )
            if key in application_keys:
                continue
            if document.get("kind") in {"Kustomization", "List"}:
                continue
            raw_documents.append(document)
    dump_documents(output_dir / "raw-manifests.yaml", raw_documents)
    dump_documents(output_dir / "applications.yaml", applications)
    return raw_documents


def render_helm_applications(
    applications: list[dict[str, Any]], output_dir: Path
) -> tuple[list[dict[str, Any]], set[str]]:
    added_repositories: set[str] = set()
    rendered_documents: list[dict[str, Any]] = []
    namespaces: set[str] = set()

    for application in sorted(
        applications, key=lambda item: (item.get("metadata") or {}).get("name", "")
    ):
        source = (application.get("spec") or {}).get("source") or {}
        repo_url = source.get("repoURL")
        oci_chart = str(repo_url).startswith("oci://") and "helm" in source
        chart = repo_url if oci_chart else source.get("chart")
        if not chart:
            continue

        app_name = (application.get("metadata") or {}).get("name", "unknown")
        target_revision = str(source.get("targetRevision", ""))
        namespace = str((application.get("spec") or {}).get("destination", {}).get(
            "namespace", "default"
        ))

        if not repo_url:
            raise RuntimeError(f"{app_name}: chart source has no repoURL")
        if not re.match(r"^v?\d", target_revision):
            raise RuntimeError(
                f"{app_name}: chart targetRevision must be an explicit version, "
                f"got {target_revision!r}"
            )

        alias = helm_repo_alias(str(repo_url))
        if not oci_chart and alias not in added_repositories:
            subprocess.run(
                ["helm", "repo", "add", alias, str(repo_url), "--force-update"],
                cwd=ROOT,
                check=False,
                text=True,
                capture_output=True,
            )
            run(["helm", "repo", "update", alias])
            added_repositories.add(alias)

        helm_config = source.get("helm") or {}
        release_name = helm_config.get("releaseName") or app_name
        values_object = helm_config.get("valuesObject") or {}
        values_path = output_dir / f"{safe_name(app_name)}.values.json"
        values_path.write_text(
            json.dumps(values_object, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        output_path = output_dir / f"chart-{safe_name(app_name)}.yaml"
        rendered = run(
            [
                "helm",
                "template",
                str(release_name),
                str(chart) if oci_chart else f"{alias}/{chart}",
                "--version",
                target_revision,
                "--namespace",
                namespace,
                "--include-crds",
                "--skip-tests",
                "-f",
                str(values_path),
            ]
        )
        output_path.write_text(rendered, encoding="utf-8")
        namespaces.add(namespace)

        for document in yaml.load_all(rendered, Loader=KubernetesLoader):
            if isinstance(document, dict) and document.get("apiVersion"):
                rendered_documents.append(document)

    return rendered_documents, namespaces


def render_kustomizations(output_dir: Path) -> tuple[list[dict[str, Any]], set[str]]:
    rendered_documents: list[dict[str, Any]] = []
    namespaces: set[str] = set()

    for root_name in MANIFEST_ROOTS:
        root = ROOT / root_name
        if not root.exists():
            continue
        for kustomization in sorted(root.rglob("kustomization.yaml")):
            relative = kustomization.parent.relative_to(ROOT)
            name = safe_name("__".join(relative.parts))
            rendered = run(["kubectl", "kustomize", str(kustomization.parent)])
            output_path = output_dir / f"kustomize-{name}.yaml"
            output_path.write_text(rendered, encoding="utf-8")
            for document in yaml.load_all(rendered, Loader=KubernetesLoader):
                if not isinstance(document, dict) or not document.get("apiVersion"):
                    continue
                rendered_documents.append(document)
                if document.get("kind") == "Namespace":
                    namespace = (document.get("metadata") or {}).get("name")
                    if namespace:
                        namespaces.add(str(namespace))

    return rendered_documents, namespaces


def extra_documents(paths: Iterable[str]) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            loaded = list(
                yaml.load_all(
                    path.read_text(encoding="utf-8"),
                    Loader=KubernetesLoader,
                )
            )
        except Exception as exc:
            raise RuntimeError(f"extra YAML parse failed: {path}: {exc}") from exc
        documents.extend(doc for doc in loaded if isinstance(doc, dict))
    return documents


def write_cluster_prerequisites(
    output_dir: Path,
    rendered_documents: list[dict[str, Any]],
    extra: list[dict[str, Any]],
    application_namespaces: set[str],
) -> None:
    crds: dict[tuple[str, str], dict[str, Any]] = {}
    namespaces = set(application_namespaces)

    for document in [*rendered_documents, *extra]:
        metadata = document.get("metadata") or {}
        namespace = metadata.get("namespace")
        if namespace:
            namespaces.add(str(namespace))
        if document.get("kind") == "CustomResourceDefinition":
            name = str(metadata.get("name", ""))
            if name:
                crds[(name, str(document.get("apiVersion", "")))] = document
        elif document.get("kind") == "Namespace":
            name = metadata.get("name")
            if name:
                namespaces.add(str(name))

    if not crds:
        raise RuntimeError("no CRDs were rendered; refusing an incomplete dry-run")

    dump_documents(output_dir / "crds.yaml", crds.values())
    dump_documents(
        output_dir / "namespaces.yaml",
        [
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": namespace},
            }
            for namespace in sorted(namespaces)
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default=".validation-renders",
        help="Directory for rendered manifests and validation metadata",
    )
    parser.add_argument(
        "--extra-crds-yaml",
        action="append",
        default=[],
        help="Additional rendered YAML files that contain bootstrap CRDs",
    )
    args = parser.parse_args()

    output_dir = ROOT / args.output
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    applications = extract_application_documents()
    if not applications:
        raise RuntimeError("no ArgoCD Application manifests found")

    raw_documents = write_raw_manifests(output_dir, applications)
    helm_documents, helm_namespaces = render_helm_applications(applications, output_dir)
    kustomize_documents, kustomize_namespaces = render_kustomizations(output_dir)
    extra = extra_documents(args.extra_crds_yaml)

    application_namespaces = {
        str((application.get("metadata") or {}).get("namespace"))
        for application in applications
        if (application.get("metadata") or {}).get("namespace")
    }
    namespaces = (
        helm_namespaces
        | kustomize_namespaces
        | application_namespaces
    )
    write_cluster_prerequisites(
        output_dir,
        [*raw_documents, *helm_documents, *kustomize_documents],
        extra,
        namespaces,
    )
    images = collect_images(
        [*raw_documents, *helm_documents, *kustomize_documents]
    )
    (output_dir / "images.txt").write_text(
        "\n".join(sorted(images)) + ("\n" if images else ""),
        encoding="utf-8",
    )

    summary = {
        "applications": len(applications),
        "helm_releases": sum(
            1
            for application in applications
            if ((application.get("spec") or {}).get("source") or {}).get("chart")
        ),
        "kustomize_outputs": len(list(output_dir.glob("kustomize-*.yaml"))),
        "chart_outputs": len(list(output_dir.glob("chart-*.yaml"))),
        "raw_documents": len(raw_documents),
        "rendered_helm_documents": len(helm_documents),
        "rendered_kustomize_documents": len(kustomize_documents),
        "images": len(images),
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    log(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        log(f"ERROR: {exc}")
        raise SystemExit(1)
