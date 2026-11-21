from __future__ import annotations

import json
from pathlib import Path

from cve_inventory import live_inventory, merge_inventory, rendered_inventory, workload_records


def test_workload_records_extract_cronjob_container() -> None:
    document = {
        "kind": "CronJob",
        "metadata": {"namespace": "jobs", "name": "nightly"},
        "spec": {
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{"name": "worker", "image": "busybox:1.36"}]
                        }
                    }
                }
            }
        },
    }
    records = workload_records([document])
    assert records == [
        {
            "namespace": "jobs",
            "kind": "CronJob",
            "name": "nightly",
            "container": "worker",
            "container_type": "containers",
            "image": "busybox:1.36",
        }
    ]


def test_merge_prefers_live_digest_and_records_drift() -> None:
    rendered = [
        {
            "namespace": "apps",
            "kind": "Deployment",
            "name": "web",
            "container": "web",
            "container_type": "containers",
            "image": "ghcr.io/example/web:abc",
            "application": "web",
            "source_kind": "kustomize",
            "source_path": "workloads/web",
            "chart": None,
            "target_revision": None,
        }
    ]
    live = [
        {
            "namespace": "apps",
            "kind": "Deployment",
            "name": "web",
            "container": "web",
            "container_type": "containers",
            "image": "ghcr.io/example/web:abc",
            "live_image": "ghcr.io/example/web@sha256:" + "a" * 64,
        }
    ]
    records, drift = merge_inventory(rendered, live)
    assert records[0]["scan_image"].endswith("@" + "sha256:" + "a" * 64)
    assert records[0]["workloads"][0]["application"] == "web"
    assert drift == []


def test_live_inventory_resolves_pod_digest_without_duplicating_pods(tmp_path: Path) -> None:
    digest = "sha256:" + "b" * 64
    live = {
        "kind": "List",
        "items": [
            {
                "kind": "Deployment",
                "metadata": {"namespace": "apps", "name": "web"},
                "spec": {
                    "template": {
                        "spec": {"containers": [{"name": "web", "image": "ghcr.io/example/web:abc"}]}
                    }
                },
            },
            {
                "kind": "ReplicaSet",
                "metadata": {
                    "namespace": "apps",
                    "name": "web-abc123",
                    "ownerReferences": [{"kind": "Deployment", "name": "web"}],
                },
                "spec": {},
            },
            {
                "kind": "Pod",
                "metadata": {
                    "namespace": "apps",
                    "name": "web-abc123-xyz",
                    "ownerReferences": [{"kind": "ReplicaSet", "name": "web-abc123"}],
                },
                "spec": {"containers": [{"name": "web", "image": "ghcr.io/example/web:abc"}]},
                "status": {
                    "containerStatuses": [
                        {"name": "web", "imageID": f"docker-pullable://ghcr.io/example/web@{digest}"}
                    ]
                },
            },
        ],
    }
    path = tmp_path / "live.json"
    path.write_text(json.dumps(live), encoding="utf-8")
    records = live_inventory(path)
    assert len(records) == 1
    assert records[0]["live_image"] == f"ghcr.io/example/web@{digest}"


def test_rendered_workload_uses_application_set_name(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    apps = root / "apps"
    apps.mkdir(parents=True)
    (apps / "root.yaml").write_text(
        """apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: root
spec:
  source:
    path: apps
    targetRevision: main
""",
        encoding="utf-8",
    )
    workload = root / "workloads" / "demo-app"
    workload.mkdir(parents=True)
    (workload / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n",
        encoding="utf-8",
    )
    render_dir = tmp_path / "renders"
    render_dir.mkdir()
    (render_dir / "kustomize-workloads__demo-app.yaml").write_text(
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: demo-app
spec:
  template:
    spec:
      containers:
        - name: web
          image: ghcr.io/example/web:abc
""",
        encoding="utf-8",
    )

    records = rendered_inventory(render_dir, root)
    assert len(records) == 1
    assert records[0]["application"] == "demo-app"
    assert records[0]["target_revision"] == "main"
