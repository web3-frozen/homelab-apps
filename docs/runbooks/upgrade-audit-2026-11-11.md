# Upgrade audit: 2026-11-11

This records the versions checked after the low-risk GitOps and infrastructure
upgrade batches. Do not treat every newer version as an automatic patch: a
chart's own version can hide an application-level major migration.

## Completed

- K3s server and agents: `v1.37.2+k3s1`
- ArgoCD chart: `10.17.2`, application `v3.6.1`
- Traefik: `3.7.18`
- kube-prometheus-stack: `93.2.0`
- Loki chart: `7.6.0`, application `3.6.18`
- Reloader: `2.2.20`
- Renovate chart: `46.424.0`, application `44.229.0`
- Infisical application: `v0.167.8`
- Trivy and Trivy Action: `v0.76.2` and `v0.36.0`
- GitHub Actions runner: `v2.338.2`
- WSL kubectl client: `v1.37.2`
- Pulumi CLI and Python SDK: `v3.274.1`

The ArgoCD chart and Traefik Pulumi update rolled without restarting the
ArgoCD pods. `https://argocd.dummysui.monster/` returned HTTP 200 immediately
after the update.

## Maintenance-gated

### Longhorn

Current `1.7.2`; latest chart `1.13.0`.

This is a storage migration, despite Helm classifying the change from `1.7` to
`1.13` as a minor update. Do not merge the routine Renovate branch. Require
healthy replicas on separate nodes, a current recovery point, and a dedicated
Longhorn upgrade window. Renovate has an explicit dashboard-approval rule for
Longhorn minor and major updates.

### Redis

Current `7-alpine`; latest `8.10.3-alpine`.

Redis 8 is an application major upgrade. Test persistence, modules, ACLs, and
client compatibility before changing the workload. The floating `redis:alpine`
image used by the Online Boutique demo should also be pinned when that demo is
next revised.

### Helm

Current CI and WSL CLI `3.22.1`; latest `4.3.1`.

Helm 4 is a tooling major upgrade. It must be tested separately against chart
rendering, ArgoCD Helm behavior, and the GitOps validation workflow. Do not
combine it with dependency PRs.

### PostgreSQL

`demo-db` was patched from `17.2` to `17.11-system-bullseye` on 2026-11-11.
The image family stayed on Debian 11. Do not jump these clusters to
`system-trixie` in the same change.

`onchain-monitor-db` uses the same pin. Authentik already runs `18.6` and
was not part of this patch.

A one-instance CloudNativePG cluster does not switch over. The operator
restarts the primary in place, and the pod may be rescheduled to another node
while the RWO volume detaches. The `demo-db` restart began at 15:45:38Z and
the cluster was healthy again at 15:49:40Z, about four minutes. It also moved
from `k3s-worker-1` to `k3s-worker-3` while the volume reattached.
`onchain-monitor-db` restarted from 15:54:20Z to 15:57:52Z, about three and a
half minutes, and also landed on `k3s-worker-3`. Both clusters kept their
pre-upgrade table and live-row counts. Record that window; do not describe it
as zero downtime.

Take and verify a logical backup with the server's own `pg_restore` before
each database image change. The workstation `pg_restore` may be older than
dump format 1.16 and is not proof. Do not test database upgrades in a routine
dependency PR.

### Ubuntu nodes

Node OS and kernel packages have not been audited as part of the Kubernetes
version check. Use the Longhorn-aware node maintenance runbook and drain one
node at a time. Do not force-drain a node with a single-replica volume.

## Transitive images pinned by upstream charts

An up-to-date chart can still render old runtime images. These images were
found by rendering every release rather than only checking chart versions:

- Infisical chart `1.12.0` renders its bundled PostgreSQL as
  `bitnamilegacy/postgresql:16.2.0-debian-11-r16` and Redis as
  `bitnamilegacy/redis:7.2.4-debian-11-r18`.
- Linkerd viz `2026.11.1` renders Prometheus `v2.55.1`.
- Actions Runner Controller `0.23.7` renders kube-rbac-proxy `v0.13.1`.
- Goldilocks `11.2.1` carries an ingress-nginx admission-hook image from 2023.
  Its ingress controller is not the active ingress path, but the hook image
  still appears in rendered manifests.

Do not change these image tags independently without checking the owning
chart's compatibility. The preferred Infisical direction is to migrate the
bundled data stores to the existing CloudNativePG operator and a managed Redis,
then disable the chart's embedded dependencies. That is a data migration, not a
routine dependency PR.

## Deliberately not bumped

Online Boutique upstream release metadata is `v0.10.7`, but the public
microservice image tags are only published through `v0.10.5`. Pinning manifests
to nonexistent `v0.10.7` images would break the demo.
