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

`demo-db` and `onchain-monitor-db` run PostgreSQL `17.2`; the same-major current
patch is `17.11`. Authentik already runs `18.6`.

Take and verify a logical or volume backup first, then perform a controlled
CloudNativePG rolling update. Do not test database upgrades directly in the
routine dependency PR.

### Ubuntu nodes

Node OS and kernel packages have not been audited as part of the Kubernetes
version check. Use the Longhorn-aware node maintenance runbook and drain one
node at a time. Do not force-drain a node with a single-replica volume.

## Deliberately not bumped

Online Boutique upstream release metadata is `v0.10.7`, but the public
microservice image tags are only published through `v0.10.5`. Pinning manifests
to nonexistent `v0.10.7` images would break the demo.
