# Implementation Plan: Homelab Dependency and Trust Migration

## Overview

Bring the homelab GitOps stack back onto maintained releases, migrate
Linkerd off its frozen 2.14 line, and replace the expiring self-generated
identity issuer with a rotatable trust chain. Every change is rendered and
validated before GitOps rollout, and each component has a rollback point.

## Architecture Decisions

- Use the Linkerd edge channel because the 2.14 stable channel has been frozen
  since 2024 and no newer stable OSS chart is published.
- Use cert-manager for Linkerd root and issuer lifecycle, with an overlap
  trust-anchor window instead of replacing the root in place.
- Pin Trivy CLI and action versions to the latest released versions; do not use
  floating `latest` at runtime.
- Upgrade Helm releases in dependency order and verify Argo health after each
  checkpoint.

## Task List

### Phase 1: Baseline and Tools
- [x] Capture Helm releases, Argo app health, node health, and current image tags.
- [x] Install pinned Helm and Linkerd edge CLI binaries with checksum verification.
- [x] Update Trivy CLI/action to the newest releases.

### Checkpoint: Baseline
- [x] Rollback commands and current versions are recorded.
- [x] Rendering tools match the target releases.

### Phase 2: Low-risk Charts
- [x] Upgrade Reloader.
- [x] Upgrade Goldilocks.
- [x] Upgrade External Secrets.

### Checkpoint: Low-risk Charts
- [x] All affected Apps are Synced/Healthy.
- [x] Existing secrets and workloads remain healthy.

### Phase 3: Stateful and Policy Components
- [x] Upgrade CloudNativePG and verify both PostgreSQL clusters.
- [x] Upgrade Kyverno and verify policy reports and admission.
- [x] Upgrade Infisical and verify External Secrets sync.

### Checkpoint: Stateful and Policy Components
- [x] Databases remain Ready.
- [x] Kyverno policies remain Enforcing.
- [x] ExternalSecret resources remain synced.

### Phase 4: Observability
- [x] Upgrade Loki and verify log ingestion/query.
- [x] Upgrade Beyla and verify metrics/traces.
- [x] Upgrade cert-manager to v1.21.3.
- [x] Upgrade kube-prometheus-stack to 93.1.0.
- [x] Upgrade the K3s-bundled Traefik runtime to v3.7.17.
- [x] Verify Grafana APM and logs dashboards.

### Checkpoint: Observability
- [x] Loki contains recent app logs with `namespace` labels.
- [x] Tempo receives spans.
- [x] Prometheus scrapes app metrics.

### Phase 5: Linkerd Trust Migration
- [x] Upgrade Linkerd CRDs/control plane/viz to edge-26.11.1.
- [x] Introduce cert-manager-managed root and issuer with overlap bundle.
- [x] Restart meshed workloads in controlled stages.
- [x] Cut over issuer, verify mTLS, then remove the legacy root.

### Checkpoint: Linkerd
- [x] Identity issuer is cert-manager managed and auto-rotating.
- [x] Linkerd check reports no trust-anchor or identity errors.
- [x] Workload traffic and APM traces remain healthy.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Linkerd trust-anchor cutover breaks mTLS | High | Keep old and new roots in the trust bundle during overlap, then restart and verify before removing old root |
| Loki major-version values changed | High | Render both old and new charts, diff rendered resources, retain 102d data and previous values for rollback |
| CNPG operator/CRD upgrade affects databases | High | Upgrade operator first, verify Cluster CR status and application connectivity before moving on |
| Infisical chart migration changes dependencies | High | Render chart, confirm embedded Postgres/Redis and External Secrets auth before rollout |
| Argo auto-sync races manual validation | Medium | Push one component at a time and use explicit health checkpoints |

## Open Questions

- None required before starting; rollback is preferred over destructive fixes.
