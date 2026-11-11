# Homelab Apps — GitOps Repository

ArgoCD App of Apps repository for the K3s homelab cluster.  
Push to `main` → ArgoCD auto-syncs everything.

## Stack Overview

| Category | Tool | Purpose |
|----------|------|---------|
| **Demo App** | [Google Online Boutique](https://github.com/GoogleCloudPlatform/microservices-demo) | 10-microservice e-commerce demo (Go, Python, Java, C#, Node.js) |
| **OTel Demo Workload** | Task Manager demo | Frontend, API, inventory, pricing, PostgreSQL, Redis, and a third-party quote provider |
| **Monitoring App** | [Onchain Monitor](workloads/onchain-monitor/) | DeFi metrics monitoring with Telegram alerts (Go backend + Next.js frontend) |
| **Service Mesh** | [Linkerd](https://linkerd.io/) | Lightweight mTLS, traffic metrics, golden signals |
| **Secrets** | [External Secrets Operator](https://external-secrets.io/) + [Infisical](https://infisical.com/) | Secret management with self-hosted backend |
| **Identity / SSO** | [Authentik](https://goauthentik.io/) | OIDC identity provider for ArgoCD and Grafana with an admin IP allowlist |
| **Policy** | [Kyverno](https://kyverno.io/) | Privileged-container and label checks enforced; resource-limit checks audited |
| **TLS** | [cert-manager](https://cert-manager.io/) | Cloudflare DNS-01 automation and Let's Encrypt issuers |
| **Storage** | [Longhorn](https://longhorn.io/) | Replicated persistent volumes with two default replicas |
| **Right-sizing** | [Goldilocks](https://github.com/FairwindsOps/goldilocks) + VPA | CPU/memory recommendation dashboard |
| **Network Policies** | Kubernetes NetworkPolicy | Default-deny ingress per namespace with explicit allow rules |
| **Metrics** | Prometheus + Grafana | Four focused Grafana dashboards for cluster, APM, Onchain Monitor, and the OTel demo |
| **Logs** | [Grafana Alloy](https://grafana.com/docs/alloy/) + [Loki](https://grafana.com/oss/loki/) | Kubernetes log collection and querying in Grafana |
| **APM / Traces** | [Grafana Beyla](https://grafana.com/oss/beyla-ebpf/) + OTel Collector + [Tempo](https://grafana.com/oss/tempo/) | Service, dependency, and request-level latency analysis |
| **CI runner** | Actions Runner Controller | Repository-scoped ephemeral runner for this repository |
| **Dependencies** | [Renovate](https://docs.renovatebot.com/) | Daily GitHub App-authenticated updates; PRs must pass the blocking GitOps validation gate |
| **Config Reload** | [Reloader](https://github.com/stakater/Reloader) | Auto-restart pods on ConfigMap/Secret changes |
| **Infra Alerting** | AlertManagerConfig | Routes PrometheusRule alerts to Telegram (onchain-monitor namespace) |

## Directory Structure

```
homelab-apps/
├── apps/                        # ArgoCD Application definitions
│   ├── root.yaml                # App of Apps root (bootstrapped by Pulumi)
│   ├── online-boutique.yaml     # Demo: Google Online Boutique
│   ├── linkerd.yaml             # Service mesh: CRDs + control plane + viz
│   ├── external-secrets.yaml    # Secret operator
│   ├── infisical.yaml           # Self-hosted secret manager
│   ├── authentik.yaml           # SSO Helm chart
│   ├── authentik-config.yaml    # PostgreSQL, secrets, blueprints, ingress
│   ├── cert-manager.yaml        # Cloudflare DNS-01 certificate automation
│   ├── cert-manager-config.yaml # ExternalSecret and ClusterIssuers
│   ├── longhorn.yaml            # Replicated storage
│   ├── kyverno.yaml             # Policy engine + policies
│   ├── goldilocks.yaml          # Resource recommender + VPA
│   ├── alloy.yaml               # Log collector (replaces Promtail)
│   ├── loki.yaml                # Log storage
│   ├── tempo.yaml               # Trace storage (OTLP)
│   ├── otel-collector.yaml      # Span normalization before Tempo
│   ├── actions-runner.yaml      # ARC Helm chart + runner Application
│   ├── renovate.yaml            # Renovate credentials + CronJob Applications
│   └── reloader.yaml            # ConfigMap/Secret watcher
├── platform/                    # Platform component manifests
│   ├── linkerd/                 # Linkerd identity cert setup Job
│   ├── authentik/               # Authentik database, OIDC blueprint, ingress
│   ├── cert-manager/            # DNS-01 credentials and issuers
│   ├── kyverno/                 # Kyverno cluster policies
│   ├── actions-runner/          # Repository-scoped RunnerDeployment
│   └── monitoring/              # Grafana datasources, 3 dashboards, alerting
└── workloads/                   # Application workloads
    ├── online-boutique/         # Google Online Boutique manifests
    │   ├── namespace.yaml
    │   ├── services.yaml
    │   └── ingress.yaml
    ├── demo-app/                # Annotation-driven OTel demo workload
    │   ├── backend.yaml         # API + checkout entry point
    │   ├── inventory.yaml       # PostgreSQL, Redis, and pricing orchestration
    │   ├── pricing.yaml         # Third-party quote dependency
    │   ├── postgres.yaml
    │   ├── frontend.yaml
    │   └── network-policy.yaml
    └── onchain-monitor/         # Onchain Monitor workload
        ├── kustomization.yaml
        ├── servicemonitor.yaml  # Prometheus scrape config
        ├── prometheusrules.yaml # Alert rules (app health + DB storage)
        └── network-policy.yaml  # Default-deny ingress + allow rules
```

### Network Policies

Each workload namespace has a `network-policy.yaml` with:
- **Default deny ingress** — no traffic allowed unless explicitly permitted
- **Allow same namespace** — pods within the same namespace can communicate
- **Allow ingress controller** — traffic from kube-system (Traefik) is permitted
- **Allow DNS egress** — pods can reach kube-dns for name resolution
- **Allow external egress** — pods can reach external APIs

Redis namespace additionally allows ingress from the `onchain-monitor` namespace only.

## Grafana

Grafana intentionally exposes four dashboards:

| Dashboard | Questions it answers |
|-----------|----------------------|
| **Homelab - Overview** | Are nodes and pods healthy? What is consuming CPU, memory, or disk? Which workloads are restarting, throttled, or missing replicas? |
| **APM - Request and Dependency Latency** | Is the frontend, backend, or a third-party dependency slow? Which service, route, or upstream call has high p95 or p99 latency? |
| **Onchain Monitor** | Is polling fresh? Which data source is failing or slow? Are alerts being delivered? What do recent logs show? |
| **Demo App - End-to-End Observability** | What is the live service topology, which edge is slow, and what did one checkout request do from browser through PostgreSQL, Redis, and the external quote provider? |

The kube-prometheus-stack default dashboards are disabled in
`apps/monitoring.yaml`. Do not enable them again without removing or replacing
the consolidated dashboards; the chart otherwise adds more than 30 overlapping
dashboards to Grafana.

Dashboard source lives in `platform/monitoring/*.json` and is rendered by the
`monitoring-config` Argo CD Application. Grafana UI edits are disabled by the
sidecar provider. Change the JSON in Git, not the UI.

Grafana admin credentials are stored in Infisical as
`INFRA_GRAFANA_ADMIN_PASSWORD` and synced to the `monitoring/grafana-admin`
Secret by External Secrets Operator. Reloader restarts Grafana after a
credential rotation is synced.

## APM

The APM dashboard answers:

- Which service or route has slow p95/p99 latency?
- Which outbound dependency is slow?
- Which onchain data source is slow or failing?
- Which individual request was slow, via Tempo traces?
- What are the upstream and downstream services for an application?

Prometheus supplies RED metrics and dependency latency. Tempo stores 10% sampled
traces exported by Beyla. Alloy reads local pod logs and links logs to traces in
Grafana through the `trace_id` derived field.

Beyla exports through the Argo CD-managed OTel Collector, which normalizes
database and external-dependency attributes before forwarding spans to Tempo.
Tempo's `service-graphs` processor writes `traces_service_graph_*` metrics back
to Prometheus. Open **Explore -> Tempo -> Service Graph** to interact with the
live topology. The same view is linked from the Demo App dashboard.

The APM dashboard reports P95 and P99 side by side. The upstream error table
keeps the HTTP status code so rate limits such as `429` are not confused with
application `5xx` failures.

See [`docs/grafana-dashboards.md`](docs/grafana-dashboards.md) for dashboard
ownership and troubleshooting.

## Upgrade Validation

Every upgrade pull request must pass `Validate GitOps upgrades` before merge.
The gate renders all Helm and Kustomize candidates, then validates them in an
ephemeral kind cluster with the required CRDs installed. A failure keeps the old
version; it is not auto-merged.

See [`docs/runbooks/upgrade-validation.md`](docs/runbooks/upgrade-validation.md)
for scope and limitations.

See
[`docs/runbooks/upgrade-audit-2026-11-11.md`](docs/runbooks/upgrade-audit-2026-11-11.md)
for the current version audit and the upgrades that require a maintenance
window.

## Access URLs

| Service | URL |
|---------|-----|
| Online Boutique | `https://shop.<your-domain>` |
| ArgoCD | `https://argocd.<your-domain>` |
| Grafana | `https://grafana.<your-domain>` |
| Authentik | `https://auth.<your-domain>` |

## Adding a New App

1. Create manifests in `workloads/my-app/` or `platform/my-tool/`
2. Create `apps/my-app.yaml` ArgoCD Application pointing to that path
3. `git push` — ArgoCD picks it up automatically

## Linkerd Mesh Injection

To add a namespace to the service mesh, add the label:
```yaml
metadata:
  labels:
    linkerd.io/inject: enabled
```

## Goldilocks Monitoring

To enable resource recommendations for a namespace:
```bash
kubectl label namespace <name> goldilocks.fairwinds.com/enabled=true
```

## Architecture

```
GitHub → ArgoCD App of Apps → Helm charts and workload manifests
GitHub → Actions Runner Controller → ephemeral self-hosted jobs

User → Cloudflare (TLS) → Encrypted Tunnel → Traefik (HTTP:80)
                                                ├── shop.<domain> → Online Boutique frontend
                                                ├── argocd.<domain> → ArgoCD server
                                                ├── grafana.<domain> → Grafana dashboard
                                                └── auth.<domain> → Authentik (IP allowlisted)

Pod-to-Pod: Linkerd mTLS sidecar proxy (automatic within meshed namespaces)
Checkout path: browser -> demo-api -> demo-inventory -> demo-pricing
               demo-inventory -> PostgreSQL / Redis
               demo-pricing -> external market-data API
Secrets: Infisical → External Secrets Operator → Kubernetes Secrets
Identity: Authentik OIDC → ArgoCD and Grafana; ArgoCD local admin is break-glass
Policy: Kyverno enforces security standards (privileged containers, resource limits, labels)
Network: Default-deny ingress NetworkPolicies per workload namespace
```

Pulumi only bootstraps the infrastructure and credentials required before
ArgoCD is available. New platform Helm charts belong here as ArgoCD
Applications, not in the Pulumi program.

Recovery procedures for the Kyverno migration-hook loop and the immutable
Linkerd trust Job are documented in the
[Pulumi repository runbook](https://github.com/web3-frozen/pulumi-k3s-proxmox/blob/main/docs/runbooks/argocd-sync-failures.md).

Authentik login, allowlist, secret names, and OIDC recovery are documented in
[`docs/runbooks/authentik-sso.md`](docs/runbooks/authentik-sso.md).

Upgrade candidates are validated by
[`scripts/validate_gitops.py`](scripts/validate_gitops.py) and the
[`Validate GitOps upgrades`](.github/workflows/validate-gitops.yaml) workflow.
