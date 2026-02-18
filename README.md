# Homelab Apps — GitOps Repository

ArgoCD App of Apps repository for the K3s homelab cluster.  
Push to `main` → ArgoCD auto-syncs everything.

## Stack Overview

| Category | Tool | Purpose |
|----------|------|---------|
| **Demo App** | [Google Online Boutique](https://github.com/GoogleCloudPlatform/microservices-demo) | 10-microservice e-commerce demo (Go, Python, Java, C#, Node.js) |
| **Monitoring App** | [Onchain Monitor](workloads/onchain-monitor/) | DeFi metrics monitoring with Telegram alerts (Go backend + Next.js frontend) |
| **Service Mesh** | [Linkerd](https://linkerd.io/) | Lightweight mTLS, traffic metrics, golden signals |
| **Secrets** | [External Secrets Operator](https://external-secrets.io/) + [Infisical](https://infisical.com/) | Secret management with self-hosted backend |
| **Policy** | [Kyverno](https://kyverno.io/) | Pod security, resource limits, label enforcement |
| **Right-sizing** | [Goldilocks](https://github.com/FairwindsOps/goldilocks) + VPA | CPU/memory recommendation dashboard |
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
│   ├── kyverno.yaml             # Policy engine + policies
│   ├── goldilocks.yaml          # Resource recommender + VPA
│   └── reloader.yaml            # ConfigMap/Secret watcher
├── platform/                    # Platform component manifests
│   ├── linkerd/                 # Linkerd identity cert setup Job
│   ├── kyverno/                 # Kyverno cluster policies
│   └── monitoring/              # AlertManagerConfig (Telegram), Grafana dashboards
└── workloads/                   # Application workloads
    ├── online-boutique/         # Google Online Boutique manifests
    │   ├── namespace.yaml
    │   ├── services.yaml
    │   └── ingress.yaml
    └── onchain-monitor/         # Onchain Monitor workload
        ├── kustomization.yaml
        ├── servicemonitor.yaml  # Prometheus scrape config
        └── prometheusrules.yaml # Alert rules (app health + DB storage)
```

## Access URLs

| Service | URL |
|---------|-----|
| Online Boutique | https://shop.&lt;your-domain&gt; |
| ArgoCD | https://argocd.&lt;your-domain&gt; |
| Grafana | https://grafana.&lt;your-domain&gt; |

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
User → Cloudflare (TLS) → Encrypted Tunnel → Traefik (HTTP:80)
                                                ├── shop.<domain> → Online Boutique frontend
                                                ├── argocd.<domain> → ArgoCD server
                                                └── grafana.<domain> → Grafana dashboard

Pod-to-Pod: Linkerd mTLS sidecar proxy (automatic within meshed namespaces)
Secrets: Infisical → External Secrets Operator → Kubernetes Secrets
Policy: Kyverno audits all pods for security best practices
```
