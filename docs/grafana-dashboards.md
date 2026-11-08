# Grafana Dashboard Operations

## Dashboard Catalog

Grafana is deliberately limited to three dashboards in the `Homelab` folder.

### Homelab - Overview

Use this as the first screen during an infrastructure incident. It shows:

- node readiness and pod readiness
- CPU, memory, and root filesystem utilization by node
- restart hotspots
- PVC utilization
- deployments with missing replicas
- CPU throttling hotspots

### APM - Request and Dependency Latency

Use this to attribute latency to a frontend, backend, or third-party call.

- server traffic, 5xx rate, and p95 latency by service
- p95 latency split into frontend, backend, and third-party dependency calls
- slow server routes
- slow upstream calls with caller-to-upstream attribution
- third-party dependency error rate
- onchain source polling latency
- Tempo trace ingest rate

This dashboard is backed by Beyla eBPF metrics and Tempo traces. Applications do
not need code changes to appear in the service metrics.

### Onchain Monitor

Use this for application health, data freshness, business metrics, and logs.

- API availability, traffic, errors, latency, CPU, memory, and restarts
- poll success, failure, and source latency
- data freshness and in-memory snapshot counts
- TVL, token prices, subscriptions, and Telegram users
- alert delivery
- Loki logs filtered by level

## Ownership

| Resource | Owner | Source |
|----------|-------|--------|
| kube-prometheus-stack | Argo CD | `apps/monitoring.yaml` |
| Beyla | Argo CD | `apps/beyla.yaml` |
| datasources, dashboards, alerts | Argo CD | `platform/monitoring/` |
| Grafana admin password | External Secrets Operator | Infisical `INFRA_GRAFANA_ADMIN_PASSWORD` |

The Grafana Deployment is annotated for Reloader. After a credential rotation
is synced into `monitoring/grafana-admin`, Reloader restarts Grafana so the new
environment value takes effect.

The Helm chart default dashboards are disabled with
`grafana.defaultDashboardsEnabled=false`. Leaving them enabled restores more
than 30 overlapping cluster dashboards and makes the three curated dashboards
hard to find.

## Change Workflow

1. Edit the relevant JSON file in `platform/monitoring/`.
2. Run `kubectl kustomize platform/monitoring` and parse the embedded JSON.
3. Push to `main`.
4. Confirm `monitoring-config` and `monitoring` Applications are `Synced` and
   `Healthy`.
5. Open Grafana and verify the changed panel returns data.

Do not edit provisioned dashboards in the Grafana UI. The sidecar provider has
`allowUiUpdates=false`, so UI changes are overwritten or lost.

## Troubleshooting

Check the Argo CD Applications:

```bash
kubectl -n argocd get applications monitoring monitoring-config beyla
```

Check dashboard discovery:

```bash
kubectl -n monitoring get configmaps -l grafana_dashboard=1
```

Only the following project dashboards should be present:

- `grafana-dashboard-homelab`
- `grafana-dashboard-apm`
- `grafana-dashboard-onchain`

Old chart dashboards use names starting with `kube-prometheus-stack-` and the
`grafana_dashboard=1` label. They are safe to remove only after
`defaultDashboardsEnabled=false` is confirmed in `apps/monitoring.yaml`.

Check the Grafana admin secret:

```bash
kubectl -n monitoring get externalsecret grafana-admin
kubectl -n monitoring get secret grafana-admin
```

If Grafana pods are waiting for `grafana-admin`, inspect the ExternalSecret event
and confirm `INFRA_GRAFANA_ADMIN_PASSWORD` exists in Infisical project
`homelab`, environment `prod`, path `/`.
