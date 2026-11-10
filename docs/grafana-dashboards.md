# Grafana Dashboard Operations

## Dashboard Catalog

Grafana is deliberately limited to four dashboards in the `Homelab` folder.

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

- server traffic, 5xx rate, and P95/P99 latency by service
- P95/P99 latency split into frontend, backend, and third-party dependency calls
- slow server routes
- slow upstream calls with caller-to-upstream attribution
- third-party dependency error rate with HTTP status attribution
- onchain source polling P95/P99 latency
- Tempo trace ingest rate

The upstream error table includes the HTTP status. A `429` is a provider rate
limit and should not be read as an application `5xx` failure.

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

### Demo App - End-to-End Observability

Use this for the annotation-driven observability POC.

- live Tempo Service Graph link
- service-graph edge latency at p95 and p99
- checkout request rate and error rate
- PostgreSQL operation latency
- browser-to-API latency
- trace drills from the dashboard into Tempo

## Ownership

| Resource | Owner | Source |
|----------|-------|--------|
| kube-prometheus-stack | Argo CD | `apps/monitoring.yaml` |
| Beyla | Argo CD | `apps/beyla.yaml` |
| datasources, dashboards, alerts | Argo CD | `platform/monitoring/` |
| Grafana admin password | External Secrets Operator | Infisical `INFRA_GRAFANA_ADMIN_PASSWORD` |
| Grafana OIDC client secret | External Secrets Operator | Infisical `INFRA_AUTHENTIK_GRAFANA_CLIENT_SECRET` |

The Grafana Deployment is annotated for Reloader. After a credential rotation
is synced into `monitoring/grafana-admin`, Reloader restarts Grafana so the new
environment value takes effect.

Grafana uses Authentik generic OAuth with the `grafana` client ID and the
callback `https://grafana.<domain>/login/generic_oauth`. `server.root_url` must
remain the public HTTPS URL, otherwise Grafana generates a `localhost:3000`
callback that Authentik rejects.

The home dashboard path is
`/tmp/dashboards/Homelab/homelab-overview.json`. Do not drop the `Homelab`
directory segment; the sidecar preserves `grafana_folder` in its file layout.

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
- `grafana-dashboard-demo-e2e`

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

## Service map troubleshooting

The Tempo datasource must link its service map to Prometheus:

```yaml
jsonData:
  serviceMap:
    datasourceUid: prometheus
```

The Tempo metrics-generator must enable both `service-graphs` and
`span-metrics`. Verify generated series:

```promql
traces_service_graph_request_total
traces_spanmetrics_calls_total
```

If the map is empty, generate traffic through the demo checkout action, then
check the Tempo logs for metrics-generator remote-write errors.
