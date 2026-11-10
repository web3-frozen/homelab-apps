# Runbook: End-to-end tracing POC

## Purpose

The demo proves one transaction can be followed from the browser through the
frontend, API, and PostgreSQL without instrumenting the Go backend source.

Questions the dashboard answers:

1. Is the browser-to-API request slow?
2. Is time spent in frontend proxying, the API, or PostgreSQL?
3. Which API route or SQL operation is responsible?
4. Which trace contains the complete request path?

## Architecture

- Browser: OpenTelemetry Web SDK plus fetch instrumentation
- Browser export: same-origin `POST /v1/traces`
- Frontend proxy: Nginx forwards OTLP to Tempo and forwards `traceparent`
- Kubernetes: Linkerd provides the proxy hop
- Backend: Beyla eBPF creates HTTP, SQL, and Redis spans without app changes
- Storage: Tempo for traces, Prometheus for RED/DB metrics, Loki for logs
- UI: Grafana dashboard `Demo App - End-to-End Observability`

## Annotation contract

Beyla only instruments Pods carrying:

```yaml
metadata:
  annotations:
    beyla.instrument: "true"
    resource.opentelemetry.io/service.name: example-service
    resource.opentelemetry.io/service.version: "1"
```

The current POC selects annotated Pods only. Other workloads are intentionally
not instrumented by Beyla to keep the demo signal focused and reduce overhead.

## Verify one trace

1. Open the demo app and create a task.
2. In browser network tools, verify `/api/tasks` has a W3C `traceparent` header.
3. Open Grafana Explore with the Tempo datasource.
4. Search:

```text
{ resource.service.name = "demo-api" }
```

The expected waterfall is:

```text
browser HTTP POST
  -> frontend Nginx / Linkerd
  -> demo-api POST /api/tasks
  -> PostgreSQL INSERT tasks
```

## Constraints

- Browser instrumentation cannot be injected by a Pod annotation. It needs a
  JavaScript bootstrap in the served application or edge HTML injection.
- eBPF SQL spans describe client-observed SQL operations. PostgreSQL internal
  query-plan, lock, and commit spans still require database monitoring such as
  `pg_stat_statements`, `auto_explain`, and CNPG metrics.
- The POC uses 100% sampling so a specific test transaction is visible. Reduce
  sampling after validation based on traffic and storage.
- Do not export traces back into the same proxy route in a way that traces the
  export request itself. The fetch instrumentation ignores `/v1/traces`.
