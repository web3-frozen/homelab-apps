# Runbook: End-to-end tracing POC

## Purpose

The demo proves one transaction can be followed from the browser through the
frontend, API, inventory, pricing, PostgreSQL, Redis, and an external quote
provider without adding tracing SDKs to the Go services.

Questions the dashboard answers:

1. Is the browser-to-API request slow?
2. Is time spent in frontend proxying, the API, inventory, pricing, PostgreSQL,
   Redis, or the external quote provider?
3. Which service edge or database operation caused the slow request?
4. Which trace contains the complete request path?

## Architecture

- Browser: OpenTelemetry Web SDK plus fetch instrumentation
- Browser export: same-origin `POST /v1/traces`
- Frontend proxy: Nginx forwards OTLP to Tempo and forwards `traceparent`
- Kubernetes: Linkerd provides the proxy hop
- Services: Beyla eBPF creates HTTP, SQL, Redis, and external-call spans
- Normalization: the OTel Collector maps `db.system.name` to the legacy
  `db.system` key used by Tempo 2.9 service graphs, and adds `peer.service`
  from `server.address` for uninstrumented HTTP dependencies
- Linkerd compatibility: Beyla excludes the `linkerd-proxy` container from
  discovery. Instrumenting both the application and its sidecar creates
  duplicate client spans with the same span ID, which Tempo then mis-pairs into
  self-edges and missing service-graph edges.
- Checkout: `demo-api -> demo-inventory -> demo-pricing`
- State: inventory persists reservations in PostgreSQL and caches status in Redis
- Third party: pricing calls a market-data HTTP API with a bounded timeout
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

1. Open the demo app and run **Checkout**.
2. In browser network tools, verify `/api/checkout` has a W3C `traceparent` header.
3. Open Grafana Explore with the Tempo datasource.
4. Search:

```text
{ resource.service.name = "demo-api" }
```

The expected waterfall is:

```text
browser HTTP POST
  -> frontend Nginx
  -> demo-api POST /api/checkout
  -> demo-inventory POST /reserve
  -> demo-pricing GET /quote
  -> external market-data GET /
  -> PostgreSQL INSERT checkout_reservations
  -> Redis SET checkout:<id>
```

The Collector is required for dependency edges. Beyla emits semantic-convention
keys such as `db.system.name` and `server.address`; Tempo 2.9 still looks for the
older `db.system` and `peer.service` keys when generating service graphs.

## Service map

Open **Grafana -> Explore -> Tempo -> Service Graph**. The graph is generated
from the same spans and shows request rate, error rate, and request duration for
each upstream/downstream edge. Select an edge to inspect the corresponding
traces. The `Demo App - End-to-End Observability` dashboard links directly to
the filtered Explore view.

## Constraints

- Browser instrumentation cannot be injected by a Pod annotation. It needs a
  JavaScript bootstrap in the served application or edge HTML injection.
- eBPF SQL spans describe client-observed SQL operations. PostgreSQL internal
  query-plan, lock, and commit spans still require database monitoring such as
  `pg_stat_statements`, `auto_explain`, and CNPG metrics.
- The POC uses 100% sampling so a specific test transaction is visible. Reduce
  sampling after validation based on traffic and storage.
- The external quote provider is a real dependency. The pricing service uses a
  short timeout and falls back to a deterministic rate so a provider outage does
  not break the checkout demo.
- Do not export traces back into the same proxy route in a way that traces the
  export request itself. The fetch instrumentation ignores `/v1/traces`.
- Do not remove the `linkerd-proxy` exclusion from Beyla discovery while Linkerd
  injection is enabled on the demo namespace. Keep mTLS at the mesh layer and
  let Beyla instrument only the application containers.
