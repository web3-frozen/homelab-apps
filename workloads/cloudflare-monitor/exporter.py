#!/usr/bin/env python3
"""Expose Cloudflare Workers/D1/R2 free-tier usage as Prometheus metrics.

Only the Python standard library is used, so the exporter can run from a
ConfigMap in a stock python:3.12-slim image.  It refreshes a cached snapshot
on a timer and serves it from /metrics; Prometheus scraping never hits the
Cloudflare API directly.

Free-tier limits (verified 2026-11-25):
  Workers Free : 100,000 requests/day, 100 Workers
  D1 Free      : 5,000,000 rows read/day, 100,000 rows written/day,
                 5 GB total storage, 10 databases, 500 MB per database
  R2 Free      : 10 GB-month storage, 1M Class A ops/month,
                 10M Class B ops/month

All storage figures are decimal (Cloudflare bills GB, not GiB).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

API = "https://api.cloudflare.com/client/v4"
ACCOUNT = os.environ.get("CF_ACCOUNT_ID", "").strip()
TOKEN = os.environ.get("CF_API_TOKEN", "").strip()
PORT = int(os.environ.get("PORT", "9103"))
REFRESH = max(60, int(os.environ.get("REFRESH_SECONDS", "300")))

LOG = logging.getLogger("cloudflare-quota-exporter")

# quota name -> (limit, period, unit)
QUOTAS: dict[str, tuple[float, str, str]] = {
    "workers_requests_daily": (100_000, "daily", "requests"),
    "workers_scripts": (100, "current", "scripts"),
    "d1_rows_read_daily": (5_000_000, "daily", "rows"),
    "d1_rows_written_daily": (100_000, "daily", "rows"),
    "d1_storage_bytes": (5_000_000_000, "current", "bytes"),
    "d1_databases": (10, "current", "databases"),
    "d1_database_size_bytes": (500_000_000, "current", "bytes"),
    "r2_storage_bytes": (10_000_000_000, "current", "bytes"),
    "r2_class_a_operations_monthly": (1_000_000, "monthly", "operations"),
    "r2_class_b_operations_monthly": (10_000_000, "monthly", "operations"),
}

# R2 operation classes, from https://developers.cloudflare.com/r2/pricing/
R2_CLASS_A = {
    "ListBuckets",
    "PutBucket",
    "ListObjects",
    "PutObject",
    "CopyObject",
    "CompleteMultipartUpload",
    "CreateMultipartUpload",
    "LifecycleStorageTierTransition",
    "ListMultipartUploads",
    "UploadPart",
    "UploadPartCopy",
    "ListParts",
    "PutBucketEncryption",
    "PutBucketCors",
    "PutBucketLifecycleConfiguration",
}
R2_CLASS_B = {
    "HeadBucket",
    "HeadObject",
    "GetObject",
    "UsageSummary",
    "GetBucketEncryption",
    "GetBucketLocation",
    "GetBucketCors",
    "GetBucketLifecycleConfiguration",
}
R2_FREE = {"DeleteObject", "DeleteBucket", "AbortMultipartUpload"}

WORKERS_QUERY = """
query($account: String!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: {accountTag: $account}) {
      workersInvocationsAdaptive(
        limit: 10000
        filter: {date_geq: $start, date_leq: $end}
      ) {
        sum { requests errors }
        dimensions { scriptName date }
      }
    }
  }
}
"""

D1_ANALYTICS_QUERY = """
query($account: String!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: {accountTag: $account}) {
      d1AnalyticsAdaptiveGroups(
        limit: 10000
        filter: {date_geq: $start, date_leq: $end}
      ) {
        sum { rowsRead rowsWritten }
        dimensions { databaseId date }
      }
    }
  }
}
"""

D1_STORAGE_QUERY = """
query($account: String!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: {accountTag: $account}) {
      d1StorageAdaptiveGroups(
        limit: 10000
        filter: {date_geq: $start, date_leq: $end}
      ) {
        max { databaseSizeBytes }
        dimensions { databaseId date }
      }
    }
  }
}
"""

R2_OPERATIONS_QUERY = """
query($account: String!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: {accountTag: $account}) {
      r2OperationsAdaptiveGroups(
        limit: 10000
        filter: {date_geq: $start, date_leq: $end}
      ) {
        sum { requests }
        dimensions { actionType bucketName date }
      }
    }
  }
}
"""

R2_STORAGE_QUERY = """
query($account: String!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: {accountTag: $account}) {
      r2StorageAdaptiveGroups(
        limit: 10000
        filter: {date_geq: $start, date_leq: $end}
      ) {
        max { objectCount payloadSize metadataSize }
        dimensions { bucketName date }
      }
    }
  }
}
"""


class State:
    """Last successful metric lines plus scrape health."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.lines: list[str] = []
        self.ok = False
        self.last_success = 0.0
        self.last_attempt = 0.0
        self.duration = 0.0
        self.error = ""

    def snapshot(self) -> tuple[list[str], bool, float, float, float, str]:
        with self.lock:
            return (
                list(self.lines),
                self.ok,
                self.last_success,
                self.last_attempt,
                self.duration,
                self.error,
            )

    def success(self, lines: list[str], duration: float) -> None:
        now = time.time()
        with self.lock:
            self.lines = lines
            self.ok = True
            self.last_success = now
            self.last_attempt = now
            self.duration = duration
            self.error = ""

    def failure(self, error: str, duration: float) -> None:
        with self.lock:
            self.ok = False
            self.last_attempt = time.time()
            self.duration = duration
            self.error = error


STATE = State()
STOP = threading.Event()


def _http_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: int = 30,
) -> Any:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        raise RuntimeError(f"HTTP {exc.code} from {url}: {detail}") from exc
    if isinstance(payload, dict) and payload.get("success") is False:
        raise RuntimeError(f"Cloudflare API error: {payload.get('errors')}")
    return payload


def rest(path: str) -> Any:
    return _http_json(f"{API}{path}").get("result")


def graphql(query: str, start: str, end: str) -> dict[str, Any]:
    payload = _http_json(
        f"{API}/graphql",
        method="POST",
        body={
            "query": query,
            "variables": {"account": ACCOUNT, "start": start, "end": end},
        },
    )
    if payload.get("errors"):
        raise RuntimeError(f"GraphQL errors: {payload['errors']}")
    accounts = (
        (payload.get("data") or {})
        .get("viewer", {})
        .get("accounts", [])
    )
    if not accounts:
        raise RuntimeError("GraphQL returned no accounts")
    return accounts[0]


def escape(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def metric(name: str, labels: dict[str, Any], value: float | int) -> str:
    if labels:
        rendered = ",".join(
            f'{key}="{escape(val)}"' for key, val in sorted(labels.items())
        )
        return f"{name}{{{rendered}}} {value}"
    return f"{name} {value}"


def latest_by_key(
    rows: list[dict[str, Any]], key: str, date_key: str = "date"
) -> dict[str, dict[str, Any]]:
    """Keep the row with the newest date for each value of key."""
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        dimensions = row.get("dimensions") or {}
        item_key = str(dimensions.get(key, ""))
        if not item_key:
            continue
        date = str(dimensions.get(date_key, ""))
        current = out.get(item_key)
        if current is None or date >= str(
            (current.get("dimensions") or {}).get(date_key, "")
        ):
            out[item_key] = row
    return out


def collect() -> list[str]:
    if not ACCOUNT or not TOKEN:
        raise RuntimeError("CF_ACCOUNT_ID and CF_API_TOKEN are required")

    now = datetime.now(timezone.utc)
    today = now.date()
    yesterday = today - timedelta(days=1)
    month_start = today.replace(day=1)

    d1_databases = rest(f"/accounts/{ACCOUNT}/d1/database") or []
    db_names = {
        str(item.get("uuid", "")): str(item.get("name") or item.get("uuid", ""))
        for item in d1_databases
        if item.get("uuid")
    }
    workers_scripts = rest(f"/accounts/{ACCOUNT}/workers/scripts") or []

    workers = graphql(WORKERS_QUERY, today.isoformat(), today.isoformat())
    d1_analytics = graphql(
        D1_ANALYTICS_QUERY, today.isoformat(), today.isoformat()
    )
    d1_storage_rows = graphql(
        D1_STORAGE_QUERY, yesterday.isoformat(), today.isoformat()
    )
    r2_ops = graphql(
        R2_OPERATIONS_QUERY, month_start.isoformat(), today.isoformat()
    )
    r2_storage_rows = graphql(
        R2_STORAGE_QUERY, yesterday.isoformat(), today.isoformat()
    )

    lines: list[str] = []
    usage: dict[str, float] = {}

    # --- Workers -----------------------------------------------------------
    worker_requests: dict[str, int] = {}
    worker_errors: dict[str, int] = {}
    for row in workers.get("workersInvocationsAdaptive") or []:
        script = str((row.get("dimensions") or {}).get("scriptName", ""))
        if not script:
            continue
        total = row.get("sum") or {}
        worker_requests[script] = worker_requests.get(script, 0) + int(
            total.get("requests") or 0
        )
        worker_errors[script] = worker_errors.get(script, 0) + int(
            total.get("errors") or 0
        )

    usage["workers_requests_daily"] = float(sum(worker_requests.values()))
    usage["workers_scripts"] = float(len(workers_scripts))

    # --- D1 ----------------------------------------------------------------
    d1_reads: dict[str, int] = {}
    d1_writes: dict[str, int] = {}
    for row in d1_analytics.get("d1AnalyticsAdaptiveGroups") or []:
        database_id = str((row.get("dimensions") or {}).get("databaseId", ""))
        if not database_id:
            continue
        total = row.get("sum") or {}
        d1_reads[database_id] = d1_reads.get(database_id, 0) + int(
            total.get("rowsRead") or 0
        )
        d1_writes[database_id] = d1_writes.get(database_id, 0) + int(
            total.get("rowsWritten") or 0
        )

    d1_sizes: dict[str, int] = {}
    for database_id, row in latest_by_key(
        d1_storage_rows.get("d1StorageAdaptiveGroups") or [], "databaseId"
    ).items():
        d1_sizes[database_id] = int(
            ((row.get("max") or {}).get("databaseSizeBytes") or 0)
        )

    usage["d1_rows_read_daily"] = float(sum(d1_reads.values()))
    usage["d1_rows_written_daily"] = float(sum(d1_writes.values()))
    usage["d1_storage_bytes"] = float(sum(d1_sizes.values()))
    usage["d1_databases"] = float(len(d1_databases))
    usage["d1_database_size_bytes"] = float(max(d1_sizes.values(), default=0))

    # --- R2 ----------------------------------------------------------------
    r2_storage: dict[str, int] = {}
    for bucket, row in latest_by_key(
        r2_storage_rows.get("r2StorageAdaptiveGroups") or [], "bucketName"
    ).items():
        maximum = row.get("max") or {}
        r2_storage[bucket] = int(maximum.get("payloadSize") or 0) + int(
            maximum.get("metadataSize") or 0
        )

    r2_classes: dict[str, dict[str, int]] = {}
    for row in r2_ops.get("r2OperationsAdaptiveGroups") or []:
        dimensions = row.get("dimensions") or {}
        action = str(dimensions.get("actionType", ""))
        # ListBuckets has no bucketName; keep it in the account-wide quota
        # and expose it under the synthetic "account" bucket.
        bucket = str(dimensions.get("bucketName") or "account")
        if not action:
            continue
        if action in R2_CLASS_A:
            klass = "A"
        elif action in R2_CLASS_B:
            klass = "B"
        elif action in R2_FREE:
            klass = "free"
        else:
            klass = "unknown"
        requests = int((row.get("sum") or {}).get("requests") or 0)
        bucket_classes = r2_classes.setdefault(bucket, {})
        bucket_classes[klass] = bucket_classes.get(klass, 0) + requests

    class_a = sum(bucket.get("A", 0) for bucket in r2_classes.values())
    class_b = sum(bucket.get("B", 0) for bucket in r2_classes.values())

    usage["r2_storage_bytes"] = float(sum(r2_storage.values()))
    usage["r2_class_a_operations_monthly"] = float(class_a)
    usage["r2_class_b_operations_monthly"] = float(class_b)

    # --- Quota usage/limit/ratio ------------------------------------------
    lines.append(
        "# HELP cloudflare_free_tier_usage Current usage for a Cloudflare free-tier quota (UTC day/calendar month to date)."
    )
    lines.append("# TYPE cloudflare_free_tier_usage gauge")
    for quota, (limit, period, unit) in sorted(QUOTAS.items()):
        value = usage.get(quota, 0.0)
        labels = {"quota": quota, "period": period, "unit": unit}
        lines.append(metric("cloudflare_free_tier_usage", labels, value))

    lines.append(
        "# HELP cloudflare_free_tier_limit Free-tier limit for the quota."
    )
    lines.append("# TYPE cloudflare_free_tier_limit gauge")
    for quota, (limit, period, unit) in sorted(QUOTAS.items()):
        labels = {"quota": quota, "period": period, "unit": unit}
        lines.append(metric("cloudflare_free_tier_limit", labels, limit))

    lines.append(
        "# HELP cloudflare_free_tier_usage_ratio usage / limit (0-1)."
    )
    lines.append("# TYPE cloudflare_free_tier_usage_ratio gauge")
    for quota, (limit, period, _unit) in sorted(QUOTAS.items()):
        value = usage.get(quota, 0.0)
        ratio = (value / limit) if limit else 0.0
        lines.append(
            metric(
                "cloudflare_free_tier_usage_ratio",
                {"quota": quota, "period": period},
                f"{ratio:.9f}",
            )
        )

    # --- Breakdowns for dashboards ----------------------------------------
    lines.append(
        "# HELP cloudflare_workers_requests_daily Requests per Worker (UTC day)."
    )
    lines.append("# TYPE cloudflare_workers_requests_daily gauge")
    for script, value in sorted(worker_requests.items()):
        lines.append(
            metric("cloudflare_workers_requests_daily", {"script": script}, value)
        )

    lines.append(
        "# HELP cloudflare_workers_errors_daily Errors per Worker (UTC day)."
    )
    lines.append("# TYPE cloudflare_workers_errors_daily gauge")
    for script, value in sorted(worker_errors.items()):
        lines.append(
            metric("cloudflare_workers_errors_daily", {"script": script}, value)
        )

    lines.append(
        "# HELP cloudflare_d1_rows_read_daily Rows read per D1 database (UTC day)."
    )
    lines.append("# TYPE cloudflare_d1_rows_read_daily gauge")
    for database_id, value in sorted(d1_reads.items()):
        name = db_names.get(database_id, database_id)
        lines.append(
            metric("cloudflare_d1_rows_read_daily", {"database": name}, value)
        )

    lines.append(
        "# HELP cloudflare_d1_rows_written_daily Rows written per D1 database (UTC day)."
    )
    lines.append("# TYPE cloudflare_d1_rows_written_daily gauge")
    for database_id, value in sorted(d1_writes.items()):
        name = db_names.get(database_id, database_id)
        lines.append(
            metric("cloudflare_d1_rows_written_daily", {"database": name}, value)
        )

    lines.append(
        "# HELP cloudflare_d1_storage_bytes Stored bytes per D1 database."
    )
    lines.append("# TYPE cloudflare_d1_storage_bytes gauge")
    for database_id, value in sorted(d1_sizes.items()):
        name = db_names.get(database_id, database_id)
        lines.append(
            metric("cloudflare_d1_storage_bytes", {"database": name}, value)
        )

    lines.append(
        "# HELP cloudflare_r2_storage_bytes Stored bytes per R2 bucket."
    )
    lines.append("# TYPE cloudflare_r2_storage_bytes gauge")
    for bucket, value in sorted(r2_storage.items()):
        lines.append(
            metric("cloudflare_r2_storage_bytes", {"bucket": bucket}, value)
        )

    lines.append(
        "# HELP cloudflare_r2_operations_monthly R2 operations by bucket and class (calendar month to date)."
    )
    lines.append("# TYPE cloudflare_r2_operations_monthly gauge")
    for bucket, classes in sorted(r2_classes.items()):
        for klass, value in sorted(classes.items()):
            lines.append(
                metric(
                    "cloudflare_r2_operations_monthly",
                    {"bucket": bucket, "class": klass},
                    value,
                )
            )

    return lines


def refresh_loop() -> None:
    while not STOP.is_set():
        started = time.monotonic()
        try:
            lines = collect()
            elapsed = time.monotonic() - started
            STATE.success(lines, elapsed)
            LOG.info("scrape ok in %.2fs (%d metric lines)", elapsed, len(lines))
        except Exception as exc:  # noqa: BLE001 - exporter must keep serving
            elapsed = time.monotonic() - started
            STATE.failure(str(exc), elapsed)
            LOG.error("scrape failed in %.2fs: %s", elapsed, exc)
        STOP.wait(max(30, REFRESH - (time.monotonic() - started)))


class Handler(BaseHTTPRequestHandler):
    server_version = "cloudflare-quota-exporter/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.debug("%s - %s", self.address_string(), fmt % args)

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path in ("/healthz", "/"):
            self._send(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if self.path == "/readyz":
            _, ok, last_success, _, _, _ = STATE.snapshot()
            fresh = last_success > 0 and (time.time() - last_success) < REFRESH * 3
            if ok and fresh:
                self._send(200, b"ok\n", "text/plain; charset=utf-8")
            else:
                self._send(503, b"not ready\n", "text/plain; charset=utf-8")
            return
        if self.path == "/metrics":
            lines, ok, last_success, last_attempt, duration, error = STATE.snapshot()
            out = list(lines)
            out.append(
                "# HELP cloudflare_free_tier_scrape_success 1 if the last Cloudflare API scrape succeeded."
            )
            out.append("# TYPE cloudflare_free_tier_scrape_success gauge")
            out.append(
                metric(
                    "cloudflare_free_tier_scrape_success",
                    {},
                    1 if ok else 0,
                )
            )
            out.append(
                "# HELP cloudflare_free_tier_last_scrape_timestamp_seconds Unix timestamp of the last successful scrape."
            )
            out.append(
                "# TYPE cloudflare_free_tier_last_scrape_timestamp_seconds gauge"
            )
            out.append(
                metric(
                    "cloudflare_free_tier_last_scrape_timestamp_seconds",
                    {},
                    f"{last_success:.0f}",
                )
            )
            out.append(
                "# HELP cloudflare_free_tier_scrape_duration_seconds Duration of the last scrape attempt."
            )
            out.append(
                "# TYPE cloudflare_free_tier_scrape_duration_seconds gauge"
            )
            out.append(
                metric(
                    "cloudflare_free_tier_scrape_duration_seconds",
                    {},
                    f"{duration:.3f}",
                )
            )
            self._send(
                200,
                ("\n".join(out) + "\n").encode(),
                "text/plain; version=0.0.4; charset=utf-8",
            )
            return
        self._send(404, b"not found\n", "text/plain; charset=utf-8")


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if not ACCOUNT or not TOKEN:
        raise SystemExit("CF_ACCOUNT_ID and CF_API_TOKEN must be set")

    server = ThreadingHTTPServer(("", PORT), Handler)

    def stop(_signum: int, _frame: Any) -> None:
        STOP.set()
        # shutdown() blocks until serve_forever() returns, so run it in a
        # helper thread instead of the signal handler.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    threading.Thread(target=refresh_loop, name="refresh", daemon=True).start()
    LOG.info("listening on :%d, refreshing every %ds", PORT, REFRESH)
    server.serve_forever(poll_interval=0.5)
    STOP.set()
    server.server_close()


if __name__ == "__main__":
    main()
