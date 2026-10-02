# CalixSentry Architecture

## Pipeline

```
Incoming Request
  -> Request Normalization      (pipeline.RequestNormalizer)
  -> Client Identification      (pipeline.ClientIdentifier)
  -> Denylist / Active Block check         -> immediate BLOCK
  -> Allowlist check                        -> bypasses rate limit + detection-driven actions
  -> Rate Analysis (mechanical, config-driven) -> immediate RATE_LIMIT (HTTP 429)
  -> Signature Detection  (detection.signature.*)
  -> Behavioral Analysis  (detection.behavioral.*)
  -> Threat Scoring        (scoring.ThreatScoringEngine)   - explainable, additive, 0-100
  -> Policy Evaluation     (policy.PolicyEngine)           - mode-driven, never decides alone
  -> Action: ALLOW forwards to backend; TEMPORARY_BLOCK short-circuits with 403
  -> Security Event / Metrics  (events.SecurityEventPublisher)
```

All of this is orchestrated by `gateway.WafGatewayFilter`, a single servlet `Filter`
registered with highest precedence (`gateway.GatewayFilterConfig`) so it runs before
Spring Security. It contains no detection or policy logic itself — it only calls
the single-responsibility collaborators above, which is what keeps the
Detection → Policy → Action separation real in the code, not just in prose.

## Why one Maven module instead of the original multi-module layout

The product brief suggested a multi-module tree (`calixsentry-engine`,
`calixsentry-gateway`, `calixsentry-detection`, ...). For the MVP this repo uses a
**single Spring Boot module** with the same boundaries expressed as Java packages
(`detection`, `policy`, `blocking`, `gateway`, ...) instead. Reasoning:

- A fresh multi-module Maven reactor adds real build-graph complexity (inter-module
  versions, `mvn install` ordering, more POM boilerplate) with no functional benefit
  until there's a second deployable artifact that actually needs to consume the
  engine as a library.
- Package boundaries already give the same "detectors don't know about policy,
  policy doesn't know about detectors' internals" discipline; splitting into
  modules later is a mechanical refactor, not a redesign, because the packages are
  already the future module boundaries.

**When to actually split it:** once there's a second deployable (e.g. a detached
edge proxy calling the engine as a decision service — see below), or once a
plugin/rule-pack ecosystem needs its own versioned artifact.

## Why the Gateway and Engine are one process for the MVP

The original brief describes a reverse-proxy Gateway (nginx-style, public 80/443)
calling out to a separate Java Engine/API on an internal port. This repo instead
runs a **single Java process** that is simultaneously the reverse proxy (via
`WafGatewayFilter`, using the JDK's `HttpClient` to forward to the backend) and the
detection/policy engine.

Trade-off, stated explicitly:
- **Pro:** one process to build, deploy, and reason about for the MVP; no
  extra network hop or serialization between gateway and engine; much simpler
  local dev (`docker compose up`, or one systemd unit in production).
  A Java servlet-based synchronous proxy is more than adequate for MVP traffic
  levels, and it avoids standing up nginx+Lua/njs (or an ext_authz sidecar)
  before there's a reason to.
- **Con:** this does not (yet) give you nginx/Envoy-grade connection handling,
  HTTP/2, or the ability to scale the edge independently of the detection engine.

**Future path (not implemented):** split into a dedicated edge proxy (nginx or
Envoy) that calls this engine as a decision service over the internal API — the
config keys `calixsentry.server.engine-port` / `engine-bind-address` already exist
reserved for exactly this, bound to `127.0.0.1` by default so the decision API is
never directly internet-reachable.

## Ports

- Public traffic: `calixsentry.server.port` (default `8080` in dev; production
  installer defaults to the same, override with `CALIXSENTRY_PORT`). Never
  hard-coded — read from `CalixSentryProperties.Server`.
- Management dashboard/API: same port, under `calixsentry.management.base-path`
  (default `/calixsentry`), protected by Basic Auth + RBAC.
- Reserved for a future detached engine: `calixsentry.server.engine-port`
  (default `9400`), bound to `127.0.0.1` — unused by the MVP, present so the
  config surface doesn't need a breaking change later.

## Data flow that matters for correctness

- `RequestNormalizer` decodes/canonicalizes a **copy** of the path used only for
  detection (handles double-encoding, Unicode tricks, redundant slashes). The
  **raw** URI is what's actually forwarded to the backend, so normalization can
  never change application behavior — only detection accuracy.
- `ProxyForwardingService` strips hop-by-hop headers per RFC 7230 §6.1 in both
  directions and never rewrites a legitimate backend status code. 502/504 are
  reserved exclusively for CalixSentry's own failure to reach/get a timely
  response from the backend.
- `ClientActivityTracker` keeps a rolling per-IP window (`detection.enumerationWindowSeconds`,
  default 5 minutes) used for unique-path count, 404/403/5xx ratios, and request
  cadence — the data behind endpoint-enumeration and rate-anomaly detection.
  MVP storage is in-memory, per-process; it does not survive a restart and does
  not share state across multiple gateway instances (see `docs/ROADMAP.md`).

## Security foundations

- Admin credentials are never hard-coded: read from `CALIXSENTRY_ADMIN_PASSWORD`
  if set, otherwise a random password is generated at first boot, logged once,
  and written to a root-readable-only file (`config.SecurityConfig`).
- Request bodies are capped (`calixsentry.backend.max-request-bytes`, default
  10MB) before any inspection or forwarding — a resource-exhaustion guard.
- Regex-based detectors deliberately avoid nested-quantifier patterns that are
  prone to catastrophic backtracking (ReDoS), and the inspection surface itself
  is size-capped upstream.
- `X-Forwarded-For` is only trusted from IPs in `calixsentry.management.trusted-proxy-ips`
  — otherwise it's client-controllable and would let an attacker spoof past
  IP-based blocking.


## Update: dedicated management port, daily logs, per-IP activity (this revision)

**Two ports, not one.** The public gateway port (`calixsentry.server.port`, default 8080 in
dev, 80/443 in production) is a pure reverse proxy - it inspects and forwards traffic, and
that is ALL it does. The dashboard, REST API, and Actuator now live exclusively on a second
port (`calixsentry.server.management-port`, default **9400**), opened as a second embedded
Tomcat connector (`config.ManagementConnectorConfig`) bound to `127.0.0.1` by default
(`calixsentry.server.management-bind-address`). Requesting `/calixsentry/...` on the PUBLIC
port is treated as ordinary application traffic (forwarded to your backend, which will
usually 404 it) rather than reaching the admin surface - the dashboard is simply not present
on the port the internet can see. `ManagementRouting` and the top of `WafGatewayFilter`
implement this split; set `management-port: 0` to fall back to the old single-port behaviour.

**Daily, date-named log files** (`logs.DailyLogService`): `calixsentry-events-YYYY-MM-DD.jsonl`
and, when `events.access-log-enabled=true`, `calixsentry-access-YYYY-MM-DD.jsonl` covering
EVERY proxied request, not only the ones that triggered a detection. A new file starts
automatically at midnight in the configured `events.timezone`; files older than
`events.retention-days` / `events.access-log-retention-days` are deleted on a schedule. The
`{basePath}/api/history/...` endpoints (`api.HistoryController`) search a given day's file
by streaming it line-by-line (bounded memory even for a huge day) and can also return the
raw file for download.

**Per-IP activity** (`activity.IpActivityStore`, fed by `activity.AccessRecorder`): a live,
bounded-memory picture of every request each client IP made - not just the ones that
triggered a detection - so "what did this IP actually check?" has a direct answer via
`{basePath}/api/ips/{ip}`. This is intentionally a SEPARATE structure from
`detection.behavioral.ClientActivityTracker`: the tracker is detection input, tuned to the
enumeration-detection window and thresholds; the activity store is an operator-facing
investigation view, with its own size/retention limits (`events.ip-tracker-max-ips`,
`events.ip-trail-per-ip`, `events.ip-retention-hours`). Both are in-memory only - the daily
access log is where longer-term per-IP history actually lives.
