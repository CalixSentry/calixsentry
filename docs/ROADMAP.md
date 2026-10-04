# Roadmap / Honest Status

Per spec section 35: anything not actually implemented is labeled here and in
code comments as `NOT IMPLEMENTED` or `FUTURE FEATURE` — never silently faked.

## Implemented in this MVP
- Detection/Policy/Action separation; MONITOR/ALERT/MANUAL/AUTOMATIC modes
- Signature detectors (SQLi, XSS, path traversal, command injection, sensitive
  paths, scanner User-Agents) + behavioral endpoint-enumeration and rate-anomaly
  detection
- Explainable threat scoring, configurable weights and severity bands
- Temporary (auto-expiring, file-persisted) and permanent IP blocks
- IP/CIDR allowlist & denylist with a preview/test endpoint
- Token-bucket rate limiting
- Structured security events; file + webhook sinks
- Basic Auth + ADMIN/ANALYST/VIEWER RBAC foundation
- Reverse-proxy gateway preserving real backend status codes
- Basic polling dashboard, REST management API, CLI, Linux systemd installer

## NOT IMPLEMENTED (explicit stubs exist, do not enable and expect data)
- **Elasticsearch/Kibana sink** — `events.sinks.ElasticsearchEventSink` is a
  no-op by design; `elasticsearch.enabled=true` does nothing yet.
- **`calixsentry update`** — CLI prints a clear "not implemented" message.
- **Windows Server / macOS native installers** — Linux x86_64/arm64 only.
- **Multi-node / shared state** — `ClientActivityTracker` and rate-limit buckets
  are in-memory per process; a second gateway instance does not share behavioral
  history or blocks (blocks ARE file-persisted per node, but not synced between
  nodes).
- **WebSocket/SSE live events** — dashboard polls every 5s.
- **Full user management** — SecurityConfig is 1 generated admin + optional
  env-var analyst/viewer; no add/remove-user UI, no MFA, no password rotation.

## Planned (extension points already exist, per spec section 30)
GeoIP / ASN / IP reputation, TLS and browser fingerprinting, threat-intelligence
feeds, machine-learning scoring, distributed deployment with central management,
multi-tenant support, Kubernetes packaging, Prometheus/OpenTelemetry export
(Micrometer counters already exist as the seam), Slack/Teams/email alert sinks
(the `EventSink` interface is the seam), SIEM integrations beyond Elasticsearch.

## Incorporated from external review (this revision)
- `RateAnomalyDetector`'s "very high request rate" threshold moved out of hard-coded Java
  into `calixsentry.detection.very-high-requests-per-second-threshold` (was fixed at 5 req/s).
- Management dashboard/API split onto its own port, bound to loopback by default (see
  ARCHITECTURE.md) - reduces exposure regardless of the CSRF/Basic-Auth caveat below.
- Added a Content-Security-Policy header on the management port as defence-in-depth for the
  dashboard (script-src/style-src 'self' only, no inline).

## Explicitly NOT done this revision (real work, not a quick fix - stays honest here)
- **Content-type-aware body inspection.** Request bodies are still inspected as a flat UTF-8
  text preview, not parsed per `Content-Type` (JSON, form-encoded, multipart, XML). A payload
  nested inside valid JSON is still visible to the text-pattern detectors today, but a
  purpose-built JSON/form-aware inspector would catch more and false-positive less. This is a
  genuine multi-day effort (safe parsing per content type, size limits per part, decompression
  handling) - it is not something to bolt on without care, so it stays a roadmap item rather
  than a rushed addition.
- **Session/token-based management auth in place of Basic Auth.** Basic Auth over the
  loopback-only management port is a reasonable MVP posture, but a real login/session model
  (or short-lived tokens) is the more correct long-term answer, particularly once the
  dashboard might ever be exposed beyond `127.0.0.1`. Not changed this revision - re-architecting
  auth deserves its own focused pass, not a bolt-on under time pressure.
- **OWASP Core Rule Set (or equivalent) as a rule engine.** The current signature detectors are
  hand-written patterns for common cases, explicitly not a claim of comprehensive coverage
  (see each detector's own Javadoc). Adopting or porting an established ruleset is a real
  option for later but is a significant undertaking in its own right.

## Known MVP limitations worth planning around
- Request body inspection is capped and text-decoded as UTF-8; binary/multipart
  uploads are not deeply inspected.
- Redirects from the backend are passed through as-is (`HttpClient.Redirect.NEVER`
  at the proxy layer — the *client* follows them, CalixSentry does not silently
  rewrite Location headers).
- No WAF-level TLS termination yet; terminate TLS in front of CalixSentry (e.g.
  a load balancer) for production HTTPS, or extend `application.yml`'s embedded
  Tomcat SSL properties directly.
