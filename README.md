# CalixSentry

A self-hosted, behavior-aware reverse-proxy Web Application Firewall.
Java 21 + Spring Boot 3. MVP stage — see `docs/ROADMAP.md` for what's real vs. planned.

CalixSentry separates **Detection → Evidence → Threat Assessment → Policy Decision → Action**.
A detection finding is never, by itself, a block — the Policy Engine decides what happens,
governed by an explicit **Protection Mode**, and it ships in `MONITOR` mode (detect + record
only, never blocks) with automatic blocking **off** by default.

## What's actually implemented (MVP)

- Reverse-proxy gateway (Java, embedded Tomcat) forwarding to your backend, preserving
  real backend status codes (a 404 stays a 404, never mistranslated to 502)
- Signature detectors: SQL injection, XSS, path traversal, command injection,
  sensitive-path access, known scanner User-Agents
- **Behavioral endpoint-enumeration detection** — recognizes automated scanning
  (many unique paths, high 404 ratio, sensitive-path hits, burst cadence) even when
  each individual request looks harmless, while requiring multiple independent
  signals and a minimum sample size to avoid false-positiving on ordinary 404s
- Configurable, explainable 0–100 threat scoring with reasons attached to every event
- Protection modes: MONITOR / ALERT / MANUAL / AUTOMATIC (automatic blocking requires
  an explicit opt-in, never enabled silently)
- Temporary blocks (auto-expiring, file-persisted across restarts) and permanent blocks
- IP/CIDR allowlist & denylist, with a preview/test endpoint before applying a rule
- Token-bucket rate limiting, independent of protection mode
- Structured security events (JSON), file sink + optional webhook sink
- Basic Auth management API/dashboard with an ADMIN/ANALYST/VIEWER RBAC foundation
- `/health` endpoint, Micrometer counters, Actuator
- A working (if intentionally simple) live dashboard at `/calixsentry/`

## What's explicitly NOT implemented yet

Labeled `NOT IMPLEMENTED` / `FUTURE FEATURE` in the code and `docs/ROADMAP.md`:
Elasticsearch/Kibana shipping, GeoIP/ASN/threat-intel enrichment, distributed/multi-node
deployment, Windows/macOS native installers, `calixsentry update`, full user-management UI,
WebSocket/SSE live event streaming (dashboard currently polls).

## Two ports, not one

The public gateway (what your visitors hit) and the management dashboard/API are on
**separate ports** by default:

| Purpose | Port | Bind address | Configure with |
|---|---|---|---|
| Public gateway (proxied traffic) | `8080` (dev) / `80`,`443` (prod) | `0.0.0.0` | `CALIXSENTRY_PORT` |
| Dashboard + API + Actuator | `9400` | `127.0.0.1` (loopback only) | `CALIXSENTRY_MANAGEMENT_PORT`, `CALIXSENTRY_MANAGEMENT_BIND` |

Requesting `/calixsentry/...` on the public port does **not** reach the dashboard - it's
treated as ordinary application traffic. See `docs/ARCHITECTURE.md` for why, and set
`calixsentry.server.management-port: 0` if you want the old single-port behaviour instead.

## Quickstart (Docker, for development)

```bash
docker compose up --build
```

Then:
- Proxied traffic: http://localhost:8080/
- Dashboard: http://localhost:9400/calixsentry/ (user `admin`; the generated password is
  printed in the container logs on first boot, or: `docker compose exec calixsentry-engine cat /data/calixsentry/initial-admin-password.txt`)

See `docs/TESTING.md` for exact commands (PowerShell + curl) to exercise every detector.

## Installing for production

Three real options today - see `docs/PACKAGING.md` for the full picture (including what's
**not** built yet, like package-manager repos and native Windows/macOS installers):

**1. Archive download (closest to how Elasticsearch ships):**
```bash
installer/package-release.sh          # builds calixsentry-<version>-linux-x64.tar.gz
tar xzf dist/calixsentry-*-linux-x64.tar.gz && cd calixsentry-*
CALIXSENTRY_BACKEND_URL=http://localhost:3000 ./bin/calixsentry-engine
```

**2. Native Linux service (systemd), the recommended way to actually run it long-term:**
```bash
sudo bash installer/install.sh
```
Installs as a systemd service, generates a bootstrap admin password, checks both ports are
free, prompts for the backend URL (your app - localhost, an internal IP, or a domain name),
and starts in the safe `MONITOR` mode.

**3. Docker**, same image as development - see above.

See `docs/ARCHITECTURE.md` for why the gateway and engine are one process in this MVP, and
the future path to split them.

## Configuring what CalixSentry protects

`CALIXSENTRY_BACKEND_URL` (or `calixsentry.backend.base-url` in `application.yml`) is the
one setting that matters here - it accepts any reachable HTTP(S) target:
```
http://localhost:3000                        an app on this same machine
http://10.20.30.40:8080                       an app on another server, by IP
http://internal-app.mycompany.local:8080      an internal hostname
https://app-origin.example.com                a cloud-hosted origin, by domain name
```
`installer/install.sh` prompts for this interactively if you don't set it beforehand.

## Project layout

```
calixsentry/
├── pom.xml                      # single Maven module for the MVP (see docs/ARCHITECTURE.md)
├── src/main/java/com/calixsentry/
│   ├── config/                  # typed configuration + Spring Security
│   ├── pipeline/                # request normalization, client identification
│   ├── detection/                # detector interfaces + signature/ and behavioral/ detectors
│   ├── scoring/                  # threat scoring engine
│   ├── policy/                   # protection modes, policy engine
│   ├── blocking/                 # temporary/permanent IP blocking
│   ├── accesslist/                # allowlist/denylist
│   ├── ratelimit/                 # token-bucket rate limiter
│   ├── events/                    # security event model, publisher, sinks
│   ├── gateway/                   # the actual reverse-proxy filter
│   └── api/                       # management REST API
├── src/main/resources/
│   ├── application.yml            # SAFE DEFAULTS: MONITOR mode, automatic blocking OFF
│   └── static/calixsentry/        # dashboard
├── src/test/java/...               # unit + integration tests
├── docker/, docker-compose.yml, Dockerfile   # dev environment
├── installer/                      # production systemd installer + CLI
└── docs/
```
