# Testing CalixSentry (Windows / PowerShell + Docker Desktop)

## 1. Build and start

```powershell
docker compose up --build
```

Wait for `calixsentry-engine` to report healthy (`docker compose ps`), then grab the
generated admin password:

```powershell
docker compose exec calixsentry-engine cat /data/calixsentry/initial-admin-password.txt
```

## 2. Run the automated tests

```powershell
mvn -q test
```

(Requires Maven + a Java 21 JDK on the machine you run this from — or run inside the
build stage of the Dockerfile, which does this automatically via `docker compose build`.)

## 3. Normal traffic -> ALLOW

```powershell
curl.exe -i http://localhost:8080/
```

Expect: `200 OK`, "CalixSentry Test Application" HTML.

## 4. 404 stays 404 (never 502)

```powershell
curl.exe -i http://localhost:8080/does-not-exist
```

Expect: `404 Not Found` — NOT `502`.

## 5. SQL injection

```powershell
curl.exe -i "http://localhost:8080/?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users"
```

In default MONITOR mode, expect the request to still be **forwarded** (200/404 from
the backend, not blocked) — check the dashboard/API for the resulting security event:

```powershell
curl.exe -u admin:<password> http://localhost:9400/calixsentry/api/events?limit=5
```

## 6. XSS

```powershell
curl.exe -i "http://localhost:8080/?q=<script>alert(1)</script>"
```

## 7. Path traversal (unencoded + encoded)

```powershell
curl.exe -i "http://localhost:8080/../../etc/passwd"
curl.exe -i "http://localhost:8080/%2e%2e%2f%2e%2e%2fetc/passwd"
```

## 8. Endpoint / scanner behavior simulation

```powershell
$paths = @("/", "/admin", "/.env", "/.git/config", "/wp-admin", "/phpinfo.php", `
           "/config.php", "/backup.zip", "/server-status") + (1..20 | ForEach-Object { "/random-path-$_" })
foreach ($p in $paths) {
  curl.exe -s -o NUL -w "%{url_effective} -> %{http_code}`n" "http://localhost:8080$p"
}
curl.exe -u admin:<password> "http://localhost:9400/calixsentry/api/events?limit=10"
```

Expect a `CS-BOT-001` / `ENDPOINT_ENUMERATION` event with several reasons listed
(unique URL count, 404 ratio, sensitive paths, etc.) — and, in MONITOR mode, the
traffic still gets through (`action: LOG`, `recommendedAction: TEMPORARY_BLOCK`).

## 9. Rate abuse

```powershell
1..150 | ForEach-Object { curl.exe -s -o NUL -w "%{http_code} " "http://localhost:8080/" }
```

Expect a run of `200` followed by `429` once the configured rate limit (default
100/60s + burst 20) is exceeded.

## 10. Temporary blocking (manual, then auto-expiry)

```powershell
curl.exe -u admin:<password> -X POST http://localhost:9400/calixsentry/api/blocks `
  -H "Content-Type: application/json" `
  -d '{"ip":"203.0.113.5","reason":"manual test","durationSeconds":30,"permanent":false}'

# simulate that client (proxy support or a machine with that IP would be needed to
# see the 403 directly; verify via the API instead):
curl.exe -u admin:<password> http://localhost:9400/calixsentry/api/blocks

# wait 30+ seconds, then check again - it should be gone:
Start-Sleep -Seconds 35
curl.exe -u admin:<password> http://localhost:9400/calixsentry/api/blocks
```

## 11. Manual permanent block + unblock

```powershell
curl.exe -u admin:<password> -X POST http://localhost:9400/calixsentry/api/blocks `
  -H "Content-Type: application/json" `
  -d '{"ip":"198.51.100.9","reason":"manual permanent","permanent":true}'

curl.exe -u admin:<password> -X DELETE http://localhost:9400/calixsentry/api/blocks/198.51.100.9
```

## 12. Allowlist bypass

```powershell
curl.exe -u admin:<password> -X POST http://localhost:9400/calixsentry/api/allowlist `
  -H "Content-Type: application/json" `
  -d '{"value":"203.0.113.5","reason":"trusted scanner for internal pentest"}'
```

## 13. Automatic protection stays off until explicitly enabled

With default config (`protection.mode: MONITOR`, `automaticBlocking: false`), repeat
step 8 (the scanning simulation) as many times as you like — confirm via
`/calixsentry/api/blocks` that **no block is ever created automatically**. Only after
setting `calixsentry.protection.mode: AUTOMATIC` and
`calixsentry.protection.automaticBlocking: true` (and restarting) should a
high-score scanning burst produce an automatic temporary block.

## Dashboard

```
http://localhost:9400/calixsentry/
```

Basic-Auth prompt: username `admin`, password from step 1.
