# Packaging & Distribution

How CalixSentry is meant to be installed, modeled on Elastic's own options, and
which of these are real today vs. planned. Stated honestly per spec section 35.

## Available today

### 1. Archive download (`.tar.gz` / `.zip`) - closest to Elastic's model
```bash
installer/package-release.sh
```
Builds the jar with Maven, then assembles and compresses:
```
dist/calixsentry-<version>-linux-x64.tar.gz
dist/calixsentry-<version>.zip
```
A user downloads it, extracts it, and runs the startup script - no install step required:
```bash
tar xzf calixsentry-<version>-linux-x64.tar.gz
cd calixsentry-<version>
CALIXSENTRY_BACKEND_URL=http://localhost:3000 ./bin/calixsentry-engine
```
This is the right choice for evaluation, development, or any environment where you
already manage processes another way (your own systemd unit, a process supervisor,
Windows Task Scheduler running `java -jar lib/calixsentry-engine.jar` directly, etc.)
Java 21+ is the only requirement - `bin/calixsentry-engine` checks for it and fails
with a clear message if it's missing, rather than crashing obscurely.

### 2. Native Linux service install (systemd)
```bash
sudo ./install.sh
```
Included inside the same archive, or run directly from the repo. Installs a systemd
service, generates directories/config/a bootstrap admin password, and starts CalixSentry
running as its own dedicated OS user. This is `installer/install.sh`, documented in the
main README.

### 3. Docker (development, and works fine for production too)
```bash
docker compose up --build
```
Or, for a real deployment, build the image (`docker build -t calixsentry .`) and run it
with your own port/env/volume choices - it's a normal Spring Boot container.

## Not implemented yet (do not advertise these as available)

### Package manager repositories (`apt install calixsentry`, `yum install calixsentry`)
This is what Elastic's `apt-get install elasticsearch` / `yum install elasticsearch`
actually requires behind the scenes: a hosted, GPG-signed APT/YUM repository, a release
pipeline that builds and signs `.deb`/`.rpm` packages on every version, and a real domain
serving that repository metadata. None of that infrastructure exists yet - `calixsentry.com`
and friends are placeholder domains from the product brief, not live services. Building the
packages themselves (with a tool like `fpm` or `jpackage`) is straightforward once there's
somewhere real to host and sign them; standing up the hosting/signing pipeline is the actual
work, and it's explicitly future work, not something to fake with a non-functional command.

### Native Windows / macOS installers
No `.msi`, no Windows service wrapper, no `.pkg`/`.dmg`, no launchd plist. The archive
download (`bin/calixsentry-engine`, or `java -jar lib\calixsentry-engine.jar` directly on
Windows) works on any OS with Java 21+, but there is no first-class installer experience
for Windows Server or macOS yet - see `docs/ROADMAP.md`.

### `curl -fsSL https://download.calixsentry.com/install.sh | sudo bash`
The one-line curl-pipe-bash installer described in the original product brief needs a real
hosted `install.sh` at a real domain - mechanically identical to `installer/install.sh` in
this repo, just served from somewhere reachable. Point that URL at this script once
`download.calixsentry.com` (or wherever you choose to host it) actually exists.
