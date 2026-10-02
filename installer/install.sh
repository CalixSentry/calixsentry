#!/usr/bin/env bash
#
# CalixSentry installer (spec section 21).
#
# SCOPE (stated honestly, per spec section 35):
#   - Supported now:  Linux x86_64 / arm64, systemd-based distros (Ubuntu,
#                      Debian, RHEL/CentOS/Rocky/Alma, Amazon Linux).
#   - NOT IMPLEMENTED: Windows Server and macOS native installers, automatic
#                      TLS/cert provisioning, multi-node/cluster install.
#                      See docs/ROADMAP.md.
#
# This installer does NOT require Docker. It runs the engine as a native
# systemd service using a JRE (bundled-preferred, falling back to the
# distro's OpenJDK 21 package - see choose_java() below).
#
# Usage:
#   sudo bash installer/install.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (safe defaults - can be overridden by environment variables
# before running this script, e.g. `CALIXSENTRY_PORT=80 sudo -E bash install.sh`)
# ---------------------------------------------------------------------------
INSTALL_DIR="/opt/calixsentry"
CONFIG_DIR="/etc/calixsentry"
DATA_DIR="/data/calixsentry"
LOG_DIR="/var/log/calixsentry"
SERVICE_NAME="calixsentry"
CALIXSENTRY_PORT="${CALIXSENTRY_PORT:-8080}"
CALIXSENTRY_MANAGEMENT_PORT="${CALIXSENTRY_MANAGEMENT_PORT:-9400}"
CALIXSENTRY_MANAGEMENT_BIND="${CALIXSENTRY_MANAGEMENT_BIND:-127.0.0.1}"
CALIXSENTRY_BACKEND_URL="${CALIXSENTRY_BACKEND_URL:-}"
SERVICE_USER="calixsentry"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log()  { echo "[calixsentry-install] $*"; }
fail() { echo "[calixsentry-install] ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Root check
# ---------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
  fail "This installer must be run as root: sudo bash installer/install.sh"
fi

# ---------------------------------------------------------------------------
# 2. Detect OS and architecture
# ---------------------------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "$OS" != "Linux" ]]; then
  fail "NOT IMPLEMENTED: native installer for '$OS' is not available yet (Linux only in this release). See docs/ROADMAP.md."
fi

case "$ARCH" in
  x86_64|amd64) ARCH_LABEL="x86_64" ;;
  aarch64|arm64) ARCH_LABEL="arm64" ;;
  *) fail "Unsupported architecture: $ARCH (supported: x86_64, arm64)" ;;
esac

log "Detected OS: Linux ($ARCH_LABEL)"

PKG_MANAGER=""
if command -v apt-get >/dev/null 2>&1; then PKG_MANAGER="apt"; fi
if command -v dnf     >/dev/null 2>&1; then PKG_MANAGER="dnf"; fi
if command -v yum     >/dev/null 2>&1 && [[ -z "$PKG_MANAGER" ]]; then PKG_MANAGER="yum"; fi

# ---------------------------------------------------------------------------
# 3. Check for systemd (required by this installer)
# ---------------------------------------------------------------------------
if ! command -v systemctl >/dev/null 2>&1; then
  fail "systemd (systemctl) not found. This installer currently requires a systemd-based distro."
fi

# ---------------------------------------------------------------------------
# 4. Check / install Java 21
# ---------------------------------------------------------------------------
choose_java() {
  if command -v java >/dev/null 2>&1; then
    local ver
    ver="$(java -version 2>&1 | head -1 | grep -oE '[0-9]+' | head -1)"
    if [[ -n "$ver" && "$ver" -ge 21 ]]; then
      log "Found Java $ver already installed: $(command -v java)"
      return 0
    fi
  fi

  log "Java 21+ not found. Attempting to install OpenJDK 21 via ${PKG_MANAGER:-<no package manager detected>}..."
  case "$PKG_MANAGER" in
    apt) apt-get update -qq && apt-get install -y -qq openjdk-21-jre-headless ;;
    dnf) dnf install -y -q java-21-openjdk-headless ;;
    yum) yum install -y -q java-21-openjdk-headless ;;
    *) fail "No supported package manager found to install Java automatically. Install a Java 21+ JRE manually, then re-run this installer." ;;
  esac

  command -v java >/dev/null 2>&1 || fail "Java installation appears to have failed."
  log "Installed: $(java -version 2>&1 | head -1)"
}
choose_java

# ---------------------------------------------------------------------------
# 5. Check port availability
# ---------------------------------------------------------------------------
check_port() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "( sport = :$port )" | grep -q ":$port"; then
      fail "Port $port is already in use. Set CALIXSENTRY_PORT to a free port and re-run: CALIXSENTRY_PORT=8081 sudo -E bash installer/install.sh"
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -ltn 2>/dev/null | grep -q ":$port "; then
      fail "Port $port is already in use. Set CALIXSENTRY_PORT to a free port and re-run."
    fi
  else
    log "WARNING: could not check port availability (no 'ss' or 'netstat' found) - proceeding without the check."
  fi
}
check_port "$CALIXSENTRY_PORT"
log "Public gateway port $CALIXSENTRY_PORT is available."
if [[ "$CALIXSENTRY_MANAGEMENT_PORT" != "0" ]]; then
  check_port "$CALIXSENTRY_MANAGEMENT_PORT"
  log "Management port $CALIXSENTRY_MANAGEMENT_PORT is available (dashboard/API - not internet-facing by default)."
fi

# ---------------------------------------------------------------------------
# 6. Locate or build the application jar
# ---------------------------------------------------------------------------
JAR_PATH=""
if [[ -f "$SCRIPT_DIR/dist/calixsentry-engine.jar" ]]; then
  JAR_PATH="$SCRIPT_DIR/dist/calixsentry-engine.jar"
  log "Using pre-built jar: $JAR_PATH"
elif [[ -f "$PROJECT_ROOT/target/calixsentry-engine.jar" ]]; then
  JAR_PATH="$PROJECT_ROOT/target/calixsentry-engine.jar"
  log "Using already-built jar: $JAR_PATH"
elif [[ -f "$PROJECT_ROOT/pom.xml" ]]; then
  log "No pre-built jar found - building from source with Maven (requires internet access to Maven Central)..."
  command -v mvn >/dev/null 2>&1 || fail "Maven not found and no pre-built jar available. Install Maven, or place a pre-built jar at installer/dist/calixsentry-engine.jar."
  ( cd "$PROJECT_ROOT" && mvn -q -B clean package -DskipTests ) || fail "Maven build failed."
  JAR_PATH="$PROJECT_ROOT/target/calixsentry-engine.jar"
  [[ -f "$JAR_PATH" ]] || fail "Build succeeded but expected jar not found at $JAR_PATH"
else
  fail "Could not find a jar to install and no pom.xml/src present to build one."
fi

# ---------------------------------------------------------------------------
# 7. Create directories
# ---------------------------------------------------------------------------
log "Creating directories..."
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
chmod 750 "$DATA_DIR"

cp "$JAR_PATH" "$INSTALL_DIR/calixsentry-engine.jar"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/calixsentry-engine.jar"

# ---------------------------------------------------------------------------
# 8. Create configuration (environment file read by the systemd unit)
# ---------------------------------------------------------------------------
if [[ -z "$CALIXSENTRY_BACKEND_URL" ]]; then
  echo
  echo "What application should CalixSentry protect? This is where CalixSentry forwards"
  echo "legitimate traffic once it has been inspected. Examples:"
  echo "  http://localhost:3000            an app running on this same server"
  echo "  http://127.0.0.1:8081            same, by loopback IP"
  echo "  http://10.20.30.40:8080          an app on another server in your private network"
  echo "  http://internal-app.mycompany.local:8080   an internal hostname"
  echo "  https://app-origin.example.com   a cloud-hosted origin (CalixSentry sits in front of it)"
  read -rp "Backend application URL to protect: " CALIXSENTRY_BACKEND_URL
  [[ -n "$CALIXSENTRY_BACKEND_URL" ]] || fail "A backend URL is required."
fi
[[ "$CALIXSENTRY_BACKEND_URL" =~ ^https?:// ]] || fail "Backend URL must start with http:// or https:// (got: $CALIXSENTRY_BACKEND_URL)"

log "Writing configuration to $CONFIG_DIR/calixsentry.env"
cat > "$CONFIG_DIR/calixsentry.env" <<EOF
CALIXSENTRY_PORT=${CALIXSENTRY_PORT}
CALIXSENTRY_MANAGEMENT_PORT=${CALIXSENTRY_MANAGEMENT_PORT}
CALIXSENTRY_MANAGEMENT_BIND=${CALIXSENTRY_MANAGEMENT_BIND}
CALIXSENTRY_BACKEND_URL=${CALIXSENTRY_BACKEND_URL}
CALIXSENTRY_DATA_DIR=${DATA_DIR}
EOF
chmod 640 "$CONFIG_DIR/calixsentry.env"
chown root:"$SERVICE_USER" "$CONFIG_DIR/calixsentry.env"

# ---------------------------------------------------------------------------
# 9. Create the systemd service
# ---------------------------------------------------------------------------
log "Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=CalixSentry - Self-Hosted Behavioral Web Application Firewall
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
EnvironmentFile=${CONFIG_DIR}/calixsentry.env
ExecStart=/usr/bin/env java -XX:MaxRAMPercentage=75.0 -jar ${INSTALL_DIR}/calixsentry-engine.jar
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_DIR}/calixsentry.log
StandardError=append:${LOG_DIR}/calixsentry.log

# Basic hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} ${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null

# ---------------------------------------------------------------------------
# 10. Install the CLI
# ---------------------------------------------------------------------------
log "Installing CLI to /usr/local/bin/calixsentry"
cp "$SCRIPT_DIR/bin/calixsentry" /usr/local/bin/calixsentry
chmod +x /usr/local/bin/calixsentry

# ---------------------------------------------------------------------------
# 11. Start and health-check
# ---------------------------------------------------------------------------
log "Starting CalixSentry..."
systemctl restart "$SERVICE_NAME"

log "Waiting for health check..."
HEALTHY=false
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${CALIXSENTRY_PORT}/health" >/dev/null 2>&1; then
    HEALTHY=true
    break
  fi
  sleep 1
done

if [[ "$HEALTHY" != "true" ]]; then
  log "WARNING: health check did not succeed within 30s. Check logs: journalctl -u ${SERVICE_NAME} -f  or  tail -f ${LOG_DIR}/calixsentry.log"
else
  log "Health check passed."
fi

# ---------------------------------------------------------------------------
# 12. Display access information (spec section 21)
# ---------------------------------------------------------------------------
ADMIN_PW_FILE="${DATA_DIR}/initial-admin-password.txt"
echo
echo "================================================================"
echo " CalixSentry Installation Complete"
echo "================================================================"
echo
echo " Gateway:"
echo "   http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo YOUR_SERVER):${CALIXSENTRY_PORT}"
echo
echo " Management Dashboard (private - bound to ${CALIXSENTRY_MANAGEMENT_BIND}, not on the public port):"
if [[ "${CALIXSENTRY_MANAGEMENT_BIND}" == "127.0.0.1" ]]; then
  echo "   http://localhost:${CALIXSENTRY_MANAGEMENT_PORT}/calixsentry/   (from this server, or via an SSH tunnel:"
  echo "   ssh -L 9400:localhost:${CALIXSENTRY_MANAGEMENT_PORT} youruser@$(hostname -I 2>/dev/null | awk '{print $1}' || echo YOUR_SERVER))"
else
  echo "   http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo YOUR_SERVER):${CALIXSENTRY_MANAGEMENT_PORT}/calixsentry/"
fi
echo "   Username: admin"
if [[ -r "$ADMIN_PW_FILE" ]]; then
  echo "   Password: $(cat "$ADMIN_PW_FILE")   (also stored at ${ADMIN_PW_FILE}, root-readable only)"
else
  echo "   Password: check '${LOG_DIR}/calixsentry.log' for the generated bootstrap password,"
  echo "             or set CALIXSENTRY_ADMIN_PASSWORD in ${CONFIG_DIR}/calixsentry.env and restart."
fi
echo
echo " Protection Mode:      MONITOR   (safe default - detects, never blocks)"
echo " Automatic Blocking:   OFF       (explicit admin opt-in required)"
echo
echo " CLI:"
echo "   calixsentry status"
echo "   calixsentry events"
echo "   calixsentry block <ip> <durationSeconds|permanent> \"<reason>\""
echo
echo " Service management:"
echo "   systemctl status ${SERVICE_NAME}"
echo "   journalctl -u ${SERVICE_NAME} -f"
echo "================================================================"
