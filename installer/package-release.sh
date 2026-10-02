#!/usr/bin/env bash
#
# Builds a self-contained release archive, the same shape Elastic ships:
# download an archive, extract it, run the startup script.
#
#   installer/package-release.sh
#
# Produces, in dist/:
#   calixsentry-<version>-linux-x64.tar.gz   (Linux/macOS: tar.gz + bin/calixsentry-engine)
#   calixsentry-<version>.zip                (Windows-friendly: same contents, .zip)
#
# Requires Maven + a Java 21 JDK with real internet access to Maven Central -
# this script builds the jar itself, it does not download a pre-built one.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(grep -m1 '<version>' "$PROJECT_ROOT/pom.xml" | sed -E 's/.*<version>(.*)<\/version>.*/\1/')"
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH_LABEL="x64" ;; aarch64|arm64) ARCH_LABEL="arm64" ;; *) ARCH_LABEL="$ARCH" ;; esac

STAGE="$PROJECT_ROOT/dist/stage/calixsentry-${VERSION}"
DIST_DIR="$PROJECT_ROOT/dist"

echo "[package] Building calixsentry-engine.jar with Maven..."
( cd "$PROJECT_ROOT" && mvn -q -B clean package -DskipTests )
JAR="$PROJECT_ROOT/target/calixsentry-engine.jar"
[[ -f "$JAR" ]] || { echo "[package] ERROR: expected jar not found at $JAR"; exit 1; }

echo "[package] Assembling release layout..."
rm -rf "$STAGE"
mkdir -p "$STAGE/lib" "$STAGE/bin" "$STAGE/config" "$STAGE/docs"

cp "$JAR" "$STAGE/lib/calixsentry-engine.jar"
cp "$PROJECT_ROOT/src/main/resources/application.yml" "$STAGE/config/application.yml.example"
cp "$SCRIPT_DIR/install.sh" "$STAGE/install.sh"
cp -r "$SCRIPT_DIR/bin/calixsentry" "$STAGE/bin/calixsentry"
[[ -f "$PROJECT_ROOT/README.md" ]] && cp "$PROJECT_ROOT/README.md" "$STAGE/"
[[ -d "$PROJECT_ROOT/docs" ]] && cp -r "$PROJECT_ROOT/docs/." "$STAGE/docs/"

# The portable startup script Elastic-style users expect: bin/calixsentry-engine
cat > "$STAGE/bin/calixsentry-engine" << 'STARTEOF'
#!/usr/bin/env bash
# Runs CalixSentry directly from an extracted archive, no install/systemd required -
# for evaluation, development, or environments that manage the process another way.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v java >/dev/null 2>&1 || { echo "Java 21+ is required. See https://adoptium.net"; exit 1; }
JAVA_MAJOR="$(java -version 2>&1 | head -1 | grep -oE '[0-9]+' | head -1)"
if [[ -n "$JAVA_MAJOR" && "$JAVA_MAJOR" -lt 21 ]]; then
  echo "Java 21+ is required (found major version $JAVA_MAJOR)."; exit 1
fi

export CALIXSENTRY_PORT="${CALIXSENTRY_PORT:-8080}"
export CALIXSENTRY_MANAGEMENT_PORT="${CALIXSENTRY_MANAGEMENT_PORT:-9400}"
export CALIXSENTRY_DATA_DIR="${CALIXSENTRY_DATA_DIR:-$HERE/data}"
mkdir -p "$CALIXSENTRY_DATA_DIR"

if [[ -z "${CALIXSENTRY_BACKEND_URL:-}" ]]; then
  echo "Set CALIXSENTRY_BACKEND_URL to the application you want to protect, e.g.:"
  echo "  CALIXSENTRY_BACKEND_URL=http://localhost:3000 ./bin/calixsentry-engine"
  exit 1
fi

echo "Starting CalixSentry: gateway on :${CALIXSENTRY_PORT}, dashboard on :${CALIXSENTRY_MANAGEMENT_PORT} (127.0.0.1 only)"
exec java -XX:MaxRAMPercentage=75.0 -jar "$HERE/lib/calixsentry-engine.jar"
STARTEOF
chmod +x "$STAGE/bin/calixsentry-engine" "$STAGE/bin/calixsentry" "$STAGE/install.sh"

mkdir -p "$DIST_DIR"
TARBALL="calixsentry-${VERSION}-linux-${ARCH_LABEL}.tar.gz"
ZIPFILE="calixsentry-${VERSION}.zip"

( cd "$PROJECT_ROOT/dist/stage" && tar -czf "$DIST_DIR/$TARBALL" "calixsentry-${VERSION}" )
if command -v zip >/dev/null 2>&1; then
  ( cd "$PROJECT_ROOT/dist/stage" && zip -rq "$DIST_DIR/$ZIPFILE" "calixsentry-${VERSION}" )
fi

echo "[package] Done:"
echo "  $DIST_DIR/$TARBALL"
[[ -f "$DIST_DIR/$ZIPFILE" ]] && echo "  $DIST_DIR/$ZIPFILE"
echo
echo "Try it:"
echo "  tar xzf $TARBALL && cd calixsentry-${VERSION}"
echo "  CALIXSENTRY_BACKEND_URL=http://localhost:3000 ./bin/calixsentry-engine"
echo "  sudo ./install.sh          # to install as a permanent systemd service instead"
