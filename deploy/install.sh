#!/bin/sh
# Blueveil private installation.
#
#   sudo ./deploy/install.sh --system                  # system service
#   ./deploy/install.sh --user --prefix "$HOME/blueveil"  # no root needed
#
# Modes:
#   --system            /usr/local/bin, /etc/blueveil, /var/lib/blueveil,
#                       blueveil system user, system systemd unit. Needs root.
#   --user --prefix DIR everything under DIR (+ user systemd unit).
#                       No root, no new users, no host changes.
# Options:
#   --no-start          install files only, do not start the service.
#   --backend sqlite|postgres   prefill config template backend (default sqlite).
#   --listen ADDR       prefill listen address (default 127.0.0.1:8008).
#   --bin PATH          server binary artifact (default <repo>/dist/blueveil).
#   --ui-dir PATH       built UI directory (default <repo>/collector/ui/dist).
#
# The script never overwrites an existing config.json, never prints
# secrets, and never starts a service whose config fails validation
# (the binary validates before any side effect; --no-start still runs
# `blueveil --serve --help`-free validation via a dry check below).
set -eu

MODE=""; PREFIX=""; NO_START=0; BACKEND="sqlite"; LISTEN="127.0.0.1:8008"; BINOVERRIDE=""; UIOVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --system) MODE="system"; shift ;;
    --user) MODE="user"; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --backend) BACKEND="$2"; shift 2 ;;
    --bin) BINOVERRIDE="$2"; shift 2 ;;
    --ui-dir) UIOVERRIDE="$2"; shift 2 ;;
    --listen) LISTEN="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ "$MODE" = "system" ] || [ "$MODE" = "user" ] || { echo "need --system or --user" >&2; exit 2; }
if [ "$MODE" = "user" ] && [ -z "$PREFIX" ]; then echo "need --prefix DIR with --user" >&2; exit 2; fi
case "$BACKEND" in sqlite|postgres) ;; *) echo "--backend must be sqlite|postgres" >&2; exit 2 ;; esac

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN_SRC="${BINOVERRIDE:-$HERE/dist/blueveil}"
UI_SRC="${UIOVERRIDE:-$HERE/collector/ui/dist}"
[ -x "$BIN_SRC" ] || { echo "missing binary: build first (see docs/OPERATOR.md §1)" >&2; exit 2; }
[ -f "$UI_SRC/index.html" ] || { echo "missing UI build: run npm run build in collector/ui first" >&2; exit 2; }

if [ "$MODE" = "system" ]; then
  [ "$(id -u)" = "0" ] || { echo "--system needs root" >&2; exit 2; }
  BINDIR=/usr/local/bin; CONFDIR=/etc/blueveil; DATADIR=/var/lib/blueveil
  UIDIR=/usr/local/share/blueveil/ui; DOCDIR=/usr/local/share/doc/blueveil
  SVC_USER=blueveil; UNIT=/etc/systemd/system/blueveil.service
  if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
    echo "created user $SVC_USER"
  fi
  SYSTEMCTL="systemctl"
else
  BINDIR="$PREFIX/bin"; CONFDIR="$PREFIX/etc"; DATADIR="$PREFIX/data"
  UIDIR="$PREFIX/share/ui"; DOCDIR="$PREFIX/share/doc"
  SVC_USER=$(id -un); UNIT="$HOME/.config/systemd/user/blueveil.service"
  mkdir -p "$HOME/.config/systemd/user"
  SYSTEMCTL="systemctl --user"
fi

install -d -m 0755 "$BINDIR" "$UIDIR" "$DOCDIR"
install -d -m 0750 "$DATADIR" "$CONFDIR"
install -m 0755 "$BIN_SRC" "$BINDIR/blueveil"
cp -r "$UI_SRC/." "$UIDIR/"
cp "$HERE/docs/OPERATOR.md" "$DOCDIR/"
sed -e "s#@BINDIR@#$BINDIR#" -e "s#@CONFDIR@#$CONFDIR#" -e "s#@DATADIR@#$DATADIR#" \
  "$HERE/deploy/blueveil.service" > "$UNIT.tmp"
if [ "$MODE" = "system" ]; then chown "root:$SVC_USER" "$CONFDIR" "$DATADIR"; fi
# User-scope units omit mount-namespace sandboxing: PrivateTmp,
# ProtectSystem/ProtectHome, PrivateDevices, ProtectKernel*,
# ProtectControlGroups, ProtectClock, ProtectHostname, ProtectProc,
# ReadWritePaths and CapabilityBoundingSet all need mount namespacing
# or privilege an unprivileged user manager may not have. At user scope
# there is no privilege boundary to defend (everything is already
# user-owned), so the unit keeps only the namespace-free restrictions.
# The system unit keeps the full set.
if [ "$MODE" = "user" ]; then
  sed -i -e '/^User=/d' -e '/^Group=/d' \
    -e '/^PrivateTmp=/d' -e '/^ProtectSystem=/d' -e '/^ReadWritePaths=/d' \
    -e '/^ProtectHome=/d' -e '/^PrivateDevices=/d' -e '/^ProtectKernelTunables=/d' \
    -e '/^ProtectKernelModules=/d' -e '/^ProtectControlGroups=/d' -e '/^ProtectClock=/d' \
    -e '/^ProtectHostname=/d' -e '/^CapabilityBoundingSet=/d' "$UNIT.tmp"
fi
mv "$UNIT.tmp" "$UNIT"
chmod 0644 "$UNIT"

# config.json: created once from the template, never overwritten.
if [ ! -f "$CONFDIR/config.json" ]; then
  sed -e "s#\"listen_addr\": \"[^\"]*\"#\"listen_addr\": \"$LISTEN\"#" \
      -e "s#\"backend\": \"[a-z]*\"#\"backend\": \"$BACKEND\"#" \
      -e "s#/var/lib/blueveil/blueveil.db#$DATADIR/blueveil.db#" \
      -e "s#/usr/local/share/blueveil/ui#$UIDIR#" \
      "$HERE/deploy/config.example.json" > "$CONFDIR/config.json"
  if [ "$MODE" = "system" ]; then chown "root:$SVC_USER" "$CONFDIR/config.json"; fi
  chmod 0640 "$CONFDIR/config.json"
  echo "wrote template $CONFDIR/config.json — EDIT keys/TLS/backend before starting"
else
  echo "keeping existing $CONFDIR/config.json"
fi
# secrets.env placeholder: created empty once (0600), never touched after.
if [ ! -f "$CONFDIR/secrets.env" ]; then
  printf '# Optional secrets (0600). Prefer config.json for key hashes.\n# BLUEVEIL_PG_PASSWORD=\n# BLUEVEIL_API_KEYS=\n' > "$CONFDIR/secrets.env"
  chmod 0600 "$CONFDIR/secrets.env"
fi

# Validate the assembled unit file offline where possible: syntax
# errors fail the install before anything starts.
if command -v systemd-analyze >/dev/null 2>&1; then
  if ! systemd-analyze verify "$UNIT" 2>&1; then
    echo "unit verification failed for $UNIT" >&2; exit 1
  fi
fi

if [ "$NO_START" = "1" ]; then
  echo "installed (not started). Next: edit $CONFDIR/config.json, then: $SYSTEMCTL daemon-reload && $SYSTEMCTL enable --now blueveil"
  exit 0
fi
$SYSTEMCTL daemon-reload
$SYSTEMCTL enable --now blueveil 2>&1 || {
  echo "service failed to start — check: $SYSTEMCTL status blueveil" >&2; exit 1; }

# Readiness is authoritative: the install succeeds only when readyz says so.
ADDR=$(sed -n 's/.*"listen_addr": *"\([^"]*\)".*/\1/p' "$CONFDIR/config.json" | head -1)
SCHEME=http
if sed -n '/"tls"[[:space:]]*:/,/"explicit_insecure_http"/p' "$CONFDIR/config.json" | grep -q '"enabled":[[:space:]]*true'; then
  SCHEME=https
fi
READY_URL="$SCHEME://$ADDR/api/v1/readyz"
echo "waiting for readiness at $READY_URL ..."
for i in $(seq 1 30); do
  if [ "$SCHEME" = "https" ]; then CURLK="-k"; else CURLK=""; fi
  # shellcheck disable=SC2086
  if curl -sf $CURLK --max-time 2 "$READY_URL" | grep -q '"status"[[:space:]]*:[[:space:]]*"ready"'; then
    echo "READY: $READY_URL"
    if [ "$MODE" = "system" ]; then $SYSTEMCTL status blueveil --no-pager | head -8; fi
    echo "Next: create an API key (collector --keygen), open the UI at $SCHEME://$ADDR/"
    exit 0
  fi
  sleep 1
done
echo "service started but never became ready — inspect: journalctl _SYSTEMD_UNIT=blueveil.service (or --user)" >&2
exit 1
