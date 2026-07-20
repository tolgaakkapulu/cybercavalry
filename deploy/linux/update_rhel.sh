#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
#  CYBER Cavalry — RHEL 9.x Production Update Script
#
#  Unlike install_rhel.sh, this script DOES NOT perform a clean install. It
#  preserves the existing deployment and only refreshes the application code
#  and dependencies:
#    - PRESERVED : .env, certs/, logs/, cybercavalry.db, backups/
#    - UPDATED   : application code, venv dependencies, static files,
#                  migrations
#
#  Safety: a DB snapshot + code snapshot are taken before the update
#  (rollback path).
#
#  Prerequisites:
#    - The system was previously installed with install_rhel.sh
#    - The new-version zip has been placed under $ZIP_SOURCE
#
#  Usage:
#    sudo bash deploy/linux/update_rhel.sh
#
#  Note — CRLF error: sudo dnf install -y dos2unix; dos2unix update_rhel.sh
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CONFIGURATION                                                       ║
# ╠══════════════════════════════════════════════════════════════════════╣
INSTALL_DIR="/data/cybercavalry"
VERSIONS_DIR="/data/versions"
ROLLBACK_DIR="/data/rollback"
ZIP_SOURCE="/home/cavalry.svc"
SERVICE_USER="cavalry"
SERVICE_GROUP="cavalry"
SERVICE_NAME="cybercavalry"
# ╚══════════════════════════════════════════════════════════════════════╝

# Paths that are PRESERVED during the update (rsync --exclude)
PRESERVE=(
    '.env'
    'venv/'
    'certs/'
    'logs/'
    'backups/'
    'cybercavalry.db'
    'cybercavalry.db-wal'
    'cybercavalry.db-shm'
)

RED=$'\e[91m'; GREEN=$'\e[92m'; YELLOW=$'\e[93m'; CYAN=$'\e[96m'
BOLD=$'\e[1m'; RESET=$'\e[0m'
info() { echo "${CYAN}[..]${RESET} $*"; }
ok()   { echo "${GREEN}[OK]${RESET} $*"; }
warn() { echo "${YELLOW}[!]${RESET}  $*"; }
err()  { echo "${RED}[FAIL]${RESET} $*" >&2; }
step() { echo; echo "${BOLD}${CYAN}═══ $* ═══${RESET}"; }


# ── Pre-flight ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root: sudo bash $0"
    exit 1
fi

if [[ ! -d "$INSTALL_DIR" ]]; then
    err "$INSTALL_DIR does not exist. This is an update script — run install_rhel.sh first."
    exit 1
fi

if [[ ! -d "$INSTALL_DIR/venv" ]]; then
    err "$INSTALL_DIR/venv is missing. Installation is incomplete — run install_rhel.sh."
    exit 1
fi

ZIP_FILE=$(ls -t "$ZIP_SOURCE"/CYBERCavalry_v*.zip 2>/dev/null | head -1 || true)
if [[ -z "$ZIP_FILE" ]]; then
    err "No CYBERCavalry_v*.zip found under $ZIP_SOURCE."
    exit 1
fi
info "Update package: $ZIP_FILE"

PYBIN="$INSTALL_DIR/venv/bin/python"
PIPBIN="$INSTALL_DIR/venv/bin/pip"


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  1. Pre-update backup (DB + code)                                    ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "1/8 Pre-update backup"
STAMP=$(date +%Y%m%d_%H%M%S)
ROLLBACK_PATH="$ROLLBACK_DIR/$STAMP"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$ROLLBACK_DIR"

# DB backup (via the app's own backup_service — a consistent SQLite copy)
if [[ -f "$INSTALL_DIR/cybercavalry.db" ]]; then
    sudo -u "$SERVICE_USER" "$PYBIN" "$INSTALL_DIR/manage.py" backup_db --force || \
        warn "Application backup_db failed — a raw file copy will be taken."
fi

# Code + critical-file snapshot (full rollback target, minus venv)
info "Taking a code snapshot: $ROLLBACK_PATH"
mkdir -p "$ROLLBACK_PATH"
rsync -a --exclude 'venv/' --exclude 'backups/' "$INSTALL_DIR/" "$ROLLBACK_PATH/"
ok "Backup taken: $ROLLBACK_PATH"


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  2. Stop the service                                                 ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "2/8 Stop the service"
systemctl stop "$SERVICE_NAME" || warn "The service may already have been stopped."
ok "${SERVICE_NAME} stopped."


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  3. Extract the new version                                          ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "3/8 Extract the new version"
mkdir -p "$VERSIONS_DIR"
mv "$ZIP_FILE" "$VERSIONS_DIR/"
ZIP_FILE="$VERSIONS_DIR/$(basename "$ZIP_FILE")"

TMP_EXTRACT=$(mktemp -d)
unzip -q "$ZIP_FILE" -d "$TMP_EXTRACT"
NEW_SRC="$TMP_EXTRACT/CYBERCavalry"
if [[ ! -d "$NEW_SRC" ]]; then
    err "The zip does not contain a CYBERCavalry/ directory — layout is unexpected."
    rm -rf "$TMP_EXTRACT"
    exit 1
fi
ok "Extracted to: $NEW_SRC"


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  4. Sync the code (preserving protected paths)                       ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "4/8 Code sync"
EXCLUDES=()
for p in "${PRESERVE[@]}"; do
    EXCLUDES+=(--exclude "$p")
done
# --delete: also removes old code files no longer shipped, but does not touch the preserved paths
rsync -a --delete "${EXCLUDES[@]}" "$NEW_SRC/" "$INSTALL_DIR/"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
rm -rf "$TMP_EXTRACT"
ok "Code updated (.env, certs, logs, db, backups preserved)."


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  5. Refresh dependencies (offline wheels)                            ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "5/8 Dependencies"

# ── Pre-flight: is the venv actually usable? ────────────────────────────
# Renaming the deployment directory or moving the base Python can silently
# invalidate the shebangs of every script under venv/bin (gunicorn, pip,
# django-admin, ...). Their exec then fails with a misleading ENOENT even
# though the files exist. If pip refuses to run we tear the venv down and
# rebuild it so the offline `pip install` below has a clean starting point.
if ! sudo -u "$SERVICE_USER" "$PIPBIN" --version >/dev/null 2>&1; then
    warn "venv appears broken (pip refuses to run) — rebuilding from scratch."
    # Sniff the venv's Python major.minor from the site-packages directory
    # so the rebuild targets the same interpreter and the matching wheel
    # bundle (py39 or py311).
    OLD_PY=$(ls -d "$INSTALL_DIR"/venv/lib/python* 2>/dev/null | head -1 | sed -E 's|.*/python||')
    REBUILD_PY="python${OLD_PY:-3}"
    if ! command -v "$REBUILD_PY" >/dev/null 2>&1; then
        warn "$REBUILD_PY not on PATH — falling back to python3."
        REBUILD_PY=python3
    fi
    info "Rebuilding venv with $REBUILD_PY"
    sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/venv"
    sudo -u "$SERVICE_USER" "$REBUILD_PY" -m venv "$INSTALL_DIR/venv"
    # ensurepip guarantees pip is present even if the base Python was
    # packaged without it (rare on RHEL, but cheap insurance).
    sudo -u "$SERVICE_USER" "$PYBIN" -m ensurepip --upgrade >/dev/null 2>&1 || true
    ok "venv rebuilt."
fi

PY_TAG=py$("$PYBIN" -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')
WHEELS_DIR="$INSTALL_DIR/deploy/wheels/$PY_TAG"
if [[ -d "$WHEELS_DIR" ]]; then
    sudo -u "$SERVICE_USER" "$PIPBIN" install \
        --no-index --find-links "$WHEELS_DIR/" \
        --upgrade -r "$INSTALL_DIR/requirements.txt" gunicorn >/dev/null
    ok "Dependencies refreshed (from wheel set $PY_TAG)."
else
    warn "Wheel directory missing ($WHEELS_DIR) — dependency refresh skipped."
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  6. SELinux labels (for the new files)                               ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "6/8 SELinux labels"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R "$INSTALL_DIR/venv" >/dev/null 2>&1 || true
    restorecon -R "$INSTALL_DIR/logs" >/dev/null 2>&1 || true
    ok "SELinux labels refreshed."
else
    info "restorecon unavailable — skipped."
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  7. Migration + static                                               ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "7/8 Migration + static"
cd "$INSTALL_DIR"
sudo -u "$SERVICE_USER" "$PYBIN" manage.py migrate --noinput
sudo -u "$SERVICE_USER" "$PYBIN" manage.py createcachetable >/dev/null 2>&1 || true
sudo -u "$SERVICE_USER" "$PYBIN" manage.py collectstatic --noinput >/dev/null
ok "Migrations applied, static files collected."


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  8. Start the service + health check                                 ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "8/8 Start the service"
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
systemctl start "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "${SERVICE_NAME}.service is running."
    echo
    echo "  ${GREEN}${BOLD}Update complete.${RESET}"
    echo "  Rollback snapshot: ${BOLD}$ROLLBACK_PATH${RESET}"
    echo "  To roll back if something goes wrong:"
    echo "    sudo systemctl stop $SERVICE_NAME"
    echo "    sudo rsync -a --delete --exclude 'venv/' $ROLLBACK_PATH/ $INSTALL_DIR/"
    echo "    sudo systemctl start $SERVICE_NAME"
else
    err "${SERVICE_NAME} failed to start! An automatic rollback is RECOMMENDED. Last logs:"
    journalctl -u "$SERVICE_NAME" -n 40 --no-pager
    echo
    err "To roll back:"
    err "  sudo rsync -a --delete --exclude 'venv/' $ROLLBACK_PATH/ $INSTALL_DIR/"
    err "  sudo systemctl restart $SERVICE_NAME"
    exit 1
fi
