#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
#  CYBER Cavalry — RHEL 9.x Offline Installer
#
#  Prerequisites (manual):
#    1. python3 (3.9 or 3.11) and the unzip RPMs installed
#    2. (Optional) the redis RPM installed — otherwise the DatabaseCache
#       fallback is used
#    3. The release zip placed under $ZIP_SOURCE
#    4. The cavalry user is preserved if it exists; otherwise it is created
#
#  Usage:
#    sudo bash deploy/install_rhel.sh
#
#  Note — if you get a CRLF error: sudo dnf install -y dos2unix; dos2unix install_rhel.sh
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CONFIGURATION                                                       ║
# ╠══════════════════════════════════════════════════════════════════════╣
INSTALL_DIR="/data/cybercavalry"
VERSIONS_DIR="/data/versions"
ZIP_SOURCE="/home/cavalry.svc"
SERVICE_USER="cavalry"
SERVICE_GROUP="cavalry"
SERVICE_NAME="cybercavalry"
HTTPS_PORT=8443
USE_REDIS_IF_AVAILABLE=true     # set to false to leave REDIS_URL commented out in .env
# ╚══════════════════════════════════════════════════════════════════════╝


# ── Coloured log helpers ─────────────────────────────────────────────────
RED=$'\e[91m'; GREEN=$'\e[92m'; YELLOW=$'\e[93m'; CYAN=$'\e[96m'
BOLD=$'\e[1m'; RESET=$'\e[0m'

info() { echo "${CYAN}[..]${RESET} $*"; }
ok()   { echo "${GREEN}[OK]${RESET} $*"; }
warn() { echo "${YELLOW}[!]${RESET}  $*"; }
err()  { echo "${RED}[FAIL]${RESET} $*" >&2; }
step() { echo; echo "${BOLD}${CYAN}═══ $* ═══${RESET}"; }


# ── Pre-flight checks ────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root. Use: sudo bash $0"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found. Install it first with 'dnf install python3' (or the offline RPMs)."
    exit 1
fi

if ! command -v unzip >/dev/null 2>&1; then
    err "unzip not found. Install it with 'dnf install unzip'."
    exit 1
fi

ZIP_FILE=$(ls -t "$ZIP_SOURCE"/CYBERCavalry_v*.zip 2>/dev/null | head -1 || true)
if [[ -z "$ZIP_FILE" ]]; then
    err "No CYBERCavalry_v*.zip found under $ZIP_SOURCE."
    err "Copy the release package there first."
    exit 1
fi
info "Release package: $ZIP_FILE"


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  1. Service user                                                     ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "1/13 Service user: $SERVICE_USER"
if id "$SERVICE_USER" >/dev/null 2>&1; then
    info "$SERVICE_USER already exists; leaving it untouched."
else
    useradd --system --home-dir "$INSTALL_DIR" \
        --shell /sbin/nologin \
        --comment "CYBER Cavalry service user" "$SERVICE_USER"
    ok "$SERVICE_USER created."
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  2. Wipe the previous install and stage the new zip                  ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "2/13 Remove the previous install"
if [[ -d "$INSTALL_DIR" ]]; then
    info "Removing existing $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
fi
mkdir -p "$VERSIONS_DIR"
rm -f "$VERSIONS_DIR"/*.zip
mv "$ZIP_FILE" "$VERSIONS_DIR/"
ZIP_FILE="$VERSIONS_DIR/$(basename "$ZIP_FILE")"
ok "Cleaned. New zip location: $ZIP_FILE"


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  3. Extract the zip in place                                         ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "3/13 Extract the zip"
unzip -q "$ZIP_FILE" -d /data/
# The zip contains a "CYBERCavalry" (camelCase) directory; rename to lowercase.
if [[ -d /data/CYBERCavalry ]]; then
    mv /data/CYBERCavalry "$INSTALL_DIR"
fi

if [[ ! -d "$INSTALL_DIR" ]]; then
    err "$INSTALL_DIR does not exist after extraction. Check the zip layout."
    exit 1
fi
ok "Extracted to: $INSTALL_DIR"


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  4. Ownership and permissions                                        ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "4/13 Ownership and permissions"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 750 \
    "$INSTALL_DIR/logs" "$INSTALL_DIR/certs"
ok "Permissions set."


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  5. Python version detection                                         ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "5/13 Python version and wheel set"
PY_TAG=py$(python3 -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')
WHEELS_DIR="$INSTALL_DIR/deploy/wheels/$PY_TAG"

if [[ ! -d "$WHEELS_DIR" ]]; then
    err "Wheel directory missing: $WHEELS_DIR"
    err "Available wheel sets: $(ls "$INSTALL_DIR/deploy/wheels/" 2>/dev/null | tr '\n' ' ')"
    exit 1
fi
ok "Python: $(python3 -V) — wheel set: $PY_TAG"


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  6. venv + pip install                                               ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "6/13 Create venv and install dependencies"
rm -rf "$INSTALL_DIR/venv"
sudo -u "$SERVICE_USER" python3 -m venv "$INSTALL_DIR/venv"

# Upgrade pip first (the older resolver is slow)
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install \
    --no-index --find-links "$WHEELS_DIR/" --upgrade pip >/dev/null

# Install all dependencies (including gunicorn) offline
sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install \
    --no-index --find-links "$WHEELS_DIR/" \
    -r "$INSTALL_DIR/requirements.txt" gunicorn

PKG_COUNT=$(sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" list --format=freeze | wc -l)
ok "Dependencies installed ($PKG_COUNT packages)."


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  7. .env configuration                                               ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "7/13 .env"
if [[ -f "$INSTALL_DIR/.env" ]] && [[ -s "$INSTALL_DIR/.env" ]]; then
    info "Existing .env preserved."
else
    _gen_key() {
        sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" -c \
"import secrets,string
chars=string.ascii_letters+string.digits+'!@#\$%^&*(-_=+)'
print(''.join(secrets.choice(chars) for _ in range(64)))"
    }
    NEW_KEY=$(_gen_key)
    FIELD_KEY=$(_gen_key)   # independent key for encrypting secret settings

    SERVER_IP=$(hostname -I | awk '{print $1}')

    # Decide the REDIS_URL line based on whether Redis is installed
    if [[ "$USE_REDIS_IF_AVAILABLE" == "true" ]] && rpm -q redis >/dev/null 2>&1; then
        REDIS_LINE="REDIS_URL=redis://127.0.0.1:6379/1"
    else
        REDIS_LINE="# REDIS_URL=redis://127.0.0.1:6379/1   # DatabaseCache fallback is active"
    fi

    sudo -u "$SERVICE_USER" tee "$INSTALL_DIR/.env" >/dev/null <<EOF
SECRET_KEY=${NEW_KEY}
FIELD_ENCRYPTION_KEY=${FIELD_KEY}
DEBUG=False
ALLOWED_HOSTS=${SERVER_IP},127.0.0.1
SECURE_SSL_REDIRECT=False

${REDIS_LINE}

ADMIN_ALLOWED_IPS=127.0.0.1,::1

SSL_CERT_FILE=certs/cert.pem
SSL_KEY_FILE=certs/key.pem
EOF
    chmod 640 "$INSTALL_DIR/.env"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/.env"
    ok ".env created (SECRET_KEY + FIELD_ENCRYPTION_KEY generated)."
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  8. SSL certificate                                                  ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "8/13 SSL certificate"
if [[ -f "$INSTALL_DIR/certs/cert.pem" ]] && [[ -f "$INSTALL_DIR/certs/key.pem" ]]; then
    info "Certificates already present; leaving them untouched."
else
    # If fullchain.pem/privkey.pem sit in the previous directory, use them (real CA)
    if [[ -f fullchain.pem ]] && [[ -f privkey.pem ]]; then
        install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 644 \
            fullchain.pem "$INSTALL_DIR/certs/cert.pem"
        install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 600 \
            privkey.pem   "$INSTALL_DIR/certs/key.pem"
        ok "CA certificates installed."
    else
        # Generate a self-signed certificate
        cd "$INSTALL_DIR"
        sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" \
            "$INSTALL_DIR/generate_cert.py"
        cd - >/dev/null
        ok "Self-signed certificate generated."
    fi
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  9. Database migrate + cache + seed + static                         ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "9/13 Database, cache, seed, static"
cd "$INSTALL_DIR"

sudo -u "$SERVICE_USER" ./venv/bin/python manage.py makemigrations --noinput || \
    warn "makemigrations: no new migration produced (likely already up to date)."
sudo -u "$SERVICE_USER" ./venv/bin/python manage.py migrate --noinput
sudo -u "$SERVICE_USER" ./venv/bin/python manage.py createcachetable
sudo -u "$SERVICE_USER" ./venv/bin/python manage.py seed_initial_data || \
    warn "seed_initial_data skipped."
sudo -u "$SERVICE_USER" ./venv/bin/python manage.py collectstatic --noinput >/dev/null
ok "DB ready, cache table created, static files collected."


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  10. Redis (local only — if the RPM is already installed)            ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "10/13 Redis (local only)"
if rpm -q redis >/dev/null 2>&1; then
    systemctl enable --now redis
    sleep 1
    if redis-cli ping 2>/dev/null | grep -q PONG; then
        BIND=$(grep -E '^bind' /etc/redis/redis.conf | head -1)
        ok "Redis is running (PONG). Config: ${BIND:-bind not set}"
    else
        warn "Redis package installed but PONG not received. Check with systemctl status redis."
    fi
else
    warn "Redis package not installed. The DatabaseCache fallback in .env is active."
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  11. SELinux labelling (required for /data)                          ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "11/13 SELinux labels"
if command -v semanage >/dev/null 2>&1; then
    # Allow HTTPS on port 8443
    semanage port -a -t http_port_t -p tcp "$HTTPS_PORT" 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp "$HTTPS_PORT" 2>/dev/null || true

    # venv binaries (gunicorn, python) — bin_t
    semanage fcontext -a -t bin_t "$INSTALL_DIR/venv/bin(/.*)?" 2>/dev/null || \
        semanage fcontext -m -t bin_t "$INSTALL_DIR/venv/bin(/.*)?" 2>/dev/null || true

    # venv libraries — lib_t
    semanage fcontext -a -t lib_t "$INSTALL_DIR/venv/lib(/.*)?" 2>/dev/null || \
        semanage fcontext -m -t lib_t "$INSTALL_DIR/venv/lib(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t lib_t "$INSTALL_DIR/venv/lib64(/.*)?" 2>/dev/null || \
        semanage fcontext -m -t lib_t "$INSTALL_DIR/venv/lib64(/.*)?" 2>/dev/null || true

    # Log directory — var_log_t
    semanage fcontext -a -t var_log_t "$INSTALL_DIR/logs(/.*)?" 2>/dev/null || \
        semanage fcontext -m -t var_log_t "$INSTALL_DIR/logs(/.*)?" 2>/dev/null || true

    restorecon -R "$INSTALL_DIR/venv" >/dev/null
    restorecon -R "$INSTALL_DIR/logs" >/dev/null

    GUNICORN_CTX=$(ls -Z "$INSTALL_DIR/venv/bin/gunicorn" 2>/dev/null | awk '{print $1}')
    ok "SELinux labels applied. gunicorn context: ${GUNICORN_CTX:-unknown}"
else
    warn "semanage not available; SELinux labelling skipped."
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  12. systemd cybercavalry.service                                    ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "12/13 systemd service"
cp "$INSTALL_DIR/deploy/cybercavalry.service" /etc/systemd/system/${SERVICE_NAME}.service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null

# Firewall (when firewalld is present)
if systemctl is-active firewalld >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${HTTPS_PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null
    ok "Firewall: $HTTPS_PORT/tcp opened."
else
    info "firewalld inactive — firewall configuration skipped."
fi

systemctl restart "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "${SERVICE_NAME}.service is running."
else
    err "${SERVICE_NAME} failed to start. Last logs:"
    journalctl -u "$SERVICE_NAME" -n 40 --no-pager
    exit 1
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  13. Summary                                                         ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "13/13 Installation complete"
SERVER_IP=$(hostname -I | awk '{print $1}')

echo
echo "  ${BOLD}${GREEN}Access:${RESET}      https://${SERVER_IP}:${HTTPS_PORT}/"
echo
echo "  ${BOLD}Service commands:${RESET}"
echo "    sudo systemctl status   $SERVICE_NAME"
echo "    sudo systemctl restart  $SERVICE_NAME"
echo "    sudo journalctl -u $SERVICE_NAME -f"
echo
echo "  ${BOLD}${YELLOW}Final step — create the superuser (manual, interactive):${RESET}"
echo "    sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/python \\"
echo "        $INSTALL_DIR/manage.py createsuperuser"
echo
