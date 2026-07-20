#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
#  CYBER Cavalry — Debian / Ubuntu Offline Installer
#
#  Prerequisites (manual):
#    1. python3 (3.9, 3.11 or 3.12) and the unzip .deb packages installed
#    2. (Optional) redis-server .deb installed — otherwise the
#       DatabaseCache fallback is used
#    3. The release zip placed under $ZIP_SOURCE
#    4. The cavalry user is preserved if it exists; otherwise it is created
#
#  Tested on:
#    - Debian 12 (bookworm)   — Python 3.11 native
#    - Debian 13 (trixie)     — Python 3.11+ / 3.12
#    - Ubuntu 22.04 (jammy)   — Python 3.10 native, 3.11 via deadsnakes PPA
#    - Ubuntu 24.04 (noble)   — Python 3.12 native
#
#  Differences vs. install_rhel.sh:
#    - Uses apt instead of dnf
#    - No SELinux labelling (Debian uses AppArmor, default profile is fine)
#    - ufw instead of firewalld
#    - Service user shell is /usr/sbin/nologin (Debian convention)
#    - Redis service name is redis-server on Debian (redis on RHEL)
#
#  Usage:
#    sudo bash deploy/linux/install_debian.sh
#
#  Note — if you get a CRLF error: sudo apt install -y dos2unix; dos2unix install_debian.sh
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
    err "python3 not found. Install it first with 'apt install python3 python3-venv' (or the offline .deb packages)."
    exit 1
fi

if ! command -v unzip >/dev/null 2>&1; then
    err "unzip not found. Install it with 'apt install unzip'."
    exit 1
fi

# python3-venv is a separate package on Debian/Ubuntu — check it's present
if ! python3 -c "import venv" >/dev/null 2>&1; then
    err "python3-venv module missing. Install with: apt install python3-venv"
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
step "1/12 Service user: $SERVICE_USER"
if id "$SERVICE_USER" >/dev/null 2>&1; then
    info "$SERVICE_USER already exists; leaving it untouched."
else
    useradd --system --home-dir "$INSTALL_DIR" \
        --shell /usr/sbin/nologin \
        --comment "CYBER Cavalry service user" "$SERVICE_USER"
    ok "$SERVICE_USER created."
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  2. Wipe the previous install and stage the new zip                  ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "2/12 Remove the previous install"
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
step "3/12 Extract the zip"
unzip -q "$ZIP_FILE" -d /data/
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
step "4/12 Ownership and permissions"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 750 \
    "$INSTALL_DIR/logs" "$INSTALL_DIR/certs"
ok "Permissions set."


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  5. Python version detection                                         ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "5/12 Python version and wheel set"
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
step "6/12 Create venv and install dependencies"
rm -rf "$INSTALL_DIR/venv"
sudo -u "$SERVICE_USER" python3 -m venv "$INSTALL_DIR/venv"

sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install \
    --no-index --find-links "$WHEELS_DIR/" --upgrade pip >/dev/null

sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install \
    --no-index --find-links "$WHEELS_DIR/" \
    -r "$INSTALL_DIR/requirements.txt" gunicorn

PKG_COUNT=$(sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" list --format=freeze | wc -l)
ok "Dependencies installed ($PKG_COUNT packages)."


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  7. .env configuration                                               ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "7/12 .env"
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
    FIELD_KEY=$(_gen_key)

    SERVER_IP=$(hostname -I | awk '{print $1}')

    # Decide the REDIS_URL line based on whether redis-server is installed
    if [[ "$USE_REDIS_IF_AVAILABLE" == "true" ]] && dpkg -l redis-server 2>/dev/null | grep -q '^ii'; then
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
step "8/12 SSL certificate"
if [[ -f "$INSTALL_DIR/certs/cert.pem" ]] && [[ -f "$INSTALL_DIR/certs/key.pem" ]]; then
    info "Certificates already present; leaving them untouched."
else
    if [[ -f fullchain.pem ]] && [[ -f privkey.pem ]]; then
        install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 644 \
            fullchain.pem "$INSTALL_DIR/certs/cert.pem"
        install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 600 \
            privkey.pem   "$INSTALL_DIR/certs/key.pem"
        ok "CA certificates installed."
    else
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
step "9/12 Database, cache, seed, static"
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
# ║  10. Redis (local only — if the .deb is already installed)           ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "10/12 Redis (local only)"
if dpkg -l redis-server 2>/dev/null | grep -q '^ii'; then
    systemctl enable --now redis-server
    sleep 1
    if redis-cli ping 2>/dev/null | grep -q PONG; then
        BIND=$(grep -E '^bind' /etc/redis/redis.conf | head -1)
        ok "Redis is running (PONG). Config: ${BIND:-bind not set}"
    else
        warn "Redis package installed but PONG not received. Check with systemctl status redis-server."
    fi
else
    warn "redis-server package not installed. The DatabaseCache fallback in .env is active."
fi


# ╔══════════════════════════════════════════════════════════════════════╗
# ║  11. systemd cybercavalry.service                                    ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "11/12 systemd service"
cp "$INSTALL_DIR/deploy/linux/cybercavalry.service" /etc/systemd/system/${SERVICE_NAME}.service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null

# Firewall — prefer ufw on Debian/Ubuntu; fall back to nftables/iptables direct
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "${HTTPS_PORT}/tcp" >/dev/null 2>&1 || true
    ok "Firewall: TCP/$HTTPS_PORT opened via ufw."
elif command -v ufw >/dev/null 2>&1; then
    info "ufw installed but inactive — firewall rule staged; run 'ufw enable' to activate."
    ufw allow "${HTTPS_PORT}/tcp" >/dev/null 2>&1 || true
else
    info "ufw not installed — configure your firewall manually to allow TCP/$HTTPS_PORT."
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
# ║  12. Summary                                                         ║
# ╚══════════════════════════════════════════════════════════════════════╝
step "12/12 Installation complete"
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
