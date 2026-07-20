#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  CYBERCavalry — Linux setup (RHEL / AlmaLinux / Rocky + Debian / Ubuntu)
#
#  Usage:
#    sudo bash deploy/linux/setup.sh install    # fresh install
#    sudo bash deploy/linux/setup.sh update     # in-place upgrade (keeps .env / db / certs / logs)
#
#  Prerequisites (install once, before running this script):
#    - python3.9+ (with python3-venv on Debian family) and unzip
#    - a CYBERCavalry_v*.zip in ${ZIP_SOURCE}
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────
INSTALL_DIR="/data/cybercavalry"
SERVICE_USER="cavalry"
SERVICE_NAME="cybercavalry"
HTTPS_PORT=8443
ZIP_SOURCE="/home/cavalry.svc"      # where the release .zip lives
ROLLBACK_DIR="/data/rollback"

# ── Helpers ────────────────────────────────────────────────────────
C_INFO=$'\e[96m'; C_OK=$'\e[92m'; C_WARN=$'\e[93m'; C_ERR=$'\e[91m'; C_END=$'\e[0m'
log()  { echo "${C_INFO}[*]${C_END} $*"; }
ok()   { echo "${C_OK}[OK]${C_END} $*"; }
warn() { echo "${C_WARN}[!]${C_END} $*"; }
die()  { echo "${C_ERR}[X]${C_END} $*" >&2; exit 1; }

FAMILY=$(command -v apt >/dev/null 2>&1 && echo debian || echo rhel)
CMD="${1:-}"

# ── Pre-flight ─────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0 $CMD"
case "$CMD" in install|update) ;; *) die "Usage: sudo bash $0 {install|update}" ;; esac
command -v python3 >/dev/null || die "python3 not installed"
command -v unzip   >/dev/null || die "unzip not installed"

find_zip() { ls -t "$ZIP_SOURCE"/CYBERCavalry_v*.zip 2>/dev/null | head -1; }

# ── Shared: venv + offline dependencies ────────────────────────────
install_deps() {
    local py="$INSTALL_DIR/venv/bin/python"
    local pip="$INSTALL_DIR/venv/bin/pip"
    local tag; tag=py$("$py" -c "import sys; print(str(sys.version_info.major)+str(sys.version_info.minor))")
    local wheels="$INSTALL_DIR/deploy/wheels/$tag"
    [[ -d "$wheels" ]] || die "Wheel bundle missing: $wheels"
    sudo -u "$SERVICE_USER" "$pip" install --no-index --find-links "$wheels/" --upgrade pip >/dev/null
    sudo -u "$SERVICE_USER" "$pip" install --no-index --find-links "$wheels/" \
        -r "$INSTALL_DIR/requirements.txt" gunicorn
    ok "dependencies from $tag"
}

create_venv() {
    sudo -u "$SERVICE_USER" python3 -m venv "$INSTALL_DIR/venv"
    install_deps
}

write_env() {
    local py="$INSTALL_DIR/venv/bin/python"
    local k1 k2 ip
    k1=$(sudo -u "$SERVICE_USER" "$py" -c "import secrets; print(secrets.token_urlsafe(64))")
    k2=$(sudo -u "$SERVICE_USER" "$py" -c "import secrets; print(secrets.token_urlsafe(64))")
    ip=$(hostname -I | awk '{print $1}')
    sudo -u "$SERVICE_USER" tee "$INSTALL_DIR/.env" >/dev/null <<EOF
SECRET_KEY=$k1
FIELD_ENCRYPTION_KEY=$k2
DEBUG=False
ALLOWED_HOSTS=$ip,127.0.0.1
SECURE_SSL_REDIRECT=False
ADMIN_ALLOWED_IPS=127.0.0.1,::1
SSL_CERT_FILE=certs/cert.pem
SSL_KEY_FILE=certs/key.pem
EOF
    chmod 640 "$INSTALL_DIR/.env"
    ok ".env created with fresh keys"
}

apply_selinux() {
    [[ "$FAMILY" == "rhel" ]] || return 0
    command -v semanage >/dev/null || return 0
    semanage port -a -t http_port_t -p tcp "$HTTPS_PORT" 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp "$HTTPS_PORT" 2>/dev/null || true
    semanage fcontext -a -t bin_t     "$INSTALL_DIR/venv/bin(/.*)?"    2>/dev/null || true
    semanage fcontext -a -t lib_t     "$INSTALL_DIR/venv/lib(/.*)?"    2>/dev/null || true
    semanage fcontext -a -t lib_t     "$INSTALL_DIR/venv/lib64(/.*)?"  2>/dev/null || true
    semanage fcontext -a -t var_log_t "$INSTALL_DIR/logs(/.*)?"        2>/dev/null || true
    restorecon -R "$INSTALL_DIR/venv" "$INSTALL_DIR/logs" >/dev/null 2>&1 || true
    ok "SELinux labels applied"
}

open_firewall() {
    if [[ "$FAMILY" == "rhel" ]]; then
        systemctl is-active --quiet firewalld && {
            firewall-cmd --permanent --add-port="${HTTPS_PORT}/tcp" >/dev/null 2>&1
            firewall-cmd --reload >/dev/null
            ok "firewalld: TCP/$HTTPS_PORT opened"
        }
    else
        command -v ufw >/dev/null && {
            ufw allow "${HTTPS_PORT}/tcp" >/dev/null 2>&1 || true
            ok "ufw: TCP/$HTTPS_PORT allowed"
        }
    fi
}

# ── install: fresh setup ───────────────────────────────────────────
do_install() {
    log "install ($FAMILY, python $(python3 -V 2>&1 | awk '{print $2}'))"
    local zip; zip=$(find_zip)
    [[ -n "$zip" ]] || die "No CYBERCavalry_v*.zip under $ZIP_SOURCE"

    id "$SERVICE_USER" &>/dev/null || useradd --system \
        --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin \
        --comment "CYBERCavalry" "$SERVICE_USER" 2>/dev/null || \
        useradd --system --home-dir "$INSTALL_DIR" --shell /sbin/nologin \
        --comment "CYBERCavalry" "$SERVICE_USER"

    rm -rf "$INSTALL_DIR"
    unzip -q "$zip" -d /data/
    [[ -d /data/CYBERCavalry ]] && mv /data/CYBERCavalry "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 \
        "$INSTALL_DIR/logs" "$INSTALL_DIR/certs"
    ok "extracted to $INSTALL_DIR"

    create_venv
    write_env

    [[ -f "$INSTALL_DIR/certs/cert.pem" ]] || \
        sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" \
        "$INSTALL_DIR/generate_cert.py"

    cd "$INSTALL_DIR"
    sudo -u "$SERVICE_USER" ./venv/bin/python manage.py migrate --noinput
    sudo -u "$SERVICE_USER" ./venv/bin/python manage.py createcachetable
    sudo -u "$SERVICE_USER" ./venv/bin/python manage.py seed_initial_data 2>/dev/null || true
    sudo -u "$SERVICE_USER" ./venv/bin/python manage.py collectstatic --noinput >/dev/null
    ok "database + static ready"

    apply_selinux
    open_firewall

    cp "$INSTALL_DIR/deploy/linux/cybercavalry.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME" >/dev/null
    sleep 3
    systemctl is-active --quiet "$SERVICE_NAME" || {
        journalctl -u "$SERVICE_NAME" -n 30 --no-pager
        die "service failed to start"
    }

    echo
    ok "install complete"
    echo "    Access:  https://$(hostname -I | awk '{print $1}'):$HTTPS_PORT/"
    echo "    Logs:    sudo journalctl -u $SERVICE_NAME -f"
    echo "    Create superuser:"
    echo "      sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/python $INSTALL_DIR/manage.py createsuperuser"
}

# ── update: refresh code, preserve state ───────────────────────────
do_update() {
    log "update ($FAMILY)"
    [[ -d "$INSTALL_DIR/venv" ]] || die "$INSTALL_DIR/venv missing — run '$0 install' first"
    local zip; zip=$(find_zip)
    [[ -n "$zip" ]] || die "No CYBERCavalry_v*.zip under $ZIP_SOURCE"

    local stamp="$(date +%Y%m%d_%H%M%S)"
    local rollback="$ROLLBACK_DIR/$stamp"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" "$ROLLBACK_DIR"
    mkdir -p "$rollback"
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" \
        "$INSTALL_DIR/manage.py" backup_db --force 2>/dev/null || \
        warn "app backup_db failed — snapshot only"
    rsync -a --exclude venv --exclude backups "$INSTALL_DIR/" "$rollback/"
    ok "snapshot: $rollback"

    systemctl stop "$SERVICE_NAME" 2>/dev/null || true

    local tmp; tmp=$(mktemp -d)
    unzip -q "$zip" -d "$tmp"
    [[ -d "$tmp/CYBERCavalry" ]] || { rm -rf "$tmp"; die "unexpected zip layout"; }
    rsync -a --delete \
        --exclude '.env' --exclude 'venv/' --exclude 'certs/' \
        --exclude 'logs/' --exclude 'backups/' --exclude 'cybercavalry.db*' \
        "$tmp/CYBERCavalry/" "$INSTALL_DIR/"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    rm -rf "$tmp"
    ok "code synced (.env / db / certs / logs preserved)"

    # venv health pre-flight: rebuild if pip is broken (rename bug, shebang rot, etc.)
    if ! sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" --version >/dev/null 2>&1; then
        warn "venv broken — rebuilding"
        rm -rf "$INSTALL_DIR/venv"
        create_venv
    else
        install_deps
    fi

    cd "$INSTALL_DIR"
    sudo -u "$SERVICE_USER" ./venv/bin/python manage.py migrate --noinput
    sudo -u "$SERVICE_USER" ./venv/bin/python manage.py collectstatic --noinput >/dev/null
    apply_selinux

    systemctl start "$SERVICE_NAME"
    sleep 3
    systemctl is-active --quiet "$SERVICE_NAME" || {
        journalctl -u "$SERVICE_NAME" -n 30 --no-pager
        die "service failed — rollback: sudo rsync -a --delete --exclude venv $rollback/ $INSTALL_DIR/"
    }
    ok "update complete (rollback available at $rollback)"
}

case "$CMD" in
    install) do_install ;;
    update)  do_update  ;;
esac
