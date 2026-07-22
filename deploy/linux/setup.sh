#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  CYBERCavalry — Linux setup (RHEL + Debian / Ubuntu)
#
#  Usage:
#    sudo bash deploy/linux/setup.sh install [OPTIONS]    # fresh install
#    sudo bash deploy/linux/setup.sh update  [OPTIONS]    # in-place upgrade
#
#  Options (every parameter has a sane default -- override as needed):
#    --install-dir  PATH   Install/deployment directory  (default: /data/cybercavalry)
#    --zip-source   PATH   Directory to look for release .zip  (default: /home/cavalry.svc)
#    --rollback-dir PATH   Where update snapshots land  (default: /data/rollback)
#    --https-port   N      TLS listening port  (default: 8443)
#    --service-user NAME   System user that runs the service  (default: cavalry)
#    --service-name NAME   systemd unit name  (default: cybercavalry)
#    --reinstall-deps      Force pip install during update (default: skipped
#                          -- venv already has every package needed for
#                          runtime; only pass this when requirements.txt
#                          actually gained/dropped a package).
#
#  Prerequisites (install once, before running this script):
#    - python3.9+ (with python3-venv on Debian family) and unzip
#    - a CYBERCavalry_v*.zip inside --zip-source
#
#  Examples:
#    sudo bash deploy/linux/setup.sh install
#    sudo bash deploy/linux/setup.sh install --install-dir /opt/cybercavalry --zip-source /tmp
#    sudo bash deploy/linux/setup.sh update  --install-dir /opt/cybercavalry --zip-source /tmp
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults (overridable via --flag) ──────────────────────────────
INSTALL_DIR="/data/cybercavalry"
SERVICE_USER="cavalry"
SERVICE_NAME="cybercavalry"
HTTPS_PORT=8443
ZIP_SOURCE="/home/cavalry.svc"
ROLLBACK_DIR="/data/rollback"
# Update flow only calls pip when the user asks for it (--reinstall-deps) or
# the venv is genuinely broken. Runtime doesn't need wheels -- the packages
# already live under venv/lib/site-packages -- so skipping pip is the safe
# default for offline production boxes.
REINSTALL_DEPS="no"

# ── Helpers ────────────────────────────────────────────────────────
C_INFO=$'\e[96m'; C_OK=$'\e[92m'; C_WARN=$'\e[93m'; C_ERR=$'\e[91m'; C_END=$'\e[0m'
log()  { echo "${C_INFO}[*]${C_END} $*"; }
ok()   { echo "${C_OK}[OK]${C_END} $*"; }
warn() { echo "${C_WARN}[!]${C_END} $*"; }
die()  { echo "${C_ERR}[X]${C_END} $*" >&2; exit 1; }

FAMILY=$(command -v apt >/dev/null 2>&1 && echo debian || echo rhel)

# ── Parse arguments: first positional = command, rest = --flag value pairs
CMD="${1:-}"
shift 2>/dev/null || true

# --help works BEFORE any pre-flight so a non-root user can still discover
# the flags without hitting `Run as root: ...` first.
if [[ "$CMD" == "-h" || "$CMD" == "--help" ]]; then
    sed -n '/^# ─\+$/,/^# ─\+$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)    INSTALL_DIR="$2";    shift 2 ;;
        --install-dir=*)  INSTALL_DIR="${1#*=}";  shift ;;
        --zip-source)     ZIP_SOURCE="$2";     shift 2 ;;
        --zip-source=*)   ZIP_SOURCE="${1#*=}";   shift ;;
        --rollback-dir)   ROLLBACK_DIR="$2";   shift 2 ;;
        --rollback-dir=*) ROLLBACK_DIR="${1#*=}"; shift ;;
        --https-port)     HTTPS_PORT="$2";     shift 2 ;;
        --https-port=*)   HTTPS_PORT="${1#*=}";   shift ;;
        --service-user)   SERVICE_USER="$2";   shift 2 ;;
        --service-user=*) SERVICE_USER="${1#*=}"; shift ;;
        --service-name)   SERVICE_NAME="$2";   shift 2 ;;
        --service-name=*) SERVICE_NAME="${1#*=}"; shift ;;
        --reinstall-deps) REINSTALL_DEPS="yes"; shift ;;
        -h|--help)
            sed -n '/^# ─\+$/,/^# ─\+$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "Unknown option: $1  (see: bash $0 --help)" ;;
    esac
done

# ── Pre-flight ─────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0 $CMD"
case "$CMD" in install|update) ;; *) die "Usage: sudo bash $0 {install|update} [--install-dir PATH] [--zip-source PATH] ...  (or --help)" ;; esac
command -v python3 >/dev/null || die "python3 not installed"
command -v unzip   >/dev/null || die "unzip not installed"

find_zip() { ls -t "$ZIP_SOURCE"/CYBERCavalry_v*.zip 2>/dev/null | head -1; }

# Locate a CYBERCavalry source in one of two modes:
#   zip  -- packaged release zip lives in $ZIP_SOURCE (production airgapped)
#   clone -- script is running from a git checkout (dev/eval flow)
# Writes SOURCE_MODE + SOURCE_PATH; dies if neither is present.
detect_source() {
    local zip; zip=$(find_zip)
    if [[ -n "$zip" ]]; then
        SOURCE_MODE="zip"
        SOURCE_PATH="$zip"
        return
    fi
    local script_dir; script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
    local project_root; project_root="$(cd "$script_dir/../.." 2>/dev/null && pwd || true)"
    if [[ -n "$project_root" && -f "$project_root/requirements.txt" && -d "$project_root/apps" ]]; then
        SOURCE_MODE="clone"
        SOURCE_PATH="$project_root"
        return
    fi
    die "No CYBERCavalry source found. Either drop a CYBERCavalry_v*.zip under $ZIP_SOURCE, or run this script from a git clone (script must live at <root>/deploy/linux/setup.sh)."
}

# ── Shared: venv + offline dependencies ────────────────────────────
# Emit a warning (non-fatal) when requirements.txt hash differs from the last
# successful install. Called from do_update on the "venv OK, no --reinstall-deps"
# path so the operator sees a hint that pip might be needed. The update still
# proceeds -- if imports are actually missing, the service will fail on start.
_warn_if_requirements_changed() {
    local req_file="$INSTALL_DIR/requirements.txt"
    local hash_file="$INSTALL_DIR/venv/.requirements.sha256"
    [[ -f "$req_file" && -f "$hash_file" ]] || return 0
    local current_hash stored_hash
    current_hash=$(sha256sum "$req_file" | awk '{print $1}')
    stored_hash=$(awk '{print $1}' "$hash_file")
    if [[ "$current_hash" != "$stored_hash" ]]; then
        warn "requirements.txt changed since the last install."
        warn "The current venv packages will be used as-is. If a NEW package"
        warn "was added, the service will fail on startup. To refresh packages:"
        warn "    sudo bash $0 update --install-dir $INSTALL_DIR --reinstall-deps"
    fi
}

install_deps() {
    log "install_deps: entering"
    local py="$INSTALL_DIR/venv/bin/python"
    local pip="$INSTALL_DIR/venv/bin/pip"

    if [[ ! -x "$py" ]]; then die "venv python not executable at $py"; fi
    if [[ ! -x "$pip" ]]; then die "venv pip not executable at $pip"; fi

    local req_file="$INSTALL_DIR/requirements.txt"
    local hash_file="$INSTALL_DIR/venv/.requirements.sha256"

    local tag; tag=py$("$py" -c "import sys; print(str(sys.version_info.major)+str(sys.version_info.minor))")
    local wheels="$INSTALL_DIR/deploy/wheels/$tag"
    log "python tag: $tag  |  wheels dir: $wheels"

    # Count *.whl files. Using a simple glob + shopt(nullglob) is more robust
    # than `find -name X -o -name Y` (whose default -print action interacts
    # badly with -o and silently underreports).
    local wheel_count=0
    if [[ -d "$wheels" ]]; then
        shopt -s nullglob
        local wheels_arr=("$wheels"/*.whl "$wheels"/*.tar.gz)
        shopt -u nullglob
        wheel_count=${#wheels_arr[@]}
    fi
    log "wheels found: $wheel_count"

    # Three install strategies (mirrors Windows setup.ps1):
    #   1. Bundle missing/empty       -> install from PyPI (needs internet)
    #   2. Bundle present + complete  -> fully offline
    #   3. Bundle present but partial -> try offline, fall back to PyPI on failure
    if [[ "$wheel_count" -eq 0 ]]; then
        local available; available=$(ls "$INSTALL_DIR/deploy/wheels/" 2>/dev/null | tr '\n' ' ')
        warn "No wheel bundle for $tag (available: ${available:-none}). Falling back to PyPI (needs internet)."
        warn "If this hangs, the box likely has no PyPI connectivity."
        warn "Verify with:  curl -m 5 https://pypi.org/simple/ -o /dev/null -w 'http_code=%{http_code}\\n'"
        # --timeout=30 caps EACH TCP connection at 30s so the script fails
        # fast on air-gapped boxes instead of hanging on default (15min).
        log "upgrading pip via PyPI (timeout=30s per attempt)..."
        sudo -u "$SERVICE_USER" "$pip" install --disable-pip-version-check --timeout=30 --upgrade pip 2>&1 \
            || die "pip upgrade from PyPI failed. Either the box is air-gapped OR the wheel bundle
is missing. Fix by regenerating the bundle on an internet-connected box:
    python deploy/prepare_offline_bundle.py --os linux --py ${tag#py}
Then include deploy/wheels/ in the release zip and rerun update."
        log "installing requirements from PyPI (timeout=30s per attempt)..."
        sudo -u "$SERVICE_USER" "$pip" install --disable-pip-version-check --timeout=30 \
            -r "$INSTALL_DIR/requirements.txt" gunicorn 2>&1 \
            || die "pip install from PyPI failed. See diagnostic above."
        ok "dependencies from PyPI ($tag)"
        sudo -u "$SERVICE_USER" sh -c "sha256sum '$req_file' > '$hash_file'"
        return
    fi

    log "upgrading pip from $tag bundle ($wheel_count wheels)..."
    sudo -u "$SERVICE_USER" "$pip" install --no-index --find-links "$wheels/" \
        --upgrade pip 2>&1 || warn "pip self-upgrade skipped (already up to date, or missing from bundle)"

    log "installing requirements from $tag bundle..."
    if sudo -u "$SERVICE_USER" "$pip" install --no-index --find-links "$wheels/" \
            -r "$INSTALL_DIR/requirements.txt" gunicorn 2>&1; then
        ok "dependencies from $tag (fully offline)"
    else
        warn "offline install incomplete -- retrying with PyPI as fallback"
        sudo -u "$SERVICE_USER" "$pip" install --find-links "$wheels/" \
            -r "$INSTALL_DIR/requirements.txt" gunicorn 2>&1 \
            || die "pip install failed even with PyPI fallback. Check network + package availability."
        ok "dependencies: $tag bundle + PyPI fallback"
    fi
    # Record the requirements hash so next update can short-circuit when
    # nothing changed (see install_deps prologue). Written after a successful
    # install so a failed attempt doesn't leave a stale marker.
    sudo -u "$SERVICE_USER" sh -c "sha256sum '$req_file' > '$hash_file'"
}

create_venv() {
    sudo -u "$SERVICE_USER" python3 -m venv "$INSTALL_DIR/venv"
    install_deps
}

write_env() {
    local py="$INSTALL_DIR/venv/bin/python"
    local k1 k2 host_short host_fqdn ip_list
    k1=$(sudo -u "$SERVICE_USER" "$py" -c "import secrets; print(secrets.token_urlsafe(64))")
    k2=$(sudo -u "$SERVICE_USER" "$py" -c "import secrets; print(secrets.token_urlsafe(64))")
    # Gather every reachable name/IP so the user can hit the box via any of
    # them without Django's 400/DisallowedHost rejecting the request.
    host_short=$(hostname 2>/dev/null || echo "")
    host_fqdn=$(hostname -f 2>/dev/null || echo "")
    # All IPv4 addrs on the box, skipping link-local (169.254.*) and loopback.
    ip_list=$(hostname -I 2>/dev/null | tr ' ' '\n' | \
              grep -Ev '^(169\.254\.|127\.|$)' | sort -u)
    # Build ALLOWED_HOSTS: localhost + loopback + hostname (short & FQDN) + every IP.
    local allowed_hosts csrf_origins entry
    allowed_hosts="localhost,127.0.0.1"
    csrf_origins="https://localhost:${HTTPS_PORT},https://127.0.0.1:${HTTPS_PORT}"
    for entry in "$host_short" "$host_fqdn"; do
        [[ -n "$entry" && ",$allowed_hosts," != *",$entry,"* ]] && {
            allowed_hosts="$allowed_hosts,$entry"
            csrf_origins="$csrf_origins,https://${entry}:${HTTPS_PORT}"
        }
    done
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        [[ ",$allowed_hosts," != *",$entry,"* ]] && {
            allowed_hosts="$allowed_hosts,$entry"
            csrf_origins="$csrf_origins,https://${entry}:${HTTPS_PORT}"
        }
    done <<< "$ip_list"
    # Full-parameter template matching .env.example -- generated once on
    # fresh install. Delete .env and re-run setup to regenerate.
    sudo -u "$SERVICE_USER" tee "$INSTALL_DIR/.env" >/dev/null <<EOF
# =============================================================
#  CYBERCavalry -- runtime configuration
#  Auto-generated by deploy/linux/setup.sh on first install.
#  Regenerate by deleting this file and re-running setup.
#  NEVER commit .env -- it lives outside git via .gitignore.
# =============================================================

# -- Core Django ----------------------------------------------
SECRET_KEY=$k1
DEBUG=False
ALLOWED_HOSTS=$allowed_hosts
CSRF_TRUSTED_ORIGINS=$csrf_origins
# Set to True when a reverse proxy (nginx/Caddy) terminates TLS in front.
SECURE_SSL_REDIRECT=False

# -- Database (SQLite by default; use postgres://user:pass@host/db in prod)
DATABASE_URL=sqlite:///cybercavalry.db

# -- Encryption key for secret Settings (SMTP/API keys/LDAP pw) --------
# If lost, existing encrypted secrets in the DB cannot be decrypted.
# Treat this key like an HSM key.
FIELD_ENCRYPTION_KEY=$k2

# -- Admin panel path & access -------------------------------
# ADMIN_PATH is loaded from here so the real URL never appears in source.
ADMIN_PATH=admin-console/
ADMIN_ALLOWED_IPS=127.0.0.1,::1

# -- SSL certificates (paths relative to the project root) ---
SSL_CERT_FILE=certs/cert.pem
SSL_KEY_FILE=certs/key.pem

# -- LDAP (optional -- leave LDAP_ENABLED=False to skip) -----
LDAP_ENABLED=False
LDAP_SERVER_URI=ldaps://dc01.example.corp:636
LDAP_BIND_DN=CN=svc-cybercavalry,OU=ServiceAccounts,DC=example,DC=corp
LDAP_BIND_PASSWORD=change-me
LDAP_USER_SEARCH_BASE=OU=Users,DC=example,DC=corp
LDAP_USER_SEARCH_FILTER=(sAMAccountName=%(user)s)
LDAP_USER_ATTR_MAP={"first_name": "givenName", "last_name": "sn", "email": "mail"}
EOF
    chmod 640 "$INSTALL_DIR/.env"
    ok ".env created with fresh keys + full parameter template"
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
    detect_source
    log "install ($FAMILY, python $(python3 -V 2>&1 | awk '{print $2}'), mode $SOURCE_MODE)"

    id "$SERVICE_USER" &>/dev/null || useradd --system \
        --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin \
        --comment "CYBERCavalry" "$SERVICE_USER" 2>/dev/null || \
        useradd --system --home-dir "$INSTALL_DIR" --shell /sbin/nologin \
        --comment "CYBERCavalry" "$SERVICE_USER"

    if [[ "$SOURCE_MODE" == "zip" ]]; then
        rm -rf "$INSTALL_DIR"
        local parent; parent=$(dirname "$INSTALL_DIR")
        mkdir -p "$parent"
        unzip -q "$SOURCE_PATH" -d "$parent/"
        # The zip's top-level folder is always "CYBERCavalry"; rename it into
        # the caller-chosen INSTALL_DIR (basename may differ, e.g.
        # --install-dir /opt/cyberc or /srv/cybercavalry-prod).
        if [[ -d "$parent/CYBERCavalry" && "$parent/CYBERCavalry" != "$INSTALL_DIR" ]]; then
            mv "$parent/CYBERCavalry" "$INSTALL_DIR"
        fi
        ok "extracted to $INSTALL_DIR"
    else
        # Clone mode: source is the git checkout at $SOURCE_PATH. If the
        # user picked --install-dir equal to the checkout, no copy needed
        # (in-place install). Otherwise rsync into INSTALL_DIR while
        # skipping the git/venv/runtime dirs.
        if [[ "$SOURCE_PATH" == "$INSTALL_DIR" ]]; then
            log "clone mode: using $INSTALL_DIR in place"
        else
            log "clone mode: copying $SOURCE_PATH -> $INSTALL_DIR"
            rm -rf "$INSTALL_DIR"
            mkdir -p "$INSTALL_DIR"
            command -v rsync >/dev/null || die "rsync is required for clone mode (dnf/apt install rsync)"
            rsync -a \
                --exclude '.git' --exclude 'venv' --exclude 'logs/*' \
                --exclude 'backups/*' --exclude '__pycache__' \
                --exclude 'staticfiles' --exclude '*.pyc' \
                "$SOURCE_PATH/" "$INSTALL_DIR/"
        fi
    fi
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 \
        "$INSTALL_DIR/logs" "$INSTALL_DIR/certs"

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

    # Substitute the caller-chosen INSTALL_DIR / SERVICE_USER / HTTPS_PORT
    # into the systemd unit before installing it. The template ships with
    # the defaults (/data/cybercavalry, cavalry, 8443); without this a
    # non-default --install-dir would leave gunicorn looking in the wrong
    # place and the service would fail on start.
    sed -e "s|/data/cybercavalry|$INSTALL_DIR|g" \
        -e "s|^User=cavalry$|User=$SERVICE_USER|" \
        -e "s|^Group=cavalry$|Group=$SERVICE_USER|" \
        -e "s|--bind 0.0.0.0:8443|--bind 0.0.0.0:$HTTPS_PORT|" \
        "$INSTALL_DIR/deploy/linux/cybercavalry.service" \
        > "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME" >/dev/null
    sleep 3
    systemctl is-active --quiet "$SERVICE_NAME" || {
        journalctl -u "$SERVICE_NAME" -n 30 --no-pager
        die "service failed to start"
    }

    echo
    ok "install complete"
    echo "    Access:      https://$(hostname -I | awk '{print $1}'):$HTTPS_PORT/"
    echo "    Login:       admin / admin  (change the password immediately in Users)"
    echo "    Service log: sudo journalctl -u $SERVICE_NAME -f"
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
    # Capture stderr so we can show WHY backup_db fell over instead of just
    # silently degrading to "snapshot only". Common causes:
    #   * Postgres DB in use (backup_db supports SQLite only)
    #   * `.env` unreadable by SERVICE_USER
    #   * backup dir has wrong ownership
    # cd first: the DATABASE_URL default `sqlite:///cybercavalry.db` is a
    # relative path -- run from anywhere else and Django can't find the DB.
    local backup_err; backup_err=$(cd "$INSTALL_DIR" && sudo -u "$SERVICE_USER" \
        "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/manage.py" backup_db --force 2>&1 >/dev/null) \
        || warn "app backup_db failed — snapshot only  (reason: ${backup_err:-unknown; check the SERVICE_USER can read .env and write to $INSTALL_DIR/backups})"
    rsync -a --exclude venv --exclude backups "$INSTALL_DIR/" "$rollback/"
    ok "snapshot: $rollback"

    systemctl stop "$SERVICE_NAME" 2>/dev/null || true

    local tmp; tmp=$(mktemp -d)
    unzip -q "$zip" -d "$tmp"
    [[ -d "$tmp/CYBERCavalry" ]] || { rm -rf "$tmp"; die "unexpected zip layout"; }
    # deploy/wheels/ is excluded so an air-gapped target keeps its offline
    # wheel bundle even if the incoming zip's dev machine happens to have
    # an empty wheels/ dir. Regenerate the bundle explicitly with
    # `prepare_offline_bundle.py` when dependencies actually change.
    rsync -a --delete \
        --exclude '.env' --exclude 'venv/' --exclude 'certs/' \
        --exclude 'logs/' --exclude 'backups/' --exclude 'cybercavalry.db*' \
        --exclude 'media/' --exclude 'deploy/wheels/' \
        "$tmp/CYBERCavalry/" "$INSTALL_DIR/"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    rm -rf "$tmp"
    ok "code synced (.env / db / certs / logs preserved)"

    # venv health pre-flight. Three outcomes:
    #   1. venv broken       -> rebuild (needs wheels OR PyPI)
    #   2. --reinstall-deps  -> user asked, run install_deps explicitly
    #   3. venv OK, default  -> SKIP pip entirely. Runtime doesn't need wheels;
    #                           the packages are already under site-packages.
    #                           Warn if requirements.txt hash changed since the
    #                           last install so the user knows to consider
    #                           --reinstall-deps.
    log "checking venv health..."
    if ! sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" --version >/dev/null 2>&1; then
        warn "venv broken — rebuilding (needs wheels bundle OR PyPI access)"
        rm -rf "$INSTALL_DIR/venv"
        log "creating fresh venv..."
        create_venv
    elif [[ "$REINSTALL_DEPS" == "yes" ]]; then
        log "venv OK -- --reinstall-deps passed, running install_deps"
        install_deps
    else
        log "venv OK -- skipping pip (venv already has all runtime packages)"
        _warn_if_requirements_changed
    fi

    cd "$INSTALL_DIR"
    log "running migrations..."
    sudo -u "$SERVICE_USER" ./venv/bin/python manage.py migrate --noinput
    ok "migrations applied"
    log "collecting static files..."
    sudo -u "$SERVICE_USER" ./venv/bin/python manage.py collectstatic --noinput >/dev/null
    ok "static collected"
    apply_selinux

    # Clear compiled Python bytecode so the freshly-started service picks up the
    # new .py files rather than an interpreter-cached .pyc from the prior release.
    # Skip venv/ so we don't invalidate the site-packages caches we just installed.
    # `|| true` because find can print harmless "cannot access ..." warnings
    # when it descends into a __pycache__ we just removed.
    find "$INSTALL_DIR" -name __pycache__ -type d -not -path "*/venv/*" -exec rm -rf {} + 2>/dev/null || true
    ok "bytecode cache cleared"

    # Restart the service. Wrapped in an `if` block so a non-zero exit from
    # systemctl (unit-not-found, unit-masked, permission-denied, etc.) does
    # NOT trigger `set -e` and silently kill the script -- we want to
    # explicitly report the failure with journalctl output.
    log "restarting $SERVICE_NAME..."
    if ! systemctl restart "$SERVICE_NAME" 2>&1; then
        warn "systemctl restart returned non-zero -- trying manual start as fallback..."
        systemctl start "$SERVICE_NAME" 2>&1 || warn "manual start also failed"
    fi
    sleep 3
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        warn "service is not active after restart -- diagnostic dump:"
        systemctl status "$SERVICE_NAME" --no-pager -n 20 || true
        echo "--- journalctl ---"
        journalctl -u "$SERVICE_NAME" -n 40 --no-pager || true
        die "service failed to start. Rollback: sudo rsync -a --delete --exclude venv $rollback/ $INSTALL_DIR/"
    fi
    ok "service restarted (active)"
    ok "update complete (rollback available at $rollback)"
}

case "$CMD" in
    install) do_install ;;
    update)  do_update  ;;
esac
