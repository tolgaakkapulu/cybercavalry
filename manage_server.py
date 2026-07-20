#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CYBER Cavalry -- Management CLI
Unified installer, starter and server-management helper.

Usage:
  python manage_server.py setup          # First-time setup
  python manage_server.py start          # Start the server
  python manage_server.py start --port 9443 --host 127.0.0.1
  python manage_server.py clean          # Reset the deployment
  python manage_server.py clean --full   # Reset including the venv
"""

import sys
import os
import re
import ssl
import shutil
import secrets
import string
import zipfile
import argparse
import subprocess
from datetime import date
from pathlib import Path

# ── UTF-8 output (Windows terminal compatibility) ───────────
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cybercavalry.settings.base")

# ── Colour constants ─────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

OK   = "[OK]"
FAIL = "[!!]"
SKIP = "[--]"


def log(msg, color=RESET):
    print(f"{color}{msg}{RESET}", flush=True)


def run(cmd, check=True):
    result = subprocess.run(cmd, shell=True, cwd=BASE_DIR)
    if check and result.returncode != 0:
        log(f"\n{FAIL} Command failed: {cmd}", RED)
        log("Aborting.", RED)
        sys.exit(1)
    return result.returncode == 0


def venv_python():
    return str(BASE_DIR / "venv" / "Scripts" / "python.exe")


def header(title):
    print()
    log("=" * 55, BOLD)
    log(f"  CYBER Cavalry -- {title}", CYAN + BOLD)
    log("=" * 55, BOLD)
    print()


def pause():
    try:
        input("Press Enter to exit...")
    except EOFError:
        pass


# ════════════════════════════════════════════════════════════
#  SETUP
# ════════════════════════════════════════════════════════════

def find_python():
    candidates = [
        Path(os.environ.get("USERPROFILE", "")) / "AppData/Roaming/uv/python/cpython-3.14.3-windows-x86_64-none/python.exe",
        Path(os.environ.get("USERPROFILE", "")) / "AppData/Roaming/uv/python/cpython-3.13.0-windows-x86_64-none/python.exe",
        Path("C:/Python312/python.exe"),
        Path("C:/Python311/python.exe"),
        Path("C:/Python310/python.exe"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    result = subprocess.run("python --version", shell=True, capture_output=True, text=True)
    if result.returncode == 0 and "Python 3" in result.stdout + result.stderr:
        return "python"
    return None


def cmd_setup(_args):
    header("Setup")

    # 1 - Locate Python
    log("[1/7] Locating Python interpreter...", CYAN)
    python = find_python()
    if not python:
        log(f"{FAIL} Python 3.10+ not found. Install Python and try again.", RED)
        sys.exit(1)
    log(f"  {OK} Using: {python}", GREEN)

    py      = venv_python()
    pip_cmd = f'"{py}" -m pip'

    # 2 - venv
    print()
    log("[2/7] Creating virtual environment...", CYAN)
    venv_dir = BASE_DIR / "venv"
    # A venv is only valid if it has pyvenv.cfg. A leftover/half-created dir
    # (e.g. interrupted setup) makes python.exe fail with "failed to locate
    # pyvenv.cfg" — detect that and rebuild from scratch.
    if venv_dir.exists() and (venv_dir / "pyvenv.cfg").exists():
        log(f"  {SKIP} venv already exists, skipping.", YELLOW)
    else:
        if venv_dir.exists():
            log(f"  {SKIP} Existing venv is incomplete (no pyvenv.cfg) — recreating.", YELLOW)
            shutil.rmtree(venv_dir, ignore_errors=True)
        run(f'"{python}" -m venv venv')
        log(f"  {OK} venv created.", GREEN)

    # Ensure pip is present and healthy (repairs broken/partial pip installs).
    # ensurepip re-bootstraps pip from the stdlib if it is missing or corrupt.
    run(f'"{py}" -m ensurepip --upgrade --default-pip', check=False)
    run(f'{pip_cmd} install --upgrade pip', check=False)

    # 3 - Bagimliliklar
    print()
    log("[3/7] Installing dependencies...", CYAN)
    run(f'{pip_cmd} install -r requirements.txt')
    log(f"  {OK} Dependencies installed.", GREEN)

    # 4 - .env
    print()
    log("[4/7] Configuring .env file...", CYAN)
    env_file    = BASE_DIR / ".env"
    env_example = BASE_DIR / ".env.example"
    if env_file.exists():
        log(f"  {SKIP} .env already exists, skipping.", YELLOW)
    elif env_example.exists():
        shutil.copy(env_example, env_file)
        log(f"  {OK} .env created from .env.example.", GREEN)
    else:
        log(f"  {SKIP} .env.example not found; skipping.", YELLOW)

    # Generate SECRET_KEY and FIELD_ENCRYPTION_KEY ONLY if missing/empty.
    # Overwriting an existing SECRET_KEY invalidates sessions; overwriting
    # FIELD_ENCRYPTION_KEY makes stored encrypted secrets (API keys, LDAP
    # password) permanently undecryptable. So we preserve whatever is set.
    if env_file.exists():
        env_text = env_file.read_text(encoding='utf-8')
        chars = string.ascii_letters + string.digits + '!@#$%^&*(-_=+)'

        def _ensure_key(text, name):
            m = re.search(rf'^{name}=(.*)$', text, re.MULTILINE)
            if m and m.group(1).strip():
                return text, False  # already set — keep it
            new_val = ''.join(secrets.choice(chars) for _ in range(64))
            if m:
                text = re.sub(rf'^{name}=.*$', f'{name}={new_val}', text, flags=re.MULTILINE)
            else:
                text = f'{name}={new_val}\n' + text
            return text, True

        env_text, sk_new = _ensure_key(env_text, 'SECRET_KEY')
        env_text, fk_new = _ensure_key(env_text, 'FIELD_ENCRYPTION_KEY')
        env_file.write_text(env_text, encoding='utf-8')
        log(f"  {OK} SECRET_KEY {'generated' if sk_new else 'preserved'}.", GREEN)
        log(f"  {OK} FIELD_ENCRYPTION_KEY {'generated' if fk_new else 'preserved'}.", GREEN)

    # 5 - Migration
    print()
    log("[5/7] Running database migrations...", CYAN)
    run(f'"{py}" manage.py makemigrations')
    run(f'"{py}" manage.py migrate')
    # DatabaseCache table (used when REDIS_URL is not set). Idempotent.
    run(f'"{py}" manage.py createcachetable', check=False)
    log(f"  {OK} Migrations applied.", GREEN)

    # 6 - Seed
    print()
    log("[6/7] Seeding initial data (roles, groups, settings)...", CYAN)
    ok = run(f'"{py}" manage.py seed_initial_data', check=False)
    if ok:
        log(f"  {OK} Initial data seeded.", GREEN)
    else:
        log(f"  {SKIP} seed_initial_data failed or not found; skipping.", YELLOW)

    # 7 - SSL
    print()
    log("[7/7] SSL certificate...", CYAN)
    cert = BASE_DIR / "certs" / "cert.pem"
    if cert.exists():
        log(f"  {SKIP} Certificate already exists, skipping.", YELLOW)
    else:
        run(f'"{py}" generate_cert.py', check=False)
        log(f"  {OK} Self-signed certificate generated.", GREEN)

    # + Static
    print()
    log("[+]  Collecting static files...", CYAN)
    run(f'"{py}" manage.py collectstatic --noinput')
    log(f"  {OK} Static files collected.", GREEN)

    # Ozet
    print()
    log("=" * 55, BOLD)
    log("  Setup complete!", GREEN + BOLD)
    log("=" * 55, BOLD)
    log("", RESET)
    log("  Create an admin user:", RESET)
    log(f"    {py} manage.py createsuperuser", BOLD)
    log("", RESET)
    log("  Start the server:", RESET)
    log("    python manage_server.py start", BOLD)
    log("", RESET)
    log("  Then open: https://localhost:8443", CYAN)
    log("=" * 55, BOLD)
    print()
    pause()


# ════════════════════════════════════════════════════════════
#  START
# ════════════════════════════════════════════════════════════

def cmd_start(args):
    header("Starting Server")

    py = Path(venv_python())
    if not py.exists():
        log(f"{FAIL} Virtual environment not found.", RED)
        log("  Run: python manage_server.py setup", YELLOW)
        sys.exit(1)

    cert_path = BASE_DIR / args.cert
    key_path  = BASE_DIR / args.key

    # Generate an SSL certificate if none is present
    if not cert_path.exists() or not key_path.exists():
        log("SSL certificates not found. Generating self-signed certificate...", YELLOW)
        run(f'"{py}" generate_cert.py', check=False)

    log(f"  {OK} Starting HTTPS server on https://{args.host}:{args.port}", GREEN)
    log("  Press Ctrl+C to stop.", YELLOW)
    print()

    # Start the Django SSL server directly
    try:
        sys.path.insert(0, str(BASE_DIR))
        # Add the venv site-packages
        import site
        venv_site = BASE_DIR / "venv" / "Lib" / "site-packages"
        if venv_site.exists():
            site.addsitedir(str(venv_site))

        from django.core.management import call_command
        import django
        django.setup()

        from django.core.servers.basehttp import WSGIServer

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        class SecureWSGIServer(WSGIServer):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.socket = ssl_context.wrap_socket(self.socket, server_side=True)

        import django.core.servers.basehttp as basehttp
        basehttp.WSGIServer = SecureWSGIServer

        call_command("runserver", f"{args.host}:{args.port}", "--noreload", "--insecure")

    except KeyboardInterrupt:
        print()
        log("  Server stopped.", YELLOW)

    print()
    pause()


# ════════════════════════════════════════════════════════════
#  CLEAN
# ════════════════════════════════════════════════════════════

def remove(path: Path, label: str):
    if path.exists():
        shutil.rmtree(path) if path.is_dir() else path.unlink()
        log(f"  {OK} Removed: {label}", GREEN)
    else:
        log(f"  {SKIP} Skipped (not found): {label}", YELLOW)


def cmd_clean(args):
    header("Cleanup & Reset")

    # 1 - Python cache
    log("[1/7] Removing Python cache files...", CYAN)
    for pycache in BASE_DIR.rglob("__pycache__"):
        if "venv" not in str(pycache):
            shutil.rmtree(pycache, ignore_errors=True)
    for pyc in BASE_DIR.rglob("*.pyc"):
        if "venv" not in str(pyc):
            pyc.unlink(missing_ok=True)
    log(f"  {OK} Done", GREEN)

    # 2 - Veritabani
    log("[2/7] Removing database...", CYAN)
    remove(BASE_DIR / "cybercavalry.db", "cybercavalry.db")

    # 3 - Dosya cache
    log("[3/7] Clearing file cache...", CYAN)
    remove(BASE_DIR / ".cache", ".cache/")

    # 4 - Static dosyalar
    log("[4/7] Removing collected staticfiles...", CYAN)
    remove(BASE_DIR / "staticfiles", "staticfiles/")

    # 5 - Log dosyalari
    log("[5/7] Removing log files...", CYAN)
    removed_logs = False
    for lf in list(BASE_DIR.glob("*.log")) + list(BASE_DIR.glob("logs/**/*.log")):
        lf.unlink(missing_ok=True)
        log(f"  {OK} Removed: {lf.relative_to(BASE_DIR)}", GREEN)
        removed_logs = True
    if not removed_logs:
        log(f"  {SKIP} No log files found.", YELLOW)

    # 6 - Sertifikalar (opsiyonel)
    if args.full:
        log("[6/7] Removing SSL certificates (--full)...", CYAN)
        certs_path = BASE_DIR / "certs"
        removed_certs = False
        for cert_file in ["cert.pem", "key.pem"]:
            f = certs_path / cert_file
            if f.exists():
                f.unlink()
                log(f"  {OK} Removed: certs/{cert_file}", GREEN)
                removed_certs = True
        if not removed_certs:
            log(f"  {SKIP} No certificates found.", YELLOW)
    else:
        log("[6/7] Keeping SSL certificates (use --full to also remove them)", YELLOW)

    # 7 - venv (opsiyonel)
    if args.full:
        log("[7/7] Removing virtual environment (--full)...", CYAN)
        venv_path = BASE_DIR / "venv"
        if venv_path.exists():
            # We cannot delete the venv while this process is still using it.
            # A background job launched with the system Python removes it after a 3 s delay.
            system_python = find_python() or sys.executable
            delete_cmd = (
                f'import time, shutil, pathlib; '
                f'time.sleep(3); '
                f'p = pathlib.Path(r"{venv_path}"); '
                f'shutil.rmtree(p, ignore_errors=True); '
                f'print("[OK] venv removed.")'
            )
            subprocess.Popen(
                [system_python, "-c", delete_cmd],
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )
            log(f"  {OK} venv will be removed in ~3 seconds after exit.", GREEN)
        else:
            log(f"  {SKIP} venv not found, skipping.", YELLOW)
    else:
        log("[7/7] Keeping venv (use --full to also remove it)", YELLOW)

    # Migration + Seed
    if not args.full:
        py = venv_python()
        print()
        log("Applying migrations to fresh database...", CYAN)
        ok = run(f'"{py}" manage.py migrate --run-syncdb', check=False)
        if ok:
            log(f"  {OK} Migrations applied.", GREEN)
        else:
            log(f"  {FAIL} Migration failed. Run manually: manage.py migrate", RED)
        # DatabaseCache table (used when REDIS_URL is not set). Idempotent.
        run(f'"{py}" manage.py createcachetable', check=False)

        log("Seeding initial data...", CYAN)
        ok = run(f'"{py}" manage.py seed_initial_data', check=False)
        if ok:
            log(f"  {OK} Initial data seeded.", GREEN)
        else:
            log(f"  {SKIP} seed_initial_data not found or failed; skipping.", YELLOW)

    # Ozet
    print()
    log("=" * 55, BOLD)
    log("  Reset complete. Next steps:", CYAN + BOLD)
    log("=" * 55, BOLD)
    if args.full:
        log("  0. python manage_server.py setup   (venv yeniden kurulur)", YELLOW)
    log("  1. venv\\Scripts\\python.exe manage.py createsuperuser", RESET)
    log("  2. python manage_server.py start", RESET)
    print()
    pause()


# ════════════════════════════════════════════════════════════
#  RELEASE
# ════════════════════════════════════════════════════════════

_ZIP_EXCLUDE_DIRS = {
    'venv', '.venv', 'env',
    '__pycache__',
    '.git', '.github',
    'staticfiles',
    'VERSIONS',
    'certs',
    'node_modules',
}

_ZIP_EXCLUDE_SUFFIXES = {
    '.pyc', '.pyo', '.pyd',
    '.log',
    '.db', '.sqlite3',
    '.zip',
}

_ZIP_EXCLUDE_FILES = {
    '.env',
    '.DS_Store',
    'Thumbs.db',
}


def _release_clean(base_dir: Path) -> None:
    """Remove __pycache__, .pyc files, staticfiles/ and logs/ — non-destructive clean."""
    log("[1/3] Removing Python cache files...", CYAN)
    removed_dirs = removed_files = 0
    for pycache in base_dir.rglob("__pycache__"):
        if "venv" not in str(pycache):
            shutil.rmtree(pycache, ignore_errors=True)
            removed_dirs += 1
    for pyc in base_dir.rglob("*.pyc"):
        if "venv" not in str(pyc):
            pyc.unlink(missing_ok=True)
            removed_files += 1
    log(f"  {OK} Removed {removed_dirs} __pycache__ dirs, {removed_files} .pyc files.", GREEN)

    log("[2/3] Removing collected staticfiles...", CYAN)
    static_root = base_dir / "staticfiles"
    if static_root.exists():
        shutil.rmtree(static_root, ignore_errors=True)
        log(f"  {OK} staticfiles/ removed.", GREEN)
    else:
        log(f"  {SKIP} staticfiles/ not found.", YELLOW)

    log("[3/3] Removing log files...", CYAN)
    count = 0
    for lf in list(base_dir.glob("*.log")) + list(base_dir.glob("logs/**/*.log")):
        lf.unlink(missing_ok=True)
        count += 1
    log(f"  {OK} {count} log file(s) removed.", GREEN)


_VERSION_FILE   = 'VERSION'
_DEFAULT_VERSION = '1.0.0'


def _read_version_file(base_dir: Path) -> str:
    """Read <BASE_DIR>/VERSION, falling back to '1.0.0' if missing/invalid."""
    try:
        raw = (base_dir / _VERSION_FILE).read_text(encoding='utf-8').strip()
        if re.match(r'^\d+\.\d+\.\d+$', raw):
            return raw
    except OSError:
        pass
    return _DEFAULT_VERSION


def _write_version_file(base_dir: Path, version: str) -> None:
    """Write the version string (with trailing newline) to <BASE_DIR>/VERSION."""
    (base_dir / _VERSION_FILE).write_text(version + '\n', encoding='utf-8')


def _bump_version(version: str, part: str) -> str:
    """Return semver-bumped version. part ∈ {patch, minor, major}."""
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)$', version)
    if not m:
        major, minor, patch = 1, 0, 0
    else:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if part == 'major':
        major += 1; minor = 0; patch = 0
    elif part == 'minor':
        minor += 1; patch = 0
    else:
        patch += 1
    return f'{major}.{minor}.{patch}'


def _get_platform_info(base_dir: Path):
    """Try to read platform_name/version. Name from Django DB if reachable,
    version from <BASE_DIR>/VERSION (managed by `release` command)."""
    version = _read_version_file(base_dir)
    try:
        venv_site = base_dir / "venv" / "Lib" / "site-packages"
        if venv_site.exists():
            import site as _site
            _site.addsitedir(str(venv_site))
        sys.path.insert(0, str(base_dir))
        import django
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cybercavalry.settings.base")
        django.setup()
        from apps.settings_app.cache import SettingsCache
        primary = SettingsCache.get('general.platform_name', 'CYBER') or 'CYBER'
        suffix  = SettingsCache.get('general.platform_name_suffix', 'Cavalry') or 'Cavalry'
        return primary + suffix, version
    except Exception:
        return 'CYBERCavalry', version


def _next_sequence(versions_dir: Path, name: str, version: str, today: str) -> int:
    prefix   = f'{name}_v{version}_{today}_'
    existing = [f.name for f in versions_dir.glob(f'{prefix}*.zip')]
    if not existing:
        return 1
    numbers = []
    for fname in existing:
        m = re.search(r'_(\d+)\.zip$', fname)
        if m:
            numbers.append(int(m.group(1)))
    return max(numbers, default=0) + 1


def _generate_secret_key() -> str:
    chars = string.ascii_letters + string.digits + '!@#$%^&*(-_=+)'
    return ''.join(secrets.choice(chars) for _ in range(64))


def _build_env_content(base_dir: Path) -> str:
    """
    Build the .env shipped inside a release zip (for a FRESH install).

    Generates fresh, independent SECRET_KEY and FIELD_ENCRYPTION_KEY values.
    NOTE: updates to an existing install must NOT use this .env — update_rhel.sh
    preserves the live .env (and its keys) so encrypted secrets stay decryptable.
    """
    env_file = base_dir / '.env'
    if env_file.exists():
        text = env_file.read_text(encoding='utf-8')
    else:
        text = (
            "SECRET_KEY=\n"
            "DEBUG=False\n"
            "ALLOWED_HOSTS=*\n"
        )

    def _set_key(text, name):
        new_val = _generate_secret_key()
        if re.search(rf'^{name}=', text, re.MULTILINE):
            return re.sub(rf'^{name}=.*$', f'{name}={new_val}', text, flags=re.MULTILINE)
        return f'{name}={new_val}\n' + text

    text = _set_key(text, 'SECRET_KEY')
    text = _set_key(text, 'FIELD_ENCRYPTION_KEY')
    return text


def _create_zip(base_dir: Path, out_path: Path) -> int:
    project_root = base_dir.relative_to(base_dir.parent)  # e.g. "CYBERCavalry"
    added = 0
    with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        # Project files
        for root, dirs, files in os.walk(base_dir, topdown=True):
            root_path = Path(root)
            dirs[:] = [
                d for d in dirs
                if d not in _ZIP_EXCLUDE_DIRS and not d.startswith('.')
            ]
            for filename in files:
                file_path = root_path / filename
                if (file_path.suffix.lower() in _ZIP_EXCLUDE_SUFFIXES
                        or filename in _ZIP_EXCLUDE_FILES
                        or filename.startswith('.')):
                    continue
                arcname = file_path.relative_to(base_dir.parent)
                zf.write(file_path, arcname)
                added += 1

        # Empty certs/ and logs/ directory entries (compatible with Python < 3.11)
        for empty_dir in ('certs', 'logs'):
            dir_arcname = str(project_root / empty_dir) + '/'
            try:
                zf.mkdir(dir_arcname.rstrip('/'))
            except AttributeError:
                # Python < 3.11: write an empty directory entry manually
                info = zipfile.ZipInfo(dir_arcname)
                zf.writestr(info, '')

        # Fresh .env with new SECRET_KEY
        env_content = _build_env_content(base_dir)
        zf.writestr(str(project_root / '.env'), env_content)

    return added


def cmd_release(_args):
    header("Release")

    # Step 1 — Clean temp files
    log("Cleaning project tree...", CYAN)
    _release_clean(BASE_DIR)

    # Step 2 — Bump version (unless --no-bump)
    print()
    log("Version bump...", CYAN)
    current_version = _read_version_file(BASE_DIR)
    no_bump = getattr(_args, 'no_bump', False)
    bump_part = getattr(_args, 'bump', 'patch')
    if no_bump:
        new_version = current_version
        log(f"  {SKIP} --no-bump set; packaging current {current_version} as-is.", YELLOW)
    else:
        new_version = _bump_version(current_version, bump_part)
        _write_version_file(BASE_DIR, new_version)
        log(f"  {OK} Version bumped: {current_version} -> {new_version} ({bump_part})", GREEN)

    # Step 3 — Determine archive name
    print()
    log("Reading platform info...", CYAN)
    platform_name, platform_version = _get_platform_info(BASE_DIR)
    platform_version = new_version  # honour the just-written value, ignore DB-cached one
    today        = date.today().strftime('%Y.%m.%d')
    versions_dir = BASE_DIR.parent / 'VERSIONS'
    if not versions_dir.exists():
        versions_dir.mkdir(parents=True, exist_ok=True)
        log(f"  {OK} Created VERSIONS/ directory at {versions_dir}.", GREEN)
    else:
        log(f"  {SKIP} VERSIONS/ already exists at {versions_dir}.", YELLOW)
    n        = _next_sequence(versions_dir, platform_name, platform_version, today)
    filename = f'{platform_name}_v{platform_version}_{today}_{n}.zip'
    out_path = versions_dir / filename
    log(f"  {OK} Archive name: {filename}", GREEN)

    # Step 3 — Create zip
    print()
    log("Creating zip archive...", CYAN)
    added    = _create_zip(BASE_DIR, out_path)
    size_mb  = out_path.stat().st_size / 1024 / 1024
    log(f"  {OK} {added} files  |  {size_mb:.1f} MB", GREEN)
    log(f"  {OK} Included: certs/ (empty),  logs/ (empty),  .env (fresh SECRET_KEY)", GREEN)

    print()
    log("=" * 55, BOLD)
    log(f"  Release ready: VERSIONS/{filename}", GREEN + BOLD)
    log("=" * 55, BOLD)
    print()
    pause()


# ════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="manage_server.py",
        description="CYBER Cavalry -- Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Commands:\n"
            "  setup              First-time setup\n"
            "  start              Start the HTTPS server\n"
            "  clean              Reset the deployment\n"
            "  release            Build a project zip archive (into VERSIONS/)\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    sub.add_parser("setup", help="First-time setup")

    # start
    p_start = sub.add_parser("start", help="Start the HTTPS server")
    p_start.add_argument("--host", default="0.0.0.0")
    p_start.add_argument("--port", type=int, default=8443)
    p_start.add_argument("--cert", default="certs/cert.pem")
    p_start.add_argument("--key",  default="certs/key.pem")

    # clean
    p_clean = sub.add_parser("clean", help="Reset the deployment")
    p_clean.add_argument("--full", action="store_true",
                         help="Delete everything including the venv")

    # release
    p_release = sub.add_parser("release", help="Build a project zip archive (into VERSIONS/)")
    p_release.add_argument(
        "--bump", choices=["patch", "minor", "major"], default="patch",
        help="Which semver component to bump in the VERSION file (default: patch).",
    )
    p_release.add_argument(
        "--no-bump", action="store_true",
        help="Skip the version bump; package the archive at the current VERSION.",
    )

    args = parser.parse_args()

    commands = {
        "setup":   cmd_setup,
        "start":   cmd_start,
        "clean":   cmd_clean,
        "release": cmd_release,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
