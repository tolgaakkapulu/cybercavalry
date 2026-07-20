#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBER Cavalry -- Offline Bundle Preparer
=========================================

The target machine has no internet access. This script runs on your own
connected machine (Windows/Linux/macOS) and downloads every Python wheel
required to run CYBER Cavalry into deploy/wheels/<pyXX>/.

Universal bundle: wheel sets for both Python 3.9 (RHEL 9 default) and
Python 3.11 (RHEL 9 AppStream) are prepared in a single pass.

Target:
  - RHEL 9.x (glibc 2.34)
  - Python 3.9 or 3.11
  - x86_64

Usage:
  python deploy/prepare_offline_bundle.py             # Both 3.9 and 3.11
  python deploy/prepare_offline_bundle.py --py 39     # 3.9 only
  python deploy/prepare_offline_bundle.py --py 311    # 3.11 only

Outputs:
  deploy/wheels/py39/         -- Wheels for Python 3.9
  deploy/wheels/py311/        -- Wheels for Python 3.11
  deploy/wheels.pyXX.lock.txt -- Lock file for each set

Install on the target RHEL host:
  PY=py$(python3 -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')
  python3 -m venv venv
  ./venv/bin/pip install --no-index --find-links deploy/wheels/$PY/ \
      -r requirements.txt gunicorn
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR    = Path(__file__).resolve().parent.parent
DEPLOY_DIR  = BASE_DIR / 'deploy'
REQS        = BASE_DIR / 'requirements.txt'

# RHEL 9 = glibc 2.34. manylinux2014 (glibc 2.17) wheels are forward-compatible.
TARGET_PLATFORMS  = ['manylinux2014_x86_64', 'manylinux_2_28_x86_64']

# The two versions we ship a ready-made bundle for out of the box. The `--py`
# argument accepts any 2- or 3-digit CPython major+minor (e.g. `39`, `310`,
# `311`, `312`, `313`); anything outside the DEFAULT_PYTHONS list is still
# allowed but PyPI may not have wheels for cryptography / lxml on bleeding-edge
# CPython yet, so the download can fail. See the CLI --help for details.
DEFAULT_PYTHONS = ['39', '311']

# pip interprets a bare --python-version like "39" as 3.9.0, which trips
# Requires-Python markers such as cryptography's "!=3.9.0,!=3.9.1". Pass a
# realistic patch-level version (RHEL 9 ships >= these) so markers evaluate
# correctly. The wheel ABI tag stays cp39/cp311 regardless of patch level.
# For versions not in this map, we fall back to the plain "X.Y" form which
# pip treats as "X.Y.0" -- fine unless a package has a `!=X.Y.0` marker.
_PIP_PYVERSION = {'39': '3.9.18', '310': '3.10.14', '311': '3.11.9', '312': '3.12.6'}


def _pip_pyversion(tag: str) -> str:
    """Return an appropriate `--python-version` value for a `pyXY` tag."""
    if tag in _PIP_PYVERSION:
        return _PIP_PYVERSION[tag]
    # Fallback: split major (first char) from minor (rest) -> "3.14", "3.10", ...
    if len(tag) >= 2 and tag.isdigit():
        return f'{tag[0]}.{tag[1:]}'
    return tag

# EXTRA_PACKAGES: packages that are not in requirements.txt, or that pip
# download skips because they are marker-conditional.
#   - gunicorn          → production WSGI server
#   - async-timeout     → conditional dependency of redis (required on
#                         Python <3.11.3; pip's cross-platform download
#                         evaluates the marker incorrectly, so we ask for
#                         it explicitly)
#   - pip               → to upgrade the default pip in the server's venv
EXTRA_PACKAGES    = [
    'gunicorn>=22,<23',
    'pip>=24,<25',

    # ── Marker-conditional packages ─────────────────────────────────────
    # pip's cross-platform download (running on Windows with Python 3.14)
    # evaluates markers against the CURRENT interpreter; the
    # --python-version flag only filters wheel tags. That is why we
    # explicitly request packages that are needed on Python 3.9 targets
    # but built-in on 3.11+.
    'async-timeout>=4.0.3',           # redis  (Python <3.11.3)
    'typing-extensions>=4.0.0',       # asgiref/Django/pydantic  (Python <3.11)
    'importlib-metadata>=6.0',        # Python <3.10 backport
    'zipp>=3.0',                      # importlib-metadata dependency
    'exceptiongroup>=1.0',            # Python <3.11 backport
    'tomli>=2.0',                     # Python <3.11 backport

    # ── Transitive dependencies of svglib 1.5.1 ─────────────────────────
    # (Stage 2 builds them locally with --no-deps; also added as Linux
    # wheels in Stage 1)
    'lxml',
    'tinycss2>=0.6.0',
    'cssselect2>=0.7.0',
    'webcolors',
    'webencodings',
]


def log(msg):
    print(msg, flush=True)


def download_for(py_ver: str):
    """Download every wheel for the specified Python version.

    On any pip download / wheel-build failure the (partial) wheels_dir is
    scrubbed so a subsequent setup run doesn't try to install from an
    incomplete bundle. Common trigger: bleeding-edge Python versions where
    cryptography / lxml don't have prebuilt wheels on PyPI yet.
    """
    abi          = f'cp{py_ver}'
    wheels_dir   = DEPLOY_DIR / 'wheels' / f'py{py_ver}'
    lock_file    = DEPLOY_DIR / f'wheels.py{py_ver}.lock.txt'

    log('')
    log(f'================ Python {py_ver} ================')

    if wheels_dir.exists():
        shutil.rmtree(wheels_dir)
    wheels_dir.mkdir(parents=True)

    platform_args = []
    for p in TARGET_PLATFORMS:
        platform_args.extend(['--platform', p])

    def _cleanup_on_failure(exc: BaseException):
        log(f'  [!] bundle build failed ({exc.__class__.__name__}) — removing partial {wheels_dir}')
        shutil.rmtree(wheels_dir, ignore_errors=True)
        # Also drop a stale lock file if we produced one from a previous run
        lock_file.unlink(missing_ok=True)

    # ---- Stage 1: download every package as a wheel (except svglib) ----
    tmp_reqs_lines = []
    for line in REQS.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if re.match(r'^svglib\b', stripped, re.IGNORECASE):
            continue
        tmp_reqs_lines.append(stripped)
    tmp_reqs = wheels_dir / '_tmp_reqs.txt'
    tmp_reqs.write_text('\n'.join(tmp_reqs_lines) + '\n', encoding='utf-8')

    cmd1 = [
        sys.executable, '-m', 'pip', 'download',
        '--dest', str(wheels_dir),
        '--python-version', _pip_pyversion(py_ver),
        *platform_args,
        '--abi', abi,
        '--implementation', 'cp',
        '--only-binary=:all:',
        '--no-cache-dir',
        '-r', str(tmp_reqs),
        *EXTRA_PACKAGES,
    ]
    log(f'  Stage 1: pip download (cp{py_ver}, manylinux2014)')
    try:
        subprocess.run(cmd1, check=True)
    except (subprocess.CalledProcessError, KeyboardInterrupt) as exc:
        tmp_reqs.unlink(missing_ok=True)
        _cleanup_on_failure(exc)
        raise
    finally:
        tmp_reqs.unlink(missing_ok=True)

    # ---- Stage 2: svglib sdist -> wheel (pure Python, py3-none-any) ----
    cmd2 = [
        sys.executable, '-m', 'pip', 'wheel',
        '--wheel-dir', str(wheels_dir),
        '--no-deps',
        '--no-cache-dir',
        'svglib>=1.5,<1.6',
    ]
    log(f'  Stage 2: pip wheel svglib (pure Python -> any)')
    try:
        subprocess.run(cmd2, check=True)
    except (subprocess.CalledProcessError, KeyboardInterrupt) as exc:
        _cleanup_on_failure(exc)
        raise

    # ---- Lock file ----
    wheels = sorted(p.name for p in wheels_dir.glob('*.whl'))
    lock_file.write_text('\n'.join(wheels) + '\n', encoding='utf-8')

    total_bytes = sum(p.stat().st_size for p in wheels_dir.iterdir() if p.is_file())
    log(f'  -> {len(wheels)} wheel, {total_bytes / 1024 / 1024:.1f} MB')
    log(f'  -> Lock: {lock_file.relative_to(BASE_DIR)}')
    return len(wheels), total_bytes


def main():
    parser = argparse.ArgumentParser(
        description='CYBER Cavalry offline wheel bundler.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--py', action='append', metavar='XY',
        help='Target Python version as major+minor digits (e.g. 39, 310, '
             '311, 312). May be repeated. Defaults to '
             f'{"+".join(DEFAULT_PYTHONS)} when omitted. Very new Python '
             'releases (3.13/3.14+) may lack prebuilt wheels for '
             'cryptography or lxml on PyPI, in which case the download '
             'step will fail with `No matching distribution found`.',
    )
    args = parser.parse_args()
    targets = args.py or list(DEFAULT_PYTHONS)

    # Validate the shape without hard-limiting the version list
    bad = [t for t in targets if not (t.isdigit() and 2 <= len(t) <= 3 and t[0] == '3')]
    if bad:
        sys.exit(f'[!] Invalid --py value(s): {bad}. Expected e.g. 39, 310, 311, 312.')

    if not REQS.exists():
        sys.exit(f'[!] requirements.txt not found: {REQS}')

    log(f'CYBER Cavalry -- Offline wheel bundler')
    log(f'Targets: Python {", ".join(targets)} / RHEL 9.x / x86_64')

    total_w = 0
    total_b = 0
    for v in targets:
        n, b = download_for(v)
        total_w += n
        total_b += b

    print()
    log('=' * 60)
    log(f'  All targets completed.')
    log(f'  Toplam: {total_w} wheel  |  {total_b / 1024 / 1024:.1f} MB')
    log('=' * 60)
    print()
    log('Install on the target RHEL host:')
    log('  PY=py$(python3 -c "import sys; print(f\'{sys.version_info.major}{sys.version_info.minor}\')")')
    log('  ./venv/bin/pip install --no-index --find-links deploy/wheels/$PY/ \\')
    log('      -r requirements.txt gunicorn')


if __name__ == '__main__':
    main()
