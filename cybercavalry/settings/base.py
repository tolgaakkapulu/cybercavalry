"""
CYBER Cavalry — Django Settings
"""

import socket
import environ
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ── Environment ──────────────────────────────────────────────
env = environ.Env(
    DEBUG=(bool, False),   # safe default — must be explicitly set True for development
    ALLOWED_HOSTS=(list, ['localhost', '127.0.0.1']),
)
environ.Env.read_env(BASE_DIR / '.env')

# ── Core ─────────────────────────────────────────────────────
SECRET_KEY = env('SECRET_KEY')  # Must be set in .env — no fallback default allowed
DEBUG = env('DEBUG')

# Dedicated key for encrypting secret Setting values (API keys, LDAP password).
# Kept SEPARATE from SECRET_KEY so that rotating SECRET_KEY (sessions/CSRF) does
# not make stored secrets undecryptable. Generated once and never auto-rotated.
# If empty, apps.settings_app.crypto falls back to SECRET_KEY (legacy behaviour).
FIELD_ENCRYPTION_KEY = env('FIELD_ENCRYPTION_KEY', default='')

# Collect all local network IPs so the app is reachable on any interface
def _local_ips():
    ips = set()
    try:
        # Primary outbound interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        # All IPs bound to this hostname
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ':' not in addr:          # skip IPv6
                ips.add(addr)
    except Exception:
        pass
    return list(ips)

# '0.0.0.0' is never a valid Host header a browser sends, so it is NOT added to
# ALLOWED_HOSTS. Interface-IP auto-detection is opt-in (off by default) — set a
# static ALLOWED_HOSTS in .env for production to keep Host validation tight.
_autodetect_hosts = env.bool('ALLOWED_HOSTS_AUTODETECT', default=False)
ALLOWED_HOSTS = list(set(
    env('ALLOWED_HOSTS') + ['localhost', '127.0.0.1']
    + (_local_ips() if _autodetect_hosts else [])
))

# Build CSRF trusted origins — always include every detected host/IP
_port = env.int('SERVER_PORT', default=8443)
_dynamic_csrf = list(dict.fromkeys(
    [f'https://{h}:{_port}' for h in ALLOWED_HOSTS if h not in ('0.0.0.0', '*')]
    + ['https://localhost:8443', 'https://127.0.0.1:8443']
))

# Merge with anything set in .env (env value takes priority, dynamic ones are always appended)
_env_csrf = env.list('CSRF_TRUSTED_ORIGINS', default=[])
CSRF_TRUSTED_ORIGINS = list(dict.fromkeys(_env_csrf + _dynamic_csrf))

# ── Applications ─────────────────────────────────────────────
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Project apps
    'apps.accounts',
    'apps.blacklist',
    'apps.whitelist',
    'apps.hashlist',
    'apps.dashboard',
    'apps.api',
    'apps.settings_app',
]

# ── Middleware ────────────────────────────────────────────────
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # WhiteNoise — serves static files from within the gunicorn process (no nginx needed).
    # Must sit immediately after SecurityMiddleware, BEFORE every other middleware.
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'cybercavalry.security_middleware.SecurityHeadersMiddleware',
    # AdminIPRestrictionMiddleware must come before session/auth so that
    # unauthenticated probes are dropped at the network level immediately.
    'cybercavalry.security_middleware.AdminIPRestrictionMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'cybercavalry.security_middleware.SessionTimeoutMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'apps.accounts.middleware.AuditMiddleware',
    # Syslog access-log forwarder — self-guards on the "Forward Access Logs"
    # toggle so it's a no-op when Settings → Actions → Syslog is off.
    'apps.settings_app.middleware.SyslogAccessLogMiddleware',
]

# ── URLs & WSGI ───────────────────────────────────────────────
ROOT_URLCONF = 'cybercavalry.urls'
WSGI_APPLICATION = 'cybercavalry.wsgi.application'

# ── Templates ─────────────────────────────────────────────────
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'apps.settings_app.context_processors.platform_settings',
            ],
        },
    },
]

# ── Database ──────────────────────────────────────────────────
DATABASES = {
    'default': env.db('DATABASE_URL', default=f'sqlite:///{BASE_DIR}/cybercavalry.db'),
}

# ── Cache (CWE-400 — shared cross-process cache for rate limiting) ──
# Redis (recommended production configuration):
#   .env → REDIS_URL=redis://127.0.0.1:6379/1
#
# When Redis is unavailable DatabaseCache takes over; it uses Django's own
# DB, is process-safe, and makes rate limiting / brute-force lockout work
# correctly in multi-worker deployments.
# Run this once on first install (or when the DB changes):
#   python manage.py createcachetable
#
# LocMemCache (Django's default) is never used — being process-local, it
# would completely bypass the rate limits in a multi-worker environment.
_REDIS_URL = env('REDIS_URL', default='')

if _REDIS_URL:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': _REDIS_URL,
            'OPTIONS': {
                'socket_connect_timeout': 2,
                'socket_timeout': 2,
                'retry_on_timeout': True,
            },
        }
    }
else:
    # DatabaseCache: uses Django's existing DB, process-safe.
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
            'LOCATION': 'cybercavalry_cache',
        }
    }

# ── Auth ──────────────────────────────────────────────────────
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

AUTHENTICATION_BACKENDS = [
    'apps.accounts.backends.LDAPAuthBackend',
    'django.contrib.auth.backends.ModelBackend',
]

LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/accounts/login/'

# ── Internationalisation ──────────────────────────────────────
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Europe/Istanbul'
USE_I18N = True
USE_TZ = True

# ── Static files ──────────────────────────────────────────────
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# ── Media (user-uploaded branding: logo / favicon / background) ───
# Served by a Django route (no nginx in the offline deployment); branding
# images are public by design (shown on the pre-auth login page).
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ── Default primary key ───────────────────────────────────────
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ── Upload / request-size limits (DoS hardening) ──────────────
# Explicit caps rather than relying on Django defaults. CSV imports are also
# row-capped in their views; this bounds the raw request body and form fields.
DATA_UPLOAD_MAX_MEMORY_SIZE   = env.int('DATA_UPLOAD_MAX_MEMORY_SIZE',   default=5 * 1024 * 1024)  # 5 MB
FILE_UPLOAD_MAX_MEMORY_SIZE   = env.int('FILE_UPLOAD_MAX_MEMORY_SIZE',   default=5 * 1024 * 1024)  # 5 MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = env.int('DATA_UPLOAD_MAX_NUMBER_FIELDS', default=1000)

# ── Session ───────────────────────────────────────────────────
SESSION_COOKIE_AGE            = 900     # 15 minutes (default; a DB setting overrides this)
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_HTTPONLY       = True    # Block JavaScript access to the cookie
SESSION_COOKIE_SECURE         = True    # Send the cookie only over HTTPS
SESSION_COOKIE_SAMESITE       = 'Lax'  # Reduce CSRF surface; 'Strict' breaks the login redirect

# ── CSRF ──────────────────────────────────────────────────────
CSRF_COOKIE_SECURE            = True    # CSRF cookie only on HTTPS
CSRF_COOKIE_HTTPONLY          = True    # Hide the CSRF cookie from JS (we use the template tag)

# ── HTTPS / Security headers ──────────────────────────────────
# The platform serves HTTPS directly on port 8443; there is no separate HTTP
# port. That is why SECURE_SSL_REDIRECT is False by default — enabling it
# would produce a redirect loop. If a reverse proxy (nginx/caddy) is added
# in front later, this can be set to True.
SECURE_SSL_REDIRECT           = env.bool('SECURE_SSL_REDIRECT', default=False)

# HSTS: tells the browser to "always connect to this domain over HTTPS".
# Use with care when running self-signed certificates — a misconfiguration
# can lock users out of the domain.
SECURE_HSTS_SECONDS           = env.int('SECURE_HSTS_SECONDS', default=300)  # 5 min default
SECURE_HSTS_INCLUDE_SUBDOMAINS = env.bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=True)
SECURE_HSTS_PRELOAD           = env.bool('SECURE_HSTS_PRELOAD', default=False)    # The preload list requires a real domain

# X-Content-Type-Options: nosniff (blocks MIME sniffing attacks)
SECURE_CONTENT_TYPE_NOSNIFF   = True

# X-Frame-Options: DENY (clickjacking protection)
X_FRAME_OPTIONS               = 'DENY'

# ── Trusted Proxies (CWE-346 — IP spoofing mitigation) ───────────
# Empty list = no reverse proxy; get_client_ip() uses REMOTE_ADDR directly.
# If a reverse proxy such as Nginx/Caddy sits in front, add the proxy's IP
# address here. Only X-Forwarded-For headers arriving from these IPs are
# treated as trustworthy.
# Example .env entry: TRUSTED_PROXIES=10.0.0.1,10.0.0.2
TRUSTED_PROXIES = env.list('TRUSTED_PROXIES', default=[])

# ── Django Admin ──────────────────────────────────────────────────────
# Path at which the admin UI is served.  Loaded from .env so the real URL
# never appears in version-controlled source code.
ADMIN_PATH = env('ADMIN_PATH', default='cybercavalry-management-console/')

# IP addresses allowed to reach the admin interface at the middleware level.
# Requests from any other IP receive a 404 — no confirmation that an admin
# path exists.  Default: localhost only.
# To permit additional IPs, set in .env:  ADMIN_ALLOWED_IPS=10.0.0.1,10.0.0.2
ADMIN_ALLOWED_IPS = env.list('ADMIN_ALLOWED_IPS', default=['127.0.0.1', '::1'])

# ── LDAP (env override; UI Settings page can also configure) ──
LDAP_ENABLED = env.bool('LDAP_ENABLED', default=False)
LDAP_SERVER_URI = env('LDAP_SERVER_URI', default='')
LDAP_BIND_DN = env('LDAP_BIND_DN', default='')
LDAP_BIND_PASSWORD = env('LDAP_BIND_PASSWORD', default='')
LDAP_USER_SEARCH_BASE = env('LDAP_USER_SEARCH_BASE', default='')
LDAP_USER_SEARCH_FILTER = env('LDAP_USER_SEARCH_FILTER', default='(sAMAccountName=%(user)s)')
LDAP_USER_ATTR_MAP = env.json('LDAP_USER_ATTR_MAP', default={
    'first_name': 'givenName',
    'last_name': 'sn',
    'email': 'mail',
})

# ── SSL ───────────────────────────────────────────────────────
SSL_CERT_FILE = env('SSL_CERT_FILE', default='certs/cert.pem')
SSL_KEY_FILE = env('SSL_KEY_FILE', default='certs/key.pem')

# ── Outbound threat-intel HTTPS (AbuseIPDB / VirusTotal) ──────
# Trust = system CA store + certifi + (optional) corporate CA below.
# Behind a corporate SSL inspection (MITM proxy)? Point this at the proxy's
# root CA as a PEM file; it is MERGED with the certifi/system CA store
# (it does not override them):
#   .env → THREAT_INTEL_CA_BUNDLE=/data/cybercavalry/certs/corp-ca.pem
THREAT_INTEL_CA_BUNDLE = env('THREAT_INTEL_CA_BUNDLE', default='')

# Last resort — disables TLS verification (INSECURE, exposed to MITM).
# Only for isolated environments where the corporate CA cannot be provided:
#   .env → THREAT_INTEL_SSL_VERIFY=False
THREAT_INTEL_SSL_VERIFY = env.bool('THREAT_INTEL_SSL_VERIFY', default=True)

# ── Error pages ───────────────────────────────────────────────
# Custom handlers are registered in cybercavalry/urls.py
# Django serves templates/errors/{404,500,403,400}.html when DEBUG=False

# ── Logging ───────────────────────────────────────────────────
# Log traffic is split across three files so operators can tail exactly what
# they need without wading through unrelated chatter:
#
#   logs/cybercavalry.log — INFO / WARNING chatter from the platform and
#                           Django. ERROR and above are stripped out by
#                           `BelowErrorFilter` so they don't duplicate what's
#                           already in error.log.
#   logs/error.log        — anything at ERROR level or higher, wherever it
#                           originates (root, django, apps, etc.).
#   logs/access.log       — one line per finished HTTP request. Written by
#                           the `access` logger (SyslogAccessLogMiddleware
#                           emits into it) and by `django.server` from
#                           `runserver` output.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{asctime} {levelname} {name} {message}',
            'style': '{',
        },
        'access': {
            'format': '{asctime} {message}',
            'style': '{',
        },
    },
    'filters': {
        'below_error': {
            '()': 'cybercavalry.log_filters.BelowErrorFilter',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'main_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'cybercavalry.log',
            'maxBytes': 10 * 1024 * 1024,  # 10 MB
            'backupCount': 5,
            'formatter': 'verbose',
            'encoding': 'utf-8',
            'filters': ['below_error'],   # keep error rows OUT of this file
        },
        'error_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'error.log',
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'verbose',
            'encoding': 'utf-8',
            'level': 'ERROR',             # only ERROR and above land here
        },
        'access_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'access.log',
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'access',
            'encoding': 'utf-8',
        },
        # Syslog mirrors — sit alongside each file handler and self-guard on
        # the Settings → Actions → Syslog checkboxes. Sharing the file
        # handler's formatter + filter means the syslog message is byte-for-
        # byte what the file received.
        'syslog_main': {
            '()': 'apps.settings_app.syslog_service.SyslogMainHandler',
            'formatter': 'verbose',
            'filters': ['below_error'],
        },
        'syslog_error': {
            '()': 'apps.settings_app.syslog_service.SyslogErrorHandler',
            'formatter': 'verbose',
            'level': 'ERROR',
        },
        'syslog_access': {
            '()': 'apps.settings_app.syslog_service.SyslogAccessHandler',
            'formatter': 'access',
        },
    },
    'root': {
        'handlers': ['console', 'main_file', 'error_file', 'syslog_main', 'syslog_error'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'main_file', 'error_file', 'syslog_main', 'syslog_error'],
            'level': 'WARNING',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console', 'main_file', 'error_file', 'syslog_main', 'syslog_error'],
            'level': 'ERROR',   # logs 500 errors with full traceback server-side
            'propagate': False,
        },
        'django.server': {
            # `runserver` prints one line per request via this logger — keep
            # them out of the main file and route them to access.log.
            'handlers': ['access_file', 'syslog_access'],
            'level': 'INFO',
            'propagate': False,
        },
        'access': {
            # SyslogAccessLogMiddleware emits into this logger; its lines go
            # exclusively to access.log (never to error.log or cybercavalry.log).
            'handlers': ['access_file', 'syslog_access'],
            'level': 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console', 'main_file', 'error_file', 'syslog_main', 'syslog_error'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
