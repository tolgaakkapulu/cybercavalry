"""
ASGI config for CYBERCavalry.

Django is served over ASGI on Windows by hypercorn (which also does TLS
terminaton on 8443, matching the Linux gunicorn+TLS setup). Django's
`get_asgi_application()` internally wraps the WSGI-style middleware
chain so nothing else in the project has to change.
"""
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cybercavalry.settings.base')

application = get_asgi_application()
