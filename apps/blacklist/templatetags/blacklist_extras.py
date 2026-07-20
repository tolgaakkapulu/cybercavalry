from django import template
from django.contrib.staticfiles.storage import staticfiles_storage

register = template.Library()


@register.filter(name='country_flag')
def country_flag(code):
    """Convert a 2-letter ISO country code (e.g. 'US', 'tr') to a Unicode flag emoji.

    Composed of two regional-indicator letters (U+1F1E6..U+1F1FF). Returns ''
    when the input is missing or not exactly two ASCII letters, so templates
    can use {{ code|country_flag }} unconditionally without breaking layout.
    """
    if not code or len(code) != 2 or not code.isascii() or not code.isalpha():
        return ''
    code = code.upper()
    base = 0x1F1E6  # 'A' regional indicator
    return chr(base + ord(code[0]) - ord('A')) + chr(base + ord(code[1]) - ord('A'))


@register.filter(name='country_flag_url')
def country_flag_url(code):
    """Return the bundled SVG flag URL for a 2-letter ISO country code, or
    '' if the code is invalid. Resolves via Django's staticfiles storage so
    WhiteNoise / hashed filenames keep working in production."""
    if not code or len(code) != 2 or not code.isascii() or not code.isalpha():
        return ''
    return staticfiles_storage.url(f'img/flags/{code.lower()}.svg')


@register.filter(name='compact_number')
def compact_number(value):
    """Format a number for dashboard stat cards using SI suffixes.

    999 → '999', 1234 → '1.2K', 1_500_000 → '1.5M', 2_500_000_000 → '2.5B'.
    Trailing '.0' is stripped (e.g. 2000 → '2K' rather than '2.0K'). Falls back
    to str(value) when the value isn't numeric so templates never break.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        return value
    sign = '-' if n < 0 else ''
    n = abs(n)
    for limit, suffix in ((1_000_000_000, 'B'), (1_000_000, 'M'), (1_000, 'K')):
        if n >= limit:
            scaled = n / limit
            text = f'{scaled:.1f}'.rstrip('0').rstrip('.')
            return f'{sign}{text}{suffix}'
    return f'{sign}{n}'
