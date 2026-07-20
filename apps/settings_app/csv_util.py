"""
CSV export hardening — neutralize spreadsheet formula injection.

A cell whose first character is one of = + - @ (or a leading tab/CR that some
parsers strip) can be interpreted as a formula by Excel/LibreOffice/Sheets when
the exported file is opened, enabling DDE/command execution or data exfiltration
(e.g. =HYPERLINK / =WEBSERVICE). User-supplied fields (reason, CIDR, log detail)
flow into our CSV exports, so every string cell must be neutralized.
"""

_DANGEROUS_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def csv_safe(value):
    """Return a CSV-cell-safe version of value (prefixes a single quote if risky)."""
    s = '' if value is None else str(value)
    if s and s[0] in _DANGEROUS_PREFIXES:
        return "'" + s
    return s


def safe_row(values):
    """Apply csv_safe to every value in an iterable, returning a list."""
    return [csv_safe(v) for v in values]
