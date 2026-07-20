"""Shared LDAP helpers used by both the auth backend and the import browse view."""
import re


_OU_RE = re.compile(r'(?i)(?:^|,)\s*ou\s*=\s*([^,]+?)(?=\s*(?:,|$))')


def first_ou_from_dn(dn: str) -> str:
    """Return the first OU= component of an LDAP DN, or '' if none is present.

    Examples:
      "CN=jdoe,OU=Staff,OU=Users,DC=corp,DC=local" -> "Staff"
      "uid=jdoe,ou=People,dc=example,dc=com"        -> "People"
      "CN=jdoe,DC=corp,DC=local"                    -> ""

    Used to label imported users with the OU they came from so admins can tell
    Staff / Contractors / Vendors apart on the Users page and the LDAP browse
    modal without having to read the full DN.
    """
    if not dn:
        return ''
    m = _OU_RE.search(dn)
    if not m:
        return ''
    # LDAP RDN values may escape commas/equals (`\,`, `\=`); restore for display.
    return m.group(1).strip().replace('\\,', ',').replace('\\=', '=')
