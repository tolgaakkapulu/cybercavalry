import ipaddress
import logging

logger = logging.getLogger(__name__)


MAX_EXPAND_HOSTS = 65536  # /16


def expand_to_hosts(cidr_str: str) -> list:
    """
    Expand a CIDR to individual /32 host entries.
    Returns a list of (cidr, ip, prefix) tuples.
    Raises ValueError if the block is too large (> MAX_EXPAND_HOSTS).
    """
    net = ipaddress.ip_network(cidr_str, strict=False)
    host_count = net.num_addresses
    if host_count > MAX_EXPAND_HOSTS:
        raise ValueError(
            f"{cidr_str} contains {host_count:,} hosts. "
            f"Maximum allowed is {MAX_EXPAND_HOSTS:,} (/{net.prefixlen} is too large — use /{32 - (MAX_EXPAND_HOSTS - 1).bit_length()} or smaller)."
        )
    result = []
    for ip in net.hosts() if net.prefixlen < 31 else net:
        host_str = str(ip)
        result.append((f"{host_str}/32", host_str, 32))
    return result


def normalize_cidr(value: str) -> tuple:
    """
    Normalize an IP or CIDR string.
    Returns (cidr_str, network_address_str, prefix_length)
    Raises ValueError on invalid input.

    Examples:
      '192.168.1.5/24'  -> ('192.168.1.0/24', '192.168.1.0', 24)
      '10.0.0.1'        -> ('10.0.0.1/32', '10.0.0.1', 32)
      '10.0.0.1/32'     -> ('10.0.0.1/32', '10.0.0.1', 32)
    """
    value = value.strip()
    if '/' not in value:
        value = value + '/32'
    net = ipaddress.ip_network(value, strict=False)
    return str(net), str(net.network_address), net.prefixlen


def is_valid_ip_or_cidr(value: str) -> bool:
    try:
        normalize_cidr(value)
        return True
    except ValueError:
        return False


def get_whitelisted_cidrs():
    """Return all active whitelist CIDRs."""
    from apps.whitelist.models import WhitelistEntry
    return list(WhitelistEntry.objects.filter(is_active=True).values_list('cidr', flat=True))


def check_whitelist_overlap(cidr_str):
    """
    Check if cidr_str overlaps with any active whitelist entry.
    Returns the matching whitelist CIDR string if overlap found, None otherwise.
    """
    from apps.whitelist.models import WhitelistEntry
    try:
        target = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return None

    for wl_cidr in WhitelistEntry.objects.filter(is_active=True).values_list('cidr', flat=True):
        try:
            if target.overlaps(ipaddress.ip_network(wl_cidr, strict=False)):
                return wl_cidr
        except ValueError:
            pass
    return None


def check_blacklist_overlap(cidr_str, group, exclude_cidr=None):
    """
    Check if cidr_str overlaps with any existing active blacklist entry in the same group
    (ignoring exclude_cidr, which is the entry being updated/re-added).
    Returns the overlapping CIDR string if found, None otherwise.
    """
    from .models import BlacklistEntry
    from django.utils import timezone
    from django.db.models import Q

    try:
        target = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return None

    qs = BlacklistEntry.objects.filter(
        group=group, is_active=True,
    ).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
    ).values_list('cidr', flat=True)

    for bl_cidr in qs:
        if exclude_cidr and bl_cidr == exclude_cidr:
            continue
        try:
            if target.overlaps(ipaddress.ip_network(bl_cidr, strict=False)):
                return bl_cidr
        except ValueError:
            pass
    return None


def filter_whitelisted(entries, whitelist_cidrs=None):
    """Filter out blacklist entries that overlap with any whitelist CIDR."""
    if whitelist_cidrs is None:
        whitelist_cidrs = get_whitelisted_cidrs()

    if not whitelist_cidrs:
        return entries

    whitelist_networks = []
    for cidr in whitelist_cidrs:
        try:
            whitelist_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass

    if not whitelist_networks:
        return entries

    result = []
    for entry in entries:
        try:
            target = ipaddress.ip_network(entry.cidr, strict=False)
            if not any(target.overlaps(wl) for wl in whitelist_networks):
                result.append(entry)
        except ValueError:
            result.append(entry)
    return result
