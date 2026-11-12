"""TAXII 2.0 pagination — HTTP `Range` / `Content-Range` with the `items` unit.

This is the part that differs most from TAXII 2.1. 2.1 paginates with
`more` / `next` fields inside an envelope; 2.0 (CS01 §3.4) uses HTTP range
headers and the `items` range unit:

    request   Range: items 0-49
    response  206 Partial Content
              Content-Range: items 0-49/500
              Accept-Ranges: items

Ranges are inclusive and zero-indexed; the third value is the total
available. A range starting past the end gets 416. §3.4.3 also allows a
server to answer 206 with `Content-Range` even when the client sent no
`Range` header at all, which is what we do to cap unbounded pulls.

The objects and manifest endpoints additionally MUST carry
`X-TAXII-Date-Added-First` / `X-TAXII-Date-Added-Last` on 200 and 206
(§3.4) — those bound the slice, not the whole collection.
"""
from __future__ import annotations

import re

RANGE_UNIT = 'items'

# `items 0-49`. Whitespace around the unit is tolerated; a bare `items 5-`
# (open-ended) is accepted and clamped to the page cap by the caller.
_RANGE_RE = re.compile(r'^\s*items\s+(\d+)\s*-\s*(\d*)\s*$', re.IGNORECASE)


class RangeNotSatisfiable(Exception):
    """Signals a 416 — requested start sits past the end of the result set."""

    def __init__(self, total: int):
        super().__init__(f'range start beyond available items (total={total})')
        self.total = total


def parse_range(header: str | None, total: int, default_size: int) -> tuple[int, int, bool]:
    """Resolve a `Range` header against `total` available items.

    Returns `(first, last_exclusive, is_partial)`:
      * `first` / `last_exclusive` slice the queryset
      * `is_partial` drives 206-vs-200

    `total == 0` short-circuits to an empty, non-partial 200 — an empty
    collection is a legitimate full answer, not a range error.
    """
    if total == 0:
        return 0, 0, False

    if not header:
        # No Range asked for. Serve the head of the set, capped, and mark it
        # partial only when we actually truncated (§3.4.3 permits this).
        last_exclusive = min(default_size, total)
        return 0, last_exclusive, last_exclusive < total

    m = _RANGE_RE.match(header)
    if not m:
        # Unparseable range → ignore it and behave as if absent, rather
        # than 416. The spec does not require rejecting a malformed unit,
        # and being lenient here keeps a quirky client working.
        last_exclusive = min(default_size, total)
        return 0, last_exclusive, last_exclusive < total

    first = int(m.group(1))
    if first >= total:
        raise RangeNotSatisfiable(total)

    end_raw = m.group(2)
    if end_raw == '':
        # Open-ended `items 10-` — give them the cap, not the whole tail.
        last_inclusive = min(first + default_size - 1, total - 1)
    else:
        last_inclusive = int(end_raw)
        if last_inclusive < first:
            raise RangeNotSatisfiable(total)
        # A server MAY return fewer items than asked for (§3.4.2).
        last_inclusive = min(last_inclusive, total - 1, first + default_size - 1)

    last_exclusive = last_inclusive + 1
    return first, last_exclusive, (last_exclusive - first) < total


def apply_range_headers(response, first: int, last_exclusive: int, total: int,
                        is_partial: bool) -> None:
    """Stamp the range headers onto a response built from that slice."""
    response['Accept-Ranges'] = RANGE_UNIT
    if is_partial and total:
        response.status_code = 206
        # Content-Range is inclusive on both ends.
        response['Content-Range'] = f'{RANGE_UNIT} {first}-{last_exclusive - 1}/{total}'


def apply_date_added_headers(response, first_ts: str | None, last_ts: str | None) -> None:
    """`X-TAXII-Date-Added-First` / `-Last` — required on 200/206 from the
    objects and manifest endpoints. Omitted when the slice is empty, since
    there is no date range to report."""
    if first_ts:
        response['X-TAXII-Date-Added-First'] = first_ts
    if last_ts:
        response['X-TAXII-Date-Added-Last'] = last_ts
