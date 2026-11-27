"""Canonical IP-validation helpers.

Single home for the "parse a string as an IP address" logic that used to be
reimplemented in ``origin.py``, ``attribution.py``, ``intel.py`` and
``allowlist.py`` with slightly different behaviour.

Both helpers are thin wrappers around ``ipaddress.ip_address`` in a
``try/except ValueError``: they do not strip whitespace and do not type-check
their input, so every caller keeps exactly the behaviour it had before the
consolidation. Callers that historically stripped whitespace or validated
types keep doing so at the call site (see ``origin.py`` and ``allowlist.py``).
"""

import ipaddress
from typing import Optional


def valid_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    """Return ``value`` parsed as an IP address, or ``None`` when it is not one.

    Equivalent to ``ipaddress.ip_address(value)`` with ``ValueError`` mapped
    to ``None``; whitespace is not stripped and non-string input behaves the
    same as it does for ``ipaddress.ip_address``.
    """
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_valid_ip(value: str) -> bool:
    """Return True when ``value`` parses as an IP address."""
    return valid_ip(value) is not None
