"""Allowlist of known-good IPs/CIDRs.

Some sources must never be treated as attackers no matter what their traffic
looks like: your own uptime monitors, CI runners, load-balancer health checks,
office egress ranges, and partner probes. A blue-team shield that virtual-patches
or rate-limits on heuristics will eventually misfire on one of these and page
someone at 3 a.m. (or, worse, auto-report a friendly address). This module keeps
a small, CIDR-aware allowlist so the integrator can *short-circuit detection*
for trusted origins before any matching, scoring, or reporting runs.

Design goals:
  * Standard library only (``ipaddress``); no runtime dependencies.
  * CIDR aware: a single ``10.0.0.0/8`` entry covers the whole range.
  * Mixed IPv4/IPv6 in one allowlist.
  * Total safety on bad input -- an invalid IP is simply "not allowed", never an
    exception, so a malformed header value can't crash the request path.

Typical use::

    allow = Allowlist(["203.0.113.7", "10.0.0.0/8", "2001:db8::/32"])
    if allow.is_allowed(resolved.attributed_ip):
        return  # skip detection entirely for this trusted source

The API is deliberately tiny: construct with entries, ``is_allowed(ip)``,
``add`` / ``remove``, and ``load_from_file(path)`` for ops-managed lists.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional, Union
from ._netutil import valid_ip

__all__ = ["Allowlist", "parse_network"]

# An entry may be an exact address ("203.0.113.7") or a CIDR block
# ("10.0.0.0/8"). A bare address is normalized to a single-host network
# (/32 for IPv4, /128 for IPv6) so membership is one uniform operation.
_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_network(entry: str) -> Optional[_Network]:
    """Parse one allowlist entry into a network, or ``None`` if invalid.

    Accepts a plain IP (treated as a single host) or a CIDR block. Host bits in
    a CIDR are tolerated (``strict=False``), so ``10.0.0.5/8`` is accepted and
    normalized to ``10.0.0.0/8``. Surrounding whitespace is ignored. Any input
    that is not a valid address or network yields ``None`` instead of raising.
    """
    if not isinstance(entry, str):
        return None
    text = entry.strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


class Allowlist:
    """A CIDR-aware set of known-good IPs/CIDRs.

    Entries may be exact IPv4/IPv6 addresses or CIDR blocks, freely mixed.
    Invalid entries passed to the constructor, ``add``, or ``load_from_file`` are
    silently skipped so a typo in an ops config never takes the shield down.
    Invalid input to ``is_allowed`` returns ``False``.
    """

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self._networks: List[_Network] = []
        for entry in entries:
            self.add(entry)

    # -- membership ---------------------------------------------------------

    def is_allowed(self, ip: str) -> bool:
        """Return ``True`` if ``ip`` is an exact match or inside an allowed CIDR.

        ``ip`` must be a single address (not a CIDR). Invalid or empty input --
        including ``None`` -- safely returns ``False``. IPv4 addresses are only
        tested against IPv4 networks and likewise for IPv6, which ``ipaddress``
        handles for us.
        """
        addr = self._parse_address(ip)
        if addr is None:
            return False
        return any(addr in net for net in self._networks)

    __contains__ = is_allowed

    # -- mutation -----------------------------------------------------------

    def add(self, entry: str) -> bool:
        """Add one IP or CIDR entry. Returns ``True`` if it was valid and stored.

        Adding an entry already covered by (or duplicating) an existing network
        is harmless; duplicates are not stored twice.
        """
        net = parse_network(entry)
        if net is None:
            return False
        if net not in self._networks:
            self._networks.append(net)
        return True

    def remove(self, entry: str) -> bool:
        """Remove a previously added entry. Returns ``True`` if it was present.

        Matching is by normalized network, so ``remove("10.0.0.0/8")`` removes an
        entry that was added as ``"10.0.0.5/8"``. Removing an absent or invalid
        entry returns ``False`` and changes nothing.
        """
        net = parse_network(entry)
        if net is None:
            return False
        try:
            self._networks.remove(net)
            return True
        except ValueError:
            return False

    def load_from_file(self, path: str) -> int:
        """Merge entries from a text file. Returns the count successfully added.

        One entry per line. Blank lines and lines beginning with ``#`` (after
        stripping whitespace) are ignored, so the file may carry comments. An
        inline ``#`` comment after an entry is also honored. Invalid lines are
        skipped. The file is read as UTF-8; a decoding or IO error propagates to
        the caller (a missing config file is worth surfacing, not swallowing).
        """
        added = 0
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                if self.add(line):
                    added += 1
        return added

    # -- introspection ------------------------------------------------------

    def entries(self) -> List[str]:
        """Return the stored networks as normalized CIDR strings."""
        return [str(net) for net in self._networks]

    def __len__(self) -> int:
        return len(self._networks)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Allowlist({self.entries()!r})"

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _parse_address(value: str) -> Optional[ipaddress._BaseAddress]:
        if not isinstance(value, str):
            return None
        text = value.strip()
        if not text:
            return None
        return valid_ip(text)
