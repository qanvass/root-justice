"""Trustworthy origin attribution.

The leftmost X-Forwarded-For value is attacker-controlled: a scanner can prepend
any IP it likes and get an innocent third party blocked and named in a federal
report. This module resolves the *attributed origin* by walking the forwarded
chain from the socket peer (which cannot be spoofed on an established TCP
connection) back toward the client, stopping at the first hop that is NOT a
trusted proxy. Every hop is tagged with a confidence level so a human can see
how much of the chain is actually dependable before anything is reported.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple
from ._netutil import valid_ip


# Confidence a given hop is the true origin, not a spoofed/relayed value.
#   "socket"   - the real TCP peer; cannot be forged on an established connection.
#   "trusted"  - a hop vouched for by the trusted-proxy allowlist.
#   "asserted" - present only because a (spoofable) header said so; treat as a lead.
CONFIDENCE_SOCKET = "socket"
CONFIDENCE_TRUSTED = "trusted"
CONFIDENCE_ASSERTED = "asserted"


@dataclass
class OriginHop:
    """One node in the resolved request path."""

    ip: str
    source: str  # "socket" | "x-forwarded-for" | "forwarded"
    confidence: str
    is_trusted_proxy: bool = False


@dataclass
class ResolvedOrigin:
    """The attributed origin plus the full chain and a reportability verdict."""

    attributed_ip: str
    attributed_confidence: str
    chain: List[OriginHop] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def is_reportable(self) -> bool:
        """True only when the attribution does not rest on a spoofable assertion.

        An "asserted"-only attribution must never be auto-submitted to authorities;
        it may still be logged and acted on defensively (block/banner) locally.
        """
        return self.attributed_confidence in (CONFIDENCE_SOCKET, CONFIDENCE_TRUSTED)

    def to_dict(self) -> Dict[str, object]:
        return {
            "attributed_ip": self.attributed_ip,
            "attributed_confidence": self.attributed_confidence,
            "is_reportable": self.is_reportable,
            "chain": [
                {
                    "ip": h.ip,
                    "source": h.source,
                    "confidence": h.confidence,
                    "is_trusted_proxy": h.is_trusted_proxy,
                }
                for h in self.chain
            ],
            "notes": list(self.notes),
        }


class TrustedProxies:
    """Allowlist of proxy IPs/CIDRs whose forwarded headers may be believed."""

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self._networks: List[ipaddress._BaseNetwork] = []
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue

    def contains(self, ip: str) -> bool:
        addr = valid_ip(ip.strip())
        if addr is None:
            return False
        return any(addr in net for net in self._networks)


def _parse_forwarded_for(headers: Dict[str, str]) -> List[Tuple[str, str]]:
    """Return [(ip, source_header)] in header order (leftmost first)."""
    out: List[Tuple[str, str]] = []
    xff = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or ""
    for part in xff.split(","):
        addr = valid_ip(part.strip())
        if addr is not None:
            out.append((str(addr), "x-forwarded-for"))
    return out


def resolve_origin(
    socket_peer_ip: str,
    headers: Dict[str, str],
    trusted: Optional[TrustedProxies] = None,
) -> ResolvedOrigin:
    """Resolve the attributed origin from the unspoofable socket peer inward.

    Algorithm (RFC-7239 / de-facto XFF handling):
      1. The socket peer is ground truth (confidence: socket).
      2. If the peer is a trusted proxy, believe the rightmost XFF hop it added,
         and keep walking left through trusted hops.
      3. The first hop that is not a trusted proxy is the attributed origin. If it
         came only from a header (not the socket), its confidence is "asserted"
         and the result is not auto-reportable.
    """
    trusted = trusted or TrustedProxies()
    notes: List[str] = []

    peer = valid_ip(socket_peer_ip.strip())
    if peer is None:
        return ResolvedOrigin(
            attributed_ip=socket_peer_ip,
            attributed_confidence=CONFIDENCE_ASSERTED,
            chain=[OriginHop(socket_peer_ip, "socket", CONFIDENCE_ASSERTED)],
            notes=["socket peer IP was not a valid address"],
        )

    peer_str = str(peer)
    peer_trusted = trusted.contains(peer_str)
    chain: List[OriginHop] = [
        OriginHop(peer_str, "socket", CONFIDENCE_SOCKET, is_trusted_proxy=peer_trusted)
    ]

    # If the direct peer is not a trusted proxy, it IS the origin. Any forwarded
    # header is unverifiable and only recorded as a lead.
    if not peer_trusted:
        forwarded = _parse_forwarded_for(headers)
        if forwarded:
            notes.append(
                "socket peer is not a trusted proxy; X-Forwarded-For present but "
                "unverifiable and recorded as a lead only"
            )
            for ip, src in forwarded:
                chain.append(OriginHop(ip, src, CONFIDENCE_ASSERTED))
        return ResolvedOrigin(
            attributed_ip=peer_str,
            attributed_confidence=CONFIDENCE_SOCKET,
            chain=chain,
            notes=notes,
        )

    # Peer is a trusted proxy: walk the forwarded chain right-to-left. Each hop is
    # believable as long as the node that reported it is trusted. The first hop
    # reported by a trusted node that is NOT itself a proxy is the real client and
    # is reportable. Anything further left was added by an untrusted node and is
    # only a spoofable lead.
    forwarded = _parse_forwarded_for(headers)
    attributed_ip = peer_str
    attributed_conf = CONFIDENCE_TRUSTED
    reporter_trusted = True
    reached_client = False
    for ip, src in reversed(forwarded):
        conf = CONFIDENCE_TRUSTED if reporter_trusted else CONFIDENCE_ASSERTED
        hop_is_proxy = trusted.contains(ip)
        chain.append(OriginHop(ip, src, conf, is_trusted_proxy=hop_is_proxy))
        if reporter_trusted and not reached_client:
            attributed_ip = ip
            attributed_conf = CONFIDENCE_TRUSTED
            if not hop_is_proxy:
                # Real client, observed and reported by a trusted proxy.
                reached_client = True
                reporter_trusted = False
                notes.append(
                    "attributed origin is the client reported by the trusted proxy "
                    "segment; hops further left are unverifiable leads"
                )
        else:
            reporter_trusted = False

    if attributed_ip == peer_str and not forwarded:
        notes.append("trusted proxy added no forwarded-for hop; origin is the proxy itself")

    return ResolvedOrigin(
        attributed_ip=attributed_ip,
        attributed_confidence=attributed_conf,
        chain=chain,
        notes=notes,
    )
