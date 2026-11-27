"""Threat-intel feeds (spec #7) -- STRICTLY DEFENSIVE.

Loads IP/CIDR blocklists from local files and/or URLs, normalizes them into a
fast-lookup structure, and answers one read-only question for the request path:
"is this source IP on a known-bad list, and if so, which one and why?"

Everything here is passive. The module only *reads* intel and *reports* a match;
it never contacts, probes, or retaliates against any address. Network fetching is
isolated behind the module-level ``_http_get`` seam so tests (and offline/air-
gapped deployments) run with no network and no admin. If a remote feed cannot be
fetched, the previously loaded entries are kept and the error is recorded in
``last_errors`` rather than raised -- a dead feed must never take the shield down.

Supported feed format (one entry per line)::

    # comments and blank lines are ignored
    203.0.113.7            ; optional inline reason after ';' or whitespace
    198.51.100.0/24        known scanner net
    2001:db8::/32

Both IPv4 and IPv6, single addresses and CIDR networks, are accepted.

Typical use::

    intel = ThreatIntel([
        {"name": "local-bans", "path": "/etc/artex/bans.txt"},
        {"name": "abuse-feed", "url": "https://example.test/feed.txt"},
    ])
    intel.refresh()
    reason = intel.is_known_bad("203.0.113.7")   # -> "local-bans: listed" or None
"""

from __future__ import annotations

import ipaddress
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union
from ._netutil import valid_ip


__all__ = ["ThreatIntel", "IntelSource", "_http_get"]


# Default timeout (seconds) for any remote feed fetch. Kept short so a slow feed
# cannot stall a refresh for long.
_HTTP_TIMEOUT = 10.0


def _http_get(url: str, timeout: float = _HTTP_TIMEOUT) -> str:
    """Fetch the body of ``url`` as text. The ONLY network seam in this module.

    Tests monkeypatch ``artex_antidote.intel._http_get`` to return canned feed
    text, so the rest of the module -- and every test -- runs fully offline.

    Only ``http`` and ``https`` URLs are honoured; anything else (e.g. ``file://``)
    raises ``ValueError`` so a malicious feed entry cannot coax the fetcher into
    reading arbitrary local paths.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"refusing to fetch non-HTTP(S) URL: {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": "artex-antidote-intel/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme checked above)
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


@dataclass
class IntelSource:
    """One configured blocklist feed.

    Exactly one of ``path`` or ``url`` must be set. ``name`` labels the source in
    match reasons and in :attr:`ThreatIntel.last_errors`.
    """

    name: str
    path: Optional[str] = None
    url: Optional[str] = None

    def __post_init__(self) -> None:
        if bool(self.path) == bool(self.url):
            raise ValueError(
                f"source {self.name!r} must set exactly one of 'path' or 'url'"
            )


# A caller may pass IntelSource objects or plain dicts; normalize both.
SourceLike = Union[IntelSource, Dict[str, str]]


def _coerce_source(src: SourceLike) -> IntelSource:
    if isinstance(src, IntelSource):
        return src
    if isinstance(src, dict):
        return IntelSource(
            name=src.get("name") or src.get("path") or src.get("url") or "unnamed",
            path=src.get("path"),
            url=src.get("url"),
        )
    raise TypeError(f"unsupported source spec: {src!r}")


def _parse_line(line: str) -> Optional[Tuple[str, str]]:
    """Return ``(network_token, reason)`` for a feed line, or ``None`` to skip it.

    The address/CIDR is the first whitespace- or ';'-delimited token; anything
    after it on the line is treated as a human-readable reason. Comment lines
    (starting with '#') and blank lines yield ``None``.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    # Allow "ip ; reason" and "ip reason" and "ip,reason".
    for sep in (";", ",", None):  # None -> split on arbitrary whitespace
        if sep is None:
            parts = stripped.split(None, 1)
        elif sep in stripped:
            parts = [p.strip() for p in stripped.split(sep, 1)]
        else:
            continue
        token = parts[0].strip()
        reason = parts[1].strip() if len(parts) > 1 and parts[1].strip() else ""
        if token:
            return token, reason
    return None


class ThreatIntel:
    """Aggregated IP/CIDR blocklist with a read-only ``is_known_bad`` lookup.

    Construction does NOT fetch anything; call :meth:`refresh` to (re)load. This
    keeps object creation cheap and side-effect-free, and lets a scheduler decide
    when feeds are pulled.

    Lookups are O(number of distinct prefix lengths) -- exact single-IP hits are a
    dict probe, and CIDR membership is checked against the compacted network set.
    """

    def __init__(self, sources: Optional[Sequence[SourceLike]] = None) -> None:
        self._sources: List[IntelSource] = [
            _coerce_source(s) for s in (sources or [])
        ]
        # Exact single-address hits: normalized IP string -> source name.
        self._exact: Dict[str, str] = {}
        # Reason text keyed by the same normalized IP string.
        self._exact_reason: Dict[str, str] = {}
        # CIDR networks: list of (network, source_name, reason).
        self._nets: List[Tuple[ipaddress._BaseNetwork, str, str]] = []
        # Per-source load errors from the most recent refresh.
        self.last_errors: Dict[str, str] = {}
        # Count of entries loaded in the most recent successful refresh.
        self.entry_count: int = 0

    # -- configuration -----------------------------------------------------

    def add_source(self, source: SourceLike) -> None:
        """Register another feed. Takes effect on the next :meth:`refresh`."""
        self._sources.append(_coerce_source(source))

    @property
    def sources(self) -> List[IntelSource]:
        return list(self._sources)

    # -- loading -----------------------------------------------------------

    def refresh(self) -> int:
        """(Re)load every configured source and rebuild the lookup tables.

        Returns the number of entries loaded. A source that fails (missing file,
        fetch error, unparseable line) is skipped: its error is recorded in
        :attr:`last_errors` and the remaining sources still load. The lookup
        tables are swapped in atomically only after all sources are processed, so
        a mid-refresh failure never leaves a half-built table in place.
        """
        exact: Dict[str, str] = {}
        exact_reason: Dict[str, str] = {}
        nets: List[Tuple[ipaddress._BaseNetwork, str, str]] = []
        errors: Dict[str, str] = {}

        for src in self._sources:
            try:
                text = self._read_source(src)
            except Exception as exc:  # noqa: BLE001 - a dead feed must not crash us
                errors[src.name] = f"{type(exc).__name__}: {exc}"
                continue
            self._ingest(src.name, text, exact, exact_reason, nets)

        self._exact = exact
        self._exact_reason = exact_reason
        self._nets = nets
        self.last_errors = errors
        self.entry_count = len(exact) + len(nets)
        return self.entry_count

    def _read_source(self, src: IntelSource) -> str:
        if src.path:
            return Path(src.path).read_text(encoding="utf-8", errors="replace")
        assert src.url  # guaranteed by IntelSource validation
        return _http_get(src.url)

    def _ingest(
        self,
        name: str,
        text: str,
        exact: Dict[str, str],
        exact_reason: Dict[str, str],
        nets: List[Tuple[ipaddress._BaseNetwork, str, str]],
    ) -> None:
        for raw in text.splitlines():
            parsed = _parse_line(raw)
            if parsed is None:
                continue
            token, reason = parsed
            if "/" in token:
                try:
                    net = ipaddress.ip_network(token, strict=False)
                except ValueError:
                    # Not a valid CIDR -- skip the line, keep the feed usable.
                    continue
                nets.append((net, name, reason))
            else:
                ip = valid_ip(token)
                if ip is None:
                    # Not a valid IP -- skip the line, keep the feed usable.
                    continue
                key = ip.compressed
                # First source to list an IP wins its attribution.
                exact.setdefault(key, name)
                if reason:
                    exact_reason.setdefault(key, reason)

    # -- lookup ------------------------------------------------------------

    def is_known_bad(self, ip: str) -> Optional[str]:
        """Return a ``"source: reason"`` string if ``ip`` is listed, else ``None``.

        ``ip`` may be any valid IPv4/IPv6 string; a malformed value returns
        ``None`` (it is not our job to validate caller input here, only to answer
        membership). Exact single-IP hits are preferred over CIDR matches, and
        among CIDR matches the most specific (longest-prefix) network wins so the
        most precise attribution is reported.
        """
        addr = valid_ip(ip)
        if addr is None:
            return None

        key = addr.compressed
        if key in self._exact:
            source = self._exact[key]
            reason = self._exact_reason.get(key)
            return f"{source}: {reason}" if reason else f"{source}: listed"

        best: Optional[Tuple[ipaddress._BaseNetwork, str, str]] = None
        for net, name, reason in self._nets:
            if addr.version != net.version:
                continue
            if addr in net:
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, name, reason)
        if best is not None:
            net, name, reason = best
            detail = reason if reason else f"within {net.compressed}"
            return f"{name}: {detail}"
        return None

    def __contains__(self, ip: str) -> bool:
        return self.is_known_bad(ip) is not None

    def __len__(self) -> int:
        return self.entry_count
