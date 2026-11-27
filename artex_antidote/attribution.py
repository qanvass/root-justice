"""Attack Reverse-Engineering, On-the-Fly Patch Synthesis, RDAP Origin Attribution, and REA Bridge."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ._netutil import is_valid_ip, valid_ip
from .signatures import classify_vectors


@dataclass
class ReverseEngineeredAttack:
    """Structured breakdown of an incoming attack and synthesized defensive patch."""

    attack_id: str
    vectors: List[str]
    extracted_iocs: Dict[str, List[str]]
    coraza_seclang_rule: str
    python_guard_snippet: str


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def reverse_engineer_request(
    method: str,
    path: str,
    user_agent: str,
    body: str = "",
) -> ReverseEngineeredAttack:
    """Reverse-engineer an inbound attack payload and synthesize Coraza + Python patches on the fly."""
    combined = f"{method} {path} {user_agent} {body}"
    attack_id = hashlib.sha256(combined.encode("utf-8")).hexdigest()[:10]

    # Vector classification is shared with the edge shield via
    # :mod:`artex_antidote.signatures`, so the payload/UA signatures cannot drift
    # between the detection path and this patch-synthesis path (previously this
    # path was missing the ``benchmark(`` SQLi primitive the shield already had).
    vectors: List[str] = classify_vectors(combined, user_agent)
    if not vectors:
        vectors.append("anomalous_probe")

    ips = sorted({m for m in _IP_RE.findall(combined) if is_valid_ip(m)})
    urls = sorted(set(_URL_RE.findall(combined)))

    # Synthesize a Coraza/ModSecurity SecLang virtual patch rule for this exact path/vector
    rule_id = 900000 + (int(attack_id[:5], 16) % 90000)
    escaped_path = path.split("?")[0].replace('"', '\\"')
    coraza_rule = (
        f'SecRule REQUEST_URI "@beginsWith {escaped_path}" '
        f'"id:{rule_id},phase:1,deny,status:429,log,'
        f'msg:\'Artex Antidote Auto-Patch [{",".join(vectors)}]\'"'
    )

    # Synthesize an immediately-loadable Python guard snippet
    python_snippet = (
        f"def guard_{attack_id}(path: str, ua: str) -> bool:\n"
        f"    # Auto-synthesized patch for vectors: {', '.join(vectors)}\n"
        f"    return path.startswith({escaped_path!r})\n"
    )

    return ReverseEngineeredAttack(
        attack_id=attack_id,
        vectors=vectors,
        extracted_iocs={"ips": ips, "urls": urls},
        coraza_seclang_rule=coraza_rule,
        python_guard_snippet=python_snippet,
    )


def _http_get_json(url: str, timeout: float = 4.0) -> Dict[str, Any]:
    """Fetch JSON over HTTPS. Single seam so attribution is testable offline."""
    req = urllib.request.Request(
        url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "RootJustice/0.1"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _extract_abuse_email(data: Dict[str, Any]) -> Optional[str]:
    """Walk RDAP entities for an abuse contact email (vCard array)."""
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        if "abuse" not in roles:
            continue
        vcard = (ent.get("vcardArray") or [None, []])[1]
        for item in vcard:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                return item[3]
    return None


def lookup_rdap(ip: str, timeout: float = 4.0) -> Dict[str, Any]:
    """Defensive RDAP lookup via the IANA bootstrap (rdap.org), not a single RIR.

    rdap.org redirects to the authoritative RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC),
    so this works for any routable IP instead of only ARIN-registered space (#6).
    """
    addr = valid_ip(ip)
    if addr is None:
        return {"ip": ip, "status": "invalid_ip"}

    if addr.is_private or addr.is_loopback or addr.is_reserved:
        return {"ip": ip, "status": "non_routable_or_local", "network": "private/loopback"}

    try:
        data = _http_get_json(f"https://rdap.org/ip/{ip}", timeout=timeout)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {"ip": ip, "status": "lookup_unavailable", "error": str(exc)}

    cidr = ""
    for c in data.get("cidr0_cidrs", []) or []:
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx:
            cidr = f"{pfx}/{c.get('length')}"
            break
    return {
        "ip": ip,
        "status": "ok",
        "name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "startAddress": data.get("startAddress"),
        "endAddress": data.get("endAddress"),
        "cidr": cidr,
        "abuse_email": _extract_abuse_email(data),
    }


def lookup_asn(ip: str, timeout: float = 4.0) -> Dict[str, Any]:
    """Resolve the originating ASN + holder + announced prefix via RIPEstat (no key)."""
    addr = valid_ip(ip)
    if addr is None:
        return {"ip": ip, "status": "invalid_ip"}
    if addr.is_private or addr.is_loopback or addr.is_reserved:
        return {"ip": ip, "status": "non_routable_or_local"}

    try:
        net = _http_get_json(
            f"https://stat.ripe.net/data/network-info/data.json?resource={ip}", timeout=timeout
        )
        data = net.get("data", {}) or {}
        asns = data.get("asns", []) or []
        prefix = data.get("prefix")
        holder = None
        if asns:
            ov = _http_get_json(
                f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asns[0]}",
                timeout=timeout,
            )
            holder = (ov.get("data", {}) or {}).get("holder")
        return {
            "ip": ip,
            "status": "ok",
            "asn": f"AS{asns[0]}" if asns else None,
            "all_asns": [f"AS{a}" for a in asns],
            "prefix": prefix,
            "holder": holder,
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {"ip": ip, "status": "lookup_unavailable", "error": str(exc)}


def attribute_origin(ip: str, timeout: float = 4.0) -> Dict[str, Any]:
    """Combined RDAP + ASN attribution for an attacker origin IP."""
    rdap = lookup_rdap(ip, timeout=timeout)
    asn = lookup_asn(ip, timeout=timeout)
    merged = dict(rdap)
    if asn.get("status") == "ok":
        merged["asn"] = asn.get("asn")
        merged["asn_holder"] = asn.get("holder")
        merged["announced_prefix"] = asn.get("prefix")
    return merged


def run_rea_static_analysis(target_path: str, timeout: int = 60) -> Dict[str, Any]:
    """Invoke REA statically (never executing the target) on a captured JS/ASAR/artifact."""
    path = Path(target_path).resolve()
    if not path.exists():
        return {"status": "error", "error": f"Target not found: {path}"}

    # Resolve npx explicitly: on Windows the executable is npx.cmd and a bare
    # ["npx", ...] without a shell fails to launch (finding #7).
    npx = shutil.which("npx") or (shutil.which("npx.cmd") if os.name == "nt" else None)
    if npx is None:
        return {
            "status": "unavailable",
            "target": str(path),
            "error": "npx not found on PATH; install Node.js to run the REA bridge",
        }

    cmd = [npx, "-y", "rea-agents@6.5.0", "analyze-javascript-application", str(path), "--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "status": "ok" if proc.returncode == 0 else "cli_error",
            "returncode": proc.returncode,
            "target": str(path),
            "stdout_preview": proc.stdout[:4000],
            "stderr_preview": proc.stderr[:1000],
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "unavailable", "target": str(path), "error": str(exc)}
