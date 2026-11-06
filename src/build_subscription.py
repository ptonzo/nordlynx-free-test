#!/usr/bin/env python3
"""Build a Happ-compatible subscription from public community feeds.

This is a personal test aggregator, not a VPN provider. TCP reachability is
only a weak liveness signal; it does not prove proxy authentication or traffic.
"""
from __future__ import annotations
import base64
import concurrent.futures
import json
import os
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, unquote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SUB_FILE = OUT / "sub.txt"
STATUS_FILE = OUT / "status.json"
MIN_NODES = int(os.getenv("MIN_NODES", "20"))
MIN_COUNTRIES = int(os.getenv("MIN_COUNTRIES", "5"))
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "3.0"))
MAX_PER_COUNTRY = int(os.getenv("MAX_PER_COUNTRY", "8"))
SOURCES = [x.strip() for x in os.getenv("SOURCES", "").splitlines() if x.strip()]
if not SOURCES:
    SOURCES = [
        "https://radarhub.top/v2ray.txt",
        "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/all.txt",
    ]
ALLOWED = ("vless://", "vmess://", "trojan://", "ss://", "socks://")

COUNTRY_PATTERNS = [
    ("🇺🇸", "United States"), ("🇩🇪", "Germany"), ("🇳🇱", "Netherlands"),
    ("🇯🇵", "Japan"), ("🇸🇬", "Singapore"), ("🇬🇧", "United Kingdom"),
    ("🇫🇷", "France"), ("🇰🇷", "South Korea"), ("🇭🇰", "Hong Kong"),
    ("🇹🇼", "Taiwan"), ("🇨🇦", "Canada"), ("🇨🇭", "Switzerland"),
    ("🇸🇪", "Sweden"), ("🇫🇮", "Finland"), ("🇵🇱", "Poland"),
    ("🇮🇹", "Italy"), ("🇪🇸", "Spain"), ("🇹🇷", "Turkey"),
    ("🇦🇺", "Australia"), ("🇧🇷", "Brazil"), ("🇮🇳", "India"),
    ("🇷🇺", "Russia"), ("🇺🇦", "Ukraine"), ("🇨🇿", "Czechia"),
    ("🇦🇹", "Austria"), ("🇧🇪", "Belgium"), ("🇳🇴", "Norway"),
    ("🇩🇰", "Denmark"), ("🇮🇪", "Ireland"), ("🇷🇴", "Romania"),
]


def decode_feed(raw: str) -> str:
    text = raw.strip().lstrip("\ufeff")
    if not text:
        return ""
    # Most V2Ray subscription endpoints return one Base64 payload.
    if not re.search(r"(?m)^(?:vless|vmess|trojan|ss|socks)://", text, re.I):
        compact = re.sub(r"\s+", "", text)
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False).decode("utf-8", "ignore")
            if re.search(r"(?m)^(?:vless|vmess|trojan|ss|socks)://", decoded, re.I):
                return decoded
        except Exception:
            pass
    return text


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "NORDLYNX-Free-Test-Aggregator/1.0"})
    with urlopen(req, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {url}")
        return decode_feed(response.read(8_000_000).decode("utf-8", "ignore"))


def parse_host_port(uri: str):
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "vmess":
        payload = uri[8:]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
        return str(data.get("add", "")), int(data.get("port", 0))
    if scheme == "ss":
        body = uri[5:].split("#", 1)[0].split("?", 1)[0]
        if "@" not in body:
            body += "=" * (-len(body) % 4)
            body = base64.urlsafe_b64decode(body.encode()).decode()
        authority = body.rsplit("@", 1)[-1]
        p = urlsplit("//" + authority)
        return p.hostname or "", p.port or 0
    p = urlsplit(uri)
    return p.hostname or "", p.port or 0


def country_from_uri(uri: str) -> str | None:
    label = unquote(uri.rsplit("#", 1)[-1]) if "#" in uri else ""
    for flag, country in COUNTRY_PATTERNS:
        if flag in label:
            return country
    low = label.lower()
    for _, country in COUNTRY_PATTERNS:
        if country.lower() in low:
            return country
    # Two-letter ISO labels are common in public node feeds.
    aliases = {"us":"United States", "de":"Germany", "nl":"Netherlands", "jp":"Japan", "sg":"Singapore", "gb":"United Kingdom", "fr":"France", "kr":"South Korea", "hk":"Hong Kong", "tw":"Taiwan", "ca":"Canada", "ch":"Switzerland", "se":"Sweden", "fi":"Finland", "pl":"Poland", "it":"Italy", "es":"Spain", "tr":"Turkey", "au":"Australia", "br":"Brazil", "in":"India", "ru":"Russia", "ua":"Ukraine", "cz":"Czechia", "at":"Austria", "be":"Belgium", "no":"Norway", "dk":"Denmark", "ie":"Ireland", "ro":"Romania"}
    m = re.search(r"(?:^|[\s_\-\[])((?:" + "|".join(aliases) + r"))(?:$|[\s_\-\]])", low)
    return aliases.get(m.group(1)) if m else None


def tcp_alive(uri: str) -> bool:
    try:
        host, port = parse_host_port(uri)
        if not host or not (1 <= port <= 65535):
            return False
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    all_uris: dict[str, str] = {}
    errors = []
    for source in SOURCES:
        try:
            body = fetch(source)
            for line in body.splitlines():
                line = line.strip()
                if line.lower().startswith(ALLOWED):
                    all_uris.setdefault(line, source)
        except Exception as exc:
            errors.append(f"{source}: {type(exc).__name__}: {exc}")

    candidates = []
    for uri in all_uris:
        country = country_from_uri(uri)
        if country:
            candidates.append((uri, country))

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as pool:
        futures = {pool.submit(tcp_alive, uri): (uri, country) for uri, country in candidates}
        for future in concurrent.futures.as_completed(futures):
            uri, country = futures[future]
            if future.result():
                alive.append((uri, country))

    # Spread selection across countries, then fill remaining slots by feed order.
    by_country: dict[str, list[str]] = {}
    for uri, country in alive:
        by_country.setdefault(country, []).append(uri)
    selected = []
    for country in sorted(by_country):
        selected.extend((uri, country) for uri in by_country[country][:MAX_PER_COUNTRY])
    selected = selected[: max(MIN_NODES, MIN_NODES * 3)]
    countries = sorted({country for _, country in selected})

    status = {
        "project": "NORDLYNX VPN — public community nodes test",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": SOURCES,
        "source_errors": errors,
        "unique_candidates_with_country_label": len(candidates),
        "tcp_reachable_nodes": len(alive),
        "selected_nodes": len(selected),
        "countries": countries,
        "minimum_nodes": MIN_NODES,
        "minimum_countries": MIN_COUNTRIES,
        "status": "ok" if len(selected) >= MIN_NODES and len(countries) >= MIN_COUNTRIES else "below_threshold",
        "warning": "TCP reachability is not an end-to-end VPN test. Operators are third parties; do not use for sensitive accounts or commercial resale without permission.",
    }

    if len(selected) < MIN_NODES or len(countries) < MIN_COUNTRIES:
        STATUS_FILE.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(status, ensure_ascii=False, indent=2))
        print("Threshold not met: refusing to overwrite/publish subscription.", file=sys.stderr)
        return 2

    lines = [
        "#profile-title: NORDLYNX TEST",
        "#profile-update-interval: 1",
        "# NORDLYNX aggregates third-party public nodes; not operated or security-audited by us.",
    ]
    lines.extend(uri for uri, _country in selected[: max(MIN_NODES, MIN_NODES * 3)])
    SUB_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    STATUS_FILE.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(status, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
