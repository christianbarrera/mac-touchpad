"""Trusted-network detection.

The server only listens while the Mac is on a network you've approved.
A network is identified by a fingerprint of its DHCP details (see
current_network). Stored in networks.json next to the device list.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path


def _run(*cmd) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _dhcp_field(packet: str, name: str) -> str:
    m = re.search(rf"^{name}\s*\([^)]*\):\s*\{{?([^}}\n]*)", packet, re.M)
    return m.group(1).strip() if m else ""


def current_network() -> dict | None:
    """Identify the network the Mac is on, without Location or Local Network permission.

    Fingerprint = router IP + DHCP server + subnet mask + DHCP domain name
    (macOS hides the Wi-Fi name and BSSID from unprivileged processes, and the
    ARP table is off-limits too). This is meant to keep the server quiet in
    cafés and hotels, not to resist a deliberately cloned network.
    Returns {'id', 'label', 'gateway', 'iface', 'ip'} or None (offline / VPN-only).
    'ip' is this Mac's address on that interface (None if it can't be read).
    """
    route = _run("route", "-n", "get", "default")
    gw = re.search(r"gateway:\s*(\S+)", route)
    iface = re.search(r"interface:\s*(\S+)", route)
    if not gw or not iface or iface.group(1).startswith(("utun", "ipsec", "ppp")):
        return None
    gw_ip, ifname = gw.group(1), iface.group(1)
    packet = _run("ipconfig", "getpacket", ifname)
    server = _dhcp_field(packet, "server_identifier")
    mask = _dhcp_field(packet, "subnet_mask")
    domain = _dhcp_field(packet, "domain_name")
    if not packet:  # static IP: fall back to router + netmask from ifconfig
        m = re.search(r"netmask (0x[0-9a-f]+)", _run("ifconfig", ifname))
        mask = m.group(1) if m else ""
    raw = "|".join([gw_ip, server, mask, domain])
    net_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
    label = (domain + " " if domain else "") + f"(router {gw_ip})"
    ip = _run("ipconfig", "getifaddr", ifname).strip() or None
    return {"id": net_id, "label": label, "gateway": gw_ip, "iface": ifname, "ip": ip}


class NetworkTrust:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> list[dict]:
        try:
            return json.loads(self.path.read_text()).get("networks", [])
        except (FileNotFoundError, ValueError):
            return []

    def save(self, nets: list[dict]):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"networks": nets}, indent=2))
        os.chmod(self.path, 0o600)

    def is_trusted(self, net: dict | None) -> bool:
        return bool(net) and any(n.get("id") == net["id"] for n in self.load())

    def trust(self, net: dict, label: str = "") -> bool:
        nets = self.load()
        if any(n.get("id") == net["id"] for n in nets):
            return False
        nets.append({"id": net["id"], "label": label or net["label"],
                     "gateway": net["gateway"], "added": int(time.time())})
        self.save(nets)
        return True

    def untrust(self, key: str) -> int:
        nets = self.load()
        keep = [] if key == "all" else [n for n in nets if key not in (n.get("id"), n["label"], n["gateway"])]
        self.save(keep)
        return len(nets) - len(keep)
