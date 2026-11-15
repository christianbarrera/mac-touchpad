"""Paired-device store.

Each approved phone makes its own P-256 key pair and keeps the private half
(non-extractable, in the Home Screen app's storage). Only the public key is
stored here, so this file holds nothing that lets anyone impersonate a phone.
Later connections prove possession by signing a fresh server nonce.

Legacy devices (paired before public keys, or by a browser without WebCrypto,
i.e. plain HTTP) hold a shared 256-bit key instead and answer with
HMAC-SHA256(key, nonce). They are upgraded in place the first time they connect
from a browser that can do public keys (see `rekey`).
"""
from __future__ import annotations

import hmac
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# Prefixed to the nonce before signing, so a signature can't be reused for anything else.
AUTH_CONTEXT = "mac-touchpad auth v1:"


def _load_pub(pub) -> ec.EllipticCurvePublicKey | None:
    """Public key from hex of the uncompressed P-256 point (65 bytes), or None."""
    if not isinstance(pub, str) or len(pub) != 130:
        return None
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pub))
    except ValueError:
        return None


def _sig_ok(pub: str, nonce: str, sig) -> bool:
    """`sig` is hex of r||s (64 bytes), as WebCrypto produces."""
    key = _load_pub(pub)
    if key is None or not isinstance(sig, str) or len(sig) != 128:
        return False
    try:
        raw = bytes.fromhex(sig)
    except ValueError:
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        key.verify(der, (AUTH_CONTEXT + nonce).encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _mac_ok(key_hex: str, nonce: str, mac) -> bool:
    if not isinstance(mac, str) or not mac.isascii():
        return False
    expected = hmac.new(bytes.fromhex(key_hex), nonce.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, mac.lower())


class DeviceStore:
    def __init__(self, path: Path):
        self.path = path
        self.devices: list[dict] = []
        self.load()

    def load(self):
        try:
            self.devices = json.loads(self.path.read_text()).get("devices", [])
        except (FileNotFoundError, ValueError):
            self.devices = []

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps({"devices": self.devices}, indent=2))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    @staticmethod
    def valid_pub(pub) -> bool:
        return _load_pub(pub) is not None

    def add(self, name: str, ip: str, pub: str | None = None) -> dict:
        """Add a phone. With `pub` it is a public-key device; without, a legacy shared-key one."""
        self.load()
        dev = {
            "id": secrets.token_hex(6),
            "name": name[:40] or "Phone",
            "paired_at": int(time.time()),
            "paired_ip": ip,
            "last_seen": int(time.time()),
        }
        if pub:
            dev["pub"] = pub.lower()
        else:
            dev["key"] = secrets.token_hex(32)
        self.devices.append(dev)
        self.save()
        return dev

    def get(self, dev_id: str) -> dict | None:
        return next((d for d in self.devices if d["id"] == dev_id), None)

    def verify(self, dev_id, nonce: str, mac=None, sig=None) -> dict | None:
        self.load()   # pick up `./touchpad forget` done while the server runs
        dev = self.get(str(dev_id))
        if not dev:
            return None
        ok = _sig_ok(dev["pub"], nonce, sig) if dev.get("pub") else _mac_ok(dev["key"], nonce, mac)
        if not ok:
            return None
        dev["last_seen"] = int(time.time())
        self.save()
        return dev

    def rekey(self, dev_id: str, pub) -> bool:
        """Upgrade a legacy shared-key device to a public key. Never replaces an existing public key."""
        self.load()
        dev = self.get(str(dev_id))
        if not dev or dev.get("pub") or not self.valid_pub(pub):
            return False
        dev["pub"] = pub.lower()
        dev.pop("key", None)
        self.save()
        return True

    def forget(self, dev_id: str) -> int:
        before = len(self.devices)
        self.devices = [] if dev_id == "all" else [d for d in self.devices if d["id"] != dev_id]
        self.save()
        return before - len(self.devices)
