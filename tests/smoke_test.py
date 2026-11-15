#!/usr/bin/env python3
"""End-to-end smoke test. Runs on macOS or Linux; no Accessibility permission needed.

Starts the server in --dry-run mode (input is logged, never injected) with a
throwaway HOME, then exercises the HTTPS app routes and plain-HTTP setup page,
the generated certificates, pairing (public-key and legacy shared-key), the
pairing lock and code, the Origin/Host checks and response headers, the setup
page closing once a phone is paired, the screen-lock and idle rules,
forgetting devices, and checks web/hmac.js against Python. All app and
WebSocket traffic goes over TLS, trusting only the server's own generated CA.

    .venv/bin/python tests/smoke_test.py        # exit code 0 = all passed
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import plistlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import aiohttp

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server" / "touchpad_server.py"
# Dry-run approves pairing without the Mac dialog only when this is set
# (inherited by every server this test starts, in-process or not).
os.environ["TOUCHPAD_TEST_AUTO_APPROVE"] = "1"
sys.path.insert(0, str(ROOT / "server"))
SSL: ssl.SSLContext | None = None   # trusts only the test server's CA; set in __main__
results: list[tuple[bool, str]] = []


def check(ok: bool, name: str, detail: str = ""):
    results.append((ok, name))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   ({detail})" if detail and not ok else ""), flush=True)


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def cli(home: str, *args) -> str:
    env = {**os.environ, "HOME": home}
    return subprocess.run([sys.executable, str(SERVER), *args], env=env, capture_output=True, text=True).stdout


async def ws_session(url: str, first, then=()):
    """Connect, answer hello with first(hello), optionally send `then` after auth. Returns server replies."""
    out = []
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=SSL)) as s:
        async with s.ws_connect(url) as ws:
            hello = json.loads((await ws.receive()).data)
            await ws.send_str(json.dumps(first(hello)))
            while True:
                try:
                    r = await asyncio.wait_for(ws.receive(), 1.5)
                except asyncio.TimeoutError:
                    break
                if r.type != aiohttp.WSMsgType.TEXT:
                    out.append({"t": "CLOSED"}); break
                m = json.loads(r.data); out.append(m)
                if m["t"] in ("paired", "auth_ok"):
                    for x in then:
                        await ws.send_str(json.dumps(x))
                    while True:      # anything the server says back to those
                        try:
                            r = await asyncio.wait_for(ws.receive(), 0.5)
                        except asyncio.TimeoutError:
                            break
                        if r.type != aiohttp.WSMsgType.TEXT:
                            break
                        out.append(json.loads(r.data))
                    break
    return out


async def ws_wait(url: str, first, want: str, timeout: float, keepalive=None) -> bool:
    """Authenticate, then wait up to `timeout` s for the server to send a `want` message."""
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=SSL)) as s:
        async with s.ws_connect(url) as ws:
            hello = json.loads((await ws.receive()).data)
            await ws.send_str(json.dumps(first(hello)))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    r = await asyncio.wait_for(ws.receive(), 1.0)
                except asyncio.TimeoutError:
                    if keepalive:
                        await ws.send_str(json.dumps(keepalive))
                    continue
                if r.type != aiohttp.WSMsgType.TEXT:
                    return False
                m = json.loads(r.data)
                if m["t"] == want:
                    return True
    return False


async def port_state(port: int, want_open: bool, timeout: float = 8.0) -> bool:
    """True once the port is open (or closed) as wanted, within `timeout` s."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close(); is_open = True
        except OSError:
            is_open = False
        if is_open == want_open:
            return True
        await asyncio.sleep(0.3)
    return False


class PhoneKey:
    """What the phone does with WebCrypto: a P-256 key pair, signing the Mac's nonce."""
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pub = self.priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()

    def sign(self, nonce: str) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s_ = decode_dss_signature(self.priv.sign(("mac-touchpad auth v1:" + nonce).encode(), ec.ECDSA(hashes.SHA256())))
        return (r.to_bytes(32, "big") + s_.to_bytes(32, "big")).hex()


def types(out):
    return [m["t"] + (":" + m["reason"] if "reason" in m else "") for m in out]


async def main(home: str, port: int, tls_port: int, log_path: Path, lock_file: Path):
    cfg = Path(home) / "Library/Application Support/mac-touchpad"
    token = (cfg / "token").read_text().strip()
    base = f"https://127.0.0.1:{tls_port}"
    url = f"wss://127.0.0.1:{tls_port}/{token}/ws"

    print("TLS")
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    leaf = x509.load_pem_x509_certificate((cfg / "tls/server.crt").read_bytes())
    ca_cert = x509.load_pem_x509_certificate((cfg / "tls/ca.crt").read_bytes())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    check("127.0.0.1" in [str(i) for i in san.get_values_for_type(x509.IPAddress)], "leaf cert has a SAN with the IP")
    days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days
    check(days <= 825, "leaf validity <= 825 days (iOS rule)", f"{days} days")
    check(ExtendedKeyUsageOID.SERVER_AUTH in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
          "leaf EKU serverAuth")
    nc = ca_cert.extensions.get_extension_for_class(x509.NameConstraints)
    check(nc.critical and x509.DNSName("local") in nc.value.permitted_subtrees, "CA name-constrained to .local + private IPs")
    modes = {f: oct((cfg / "tls" / f).stat().st_mode & 0o777) for f in ("ca.key", "server.key")}
    check(all(m == "0o600" for m in modes.values()), "private keys are mode 600", str(modes))
    try:
        async with aiohttp.ClientSession() as s:   # system trust store only
            async with s.get(base + "/"):
                pass
        check(False, "client that doesn't trust the CA is refused")
    except aiohttp.ClientConnectorCertificateError:
        check(True, "client that doesn't trust the CA is refused")
    curl = shutil.which("curl")
    if curl:
        r = subprocess.run([curl, "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--cacert",
                            str(cfg / "tls/ca.crt"), f"{base}/{token}/"], capture_output=True, text=True)
        check(r.stdout == "200", "curl --cacert works", r.stdout + r.stderr)
    tls_unit(cfg)

    print("Setup page (plain HTTP)")
    async with aiohttp.ClientSession() as s:
        hbase = f"http://127.0.0.1:{port}"
        async def get(path):
            async with s.get(hbase + path, allow_redirects=False) as r:
                return r.status, r.headers.get("Content-Type", ""), await r.read()
        st, _, body = await get(f"/{token}/")
        check(st == 200 and f"https://127.0.0.1:{tls_port}/{token}/".encode() in body,
              "setup page links to the HTTPS app", str(st))
        check(b"app.js" not in body and (await get(f"/{token}/app.js"))[0] == 404, "no app JS over plain HTTP")
        check((await get("/wrongcode/"))[0] == 404, "setup page needs the pairing code")
        st, ctype, body = await get(f"/{token}/touchpad-ca.mobileconfig")
        prof = plistlib.loads(body) if st == 200 else {}
        der = (cfg / "tls/ca.crt").read_bytes()
        der = ssl.PEM_cert_to_DER_cert(der.decode())
        check(ctype == "application/x-apple-aspen-config" and prof.get("PayloadContent", [{}])[0].get("PayloadContent") == der
              and prof["PayloadContent"][0]["PayloadType"] == "com.apple.security.root",
              ".mobileconfig carries the CA as a root payload", ctype)
        st, ctype, body = await get(f"/{token}/touchpad-ca.crt")
        check(st == 200 and body == der, ".crt download is the CA (DER)")
        check((await get("/"))[0] == 404, "setup port says nothing without the pairing code")
        async with s.get(hbase + f"/{token}/", headers={"Host": "evil.example"}) as r:
            check(r.status == 421, "setup page refuses a foreign Host name", str(r.status))
        async with s.get(hbase + f"/{token}/", headers={"Host": 'a"</script><script>alert(1)</script>'}) as r:
            body = await r.read()
            check(r.status == 421 and b"alert(1)" not in body, "setup page doesn't reflect a hostile Host header", str(r.status))

    print("HTTPS routes")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=SSL)) as s:
        async def status(path):
            async with s.get(base + path, allow_redirects=False) as r:
                return r.status, r.headers.get("Content-Type", "")
        check((await status("/"))[0] == 404, "nothing served outside the pairing-code path")
        async with s.get(base + f"/{token}/") as r:
            h = r.headers
            csp = h.get("Content-Security-Policy", "")
            check("script-src 'self'" in csp and f"wss://127.0.0.1:{tls_port}" in csp and "frame-ancestors 'none'" in csp,
                  "app has a Content-Security-Policy", csp)
            check(h.get("X-Content-Type-Options") == "nosniff" and h.get("Referrer-Policy") == "no-referrer"
                  and "Strict-Transport-Security" not in h, "hardening headers set (and no HSTS)")
            check(h.get("Server") == "mac-touchpad", "Server header doesn't reveal versions", h.get("Server", ""))
        async with s.get(base + f"/{token}/", headers={"Host": "evil.example"}) as r:
            check(r.status == 421, "foreign Host name refused (DNS rebinding)", str(r.status))
        for origin, want in (("https://evil.example", 403), (f"https://127.0.0.1:{tls_port}", 101)):
            try:
                async with s.ws_connect(url, headers={"Origin": origin}):
                    got = 101
            except aiohttp.WSServerHandshakeError as e:
                got = e.status
            check(got == want, f"WebSocket from {'another site' if want == 403 else 'our own page'} -> {want}", str(got))
        check((await status(f"/{token}/"))[0] == 200, "app served under the pairing-code path")
        check((await status("/wrongcode/"))[0] == 404, "wrong pairing code -> 404")
        check((await status(f"/{token}/..%2Ftouchpad"))[0] == 404, "path traversal -> 404")
        check("manifest+json" in (await status(f"/{token}/manifest.webmanifest"))[1], "manifest content type")
        check((await status(f"/{token}/hmac.js"))[0] == 200, "hmac.js served")
        check("javascript" in (await status(f"/{token}/sw.js"))[1], "service worker served as JS")

    print("Pairing + auth")
    hellos = []
    out = await ws_session(url, lambda h: (hellos.append(h), {"t": "c", "b": "l"})[1])
    check(out == [], "input before auth is ignored", str(out))
    nat = hellos[0].get("natural") if hellos else "missing"
    check(nat is None or isinstance(nat, bool), "hello reports the Mac's scroll direction", repr(nat))

    out = await ws_session(url, lambda h: {"t": "pair", "name": "TestPhone"}, [{"t": "c", "b": "l"}])
    check(types(out) == ["pair_wait", "paired"], "first phone can pair (dry-run auto-approves)", str(types(out)))
    code = out[0].get("code", "") if out else ""
    check(len(code) == 4 and code.isdigit(), "phone is given a 4-digit code to type on the Mac", repr(code))
    dev = next((m for m in out if m["t"] == "paired"), None)
    if not dev:
        return
    check(await port_state(port, False), "setup page (plain HTTP) closes once a phone is paired")
    mac = lambda nonce: hmac.new(bytes.fromhex(dev["key"]), nonce.encode(), hashlib.sha256).hexdigest()

    out = await ws_session(url, lambda h: {"t": "auth", "id": dev["id"], "mac": mac(h["nonce"])}, [{"t": "c", "b": "r"}])
    check(types(out) == ["auth_ok"], "paired phone authenticates with its key", str(types(out)))
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev["id"], "mac": "00" * 32})
    check(types(out) == ["auth_fail", "CLOSED"], "wrong key -> auth_fail + close", str(types(out)))
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev["id"], "mac": mac("old-nonce")})
    check(types(out) == ["auth_fail", "CLOSED"], "replayed answer -> auth_fail", str(types(out)))
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev["id"], "mac": "é" * 64})
    check(types(out) == ["auth_fail", "CLOSED"], "malformed answer -> auth_fail (no crash)", str(types(out)))

    print("Screen lock")
    lock_file.touch()
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev["id"], "mac": mac(h["nonce"])}, [{"t": "k", "k": "tab"}])
    lock_file.unlink()
    await asyncio.sleep(0.2)
    check(types(out) == ["auth_ok", "locked"] and "key('tab'" not in log_path.read_text(),
          "input is ignored while the Mac is locked", str(types(out)))

    print("Pairing lock")
    out = await ws_session(url, lambda h: {"t": "pair", "name": "Intruder"})
    check(types(out) == ["pair_denied:closed", "CLOSED"], "second phone refused while pairing is closed", str(types(out)))
    cli(home, "--open-pairing")
    check(await port_state(port, True), "`touchpad pair` reopens the setup page")
    out = await ws_session(url, lambda h: {"t": "pair", "name": "Phone2\n\nfake line\x07"})
    check(types(out) == ["pair_wait", "paired"], "`touchpad pair` lets one more phone pair", str(types(out)))
    dev2 = next((m for m in out if m["t"] == "paired"), {})
    check(dev2.get("name") == "Phone2 fake line", "device name is flattened to one printable line", repr(dev2.get("name")))
    out = await ws_session(url, lambda h: {"t": "pair", "name": "Intruder2"})
    check(types(out) == ["pair_denied:closed", "CLOSED"], "pairing window closes after one phone", str(types(out)))

    print("Public-key phones")
    devices = lambda: {d["id"]: d for d in json.loads((cfg / "devices.json").read_text())["devices"]}
    k2 = PhoneKey()
    mac2 = lambda nonce: hmac.new(bytes.fromhex(dev2["key"]), nonce.encode(), hashlib.sha256).hexdigest()
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev2["id"], "mac": mac2(h["nonce"])}, [{"t": "rekey", "pub": k2.pub}])
    stored = devices().get(dev2["id"], {})
    check(types(out) == ["auth_ok", "rekeyed"] and out[0].get("pk") is False and "key" not in stored and stored.get("pub") == k2.pub,
          "shared-key phone upgrades itself to a public key", str(out))
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev2["id"], "mac": mac2(h["nonce"])})
    check(types(out) == ["auth_fail", "CLOSED"], "old shared key stops working after the upgrade", str(types(out)))
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev2["id"], "mac": mac2(h["nonce"]), "sig": k2.sign(h["nonce"])},
                           [{"t": "rekey", "pub": PhoneKey().pub}])
    check(types(out) == ["auth_ok"] and out[0].get("pk") is True and devices()[dev2["id"]]["pub"] == k2.pub,
          "signs in with its signature; an existing public key can't be swapped", str(out))
    cli(home, "--open-pairing")
    out = await ws_session(url, lambda h: {"t": "pair", "name": "Bad", "pub": "04" + "00" * 64})
    check(types(out) == ["pair_denied:badkey", "CLOSED"], "invalid public key refused", str(types(out)))
    k3 = PhoneKey()
    out = await ws_session(url, lambda h: {"t": "pair", "name": "Phone3", "pub": k3.pub})
    dev3 = next((m for m in out if m["t"] == "paired"), {})
    check(types(out) == ["pair_wait", "paired"] and "key" not in dev3 and dev3.get("pk") is True
          and "key" not in devices().get(dev3.get("id"), {"key": 1}),
          "new phone pairs with a public key: no secret sent or stored on the Mac", str(out))
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev3["id"], "sig": k3.sign(h["nonce"])})
    check(types(out) == ["auth_ok"], "public-key phone authenticates", str(types(out)))
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev3["id"], "sig": k2.sign(h["nonce"])})
    check(types(out) == ["auth_fail", "CLOSED"], "another phone's signature -> auth_fail", str(types(out)))
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev3["id"], "sig": k3.sign("old-nonce")})
    check(types(out) == ["auth_fail", "CLOSED"], "replayed signature -> auth_fail", str(types(out)))

    print("Idle + forget (takes ~15 s)")
    auth3 = lambda h: {"t": "auth", "id": dev3["id"], "sig": k3.sign(h["nonce"])}
    check(await ws_wait(url, auth3, "idle", 12), "a phone that sends nothing is disconnected")
    kicked = asyncio.ensure_future(ws_wait(url, auth3, "auth_fail", 12, keepalive={"t": "s", "x": 0, "y": 0}))
    await asyncio.sleep(1.5)
    await asyncio.to_thread(cli, home, "--forget", dev3["id"])
    check(await kicked, "forgetting a phone disconnects it while it's connected")

    print("Forget")
    cli(home, "--forget", "all")
    out = await ws_session(url, lambda h: {"t": "auth", "id": dev["id"], "mac": mac(h["nonce"])})
    check(types(out) == ["auth_fail", "CLOSED"], "forgotten phone is refused (no restart needed)", str(types(out)))

    await asyncio.sleep(0.3)
    log = log_path.read_text()
    check("Phone2 fake line" in log and "fake line\x07" not in log, "log lines can't be forged through the device name")
    check(log.count("[dry-run] click('l',)") == 1, "exactly one left click injected (only the authed one)",
          f"{log.count(chr(91) + 'dry-run] click(' + chr(39) + 'l' + chr(39) + ',)')} found")
    check(log.count("[dry-run] click('r',)") == 1, "right click from authed session injected")


def tls_unit(cfg: Path) -> None:
    """Re-issue logic on a scratch copy of the CA (doesn't touch the running server's files)."""
    from tls import LocalCA
    d = Path(tempfile.mkdtemp(prefix="touchpad-tls-"))
    try:
        for f in ("ca.crt", "ca.key"):
            shutil.copy(cfg / "tls" / f, d / f)
        ca = LocalCA(d); ca.ensure_ca()
        first = ca.ensure_leaf(["mac.local", "192.168.1.5"])
        same = ca.ensure_leaf(["192.168.1.5", "MAC.local"])
        moved = ca.ensure_leaf(["mac.local", "10.0.0.7"])
        check(first and not same and moved, "leaf re-issued only when the name/IP set changes", f"{first} {same} {moved}")
        ca.ensure_leaf(["mac.local", "8.8.8.8", "example.com"])
        check(ca.leaf_names() == (["mac.local"], []), "public IPs / non-.local names left out of the leaf",
              str(ca.leaf_names()))
        # Force a leaf outside the constraints: OpenSSL must refuse it when verifying the chain.
        import tls
        orig, tls.permitted = tls.permitted, (lambda n: True)
        try:
            ca.ensure_leaf(["evil.example.com"])
        finally:
            tls.permitted = orig
        client = ssl.create_default_context(cafile=str(d / "ca.crt"))
        try:
            ok = _handshake(ca.server_context(), client, "evil.example.com")
        except ssl.SSLCertVerificationError:
            ok = False
        check(not ok, "CA can't vouch for names outside .local (name constraints)")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _handshake(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext, name: str) -> bool:
    """In-memory TLS handshake; True if the client accepts the server's cert for `name`."""
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    cli_obj = client_ctx.wrap_bio(c_in, c_out, server_hostname=name)
    srv_obj = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        for obj in (cli_obj, srv_obj):
            try:
                obj.do_handshake()
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read()); c_in.write(s_out.read())
        try:
            cli_obj.do_handshake(); return True
        except ssl.SSLWantReadError:
            continue
    return False


class _MemoryStore:
    """Stand-in for the keychain in tests. `drop_writes` simulates a write that doesn't stick."""

    def __init__(self, data=None, drop_writes=False):
        self.data, self.drop_writes, self.location = data, drop_writes, "memory store"

    def load(self):
        return self.data

    def save(self, data):
        if not self.drop_writes:
            self.data = data

    def delete(self):
        self.data = None


def keystore_unit() -> None:
    """CA key storage and the file -> keychain migration, with an in-memory stand-in for the keychain."""
    print("CA key store + migration")
    from keystore import FileKeyStore, KeyStoreError, migrate
    from tls import CAKeyUnavailable, LocalCA
    d = Path(tempfile.mkdtemp(prefix="touchpad-keys-"))
    try:
        ca = LocalCA(d); ca.ensure_ca()
        key_file = d / "ca.key"
        check(key_file.exists() and oct(key_file.stat().st_mode & 0o777) == "0o600", "file store: new CA key is mode 600")
        fp = ca.fingerprint
        lazy = LocalCA(d); lazy.ensure_ca()
        check(lazy._ca_key is None and lazy.fingerprint == fp, "existing CA: certificate loaded, key not read yet")

        # The keychain-equivalent store gets the key; the file is deleted only after it checks out.
        mem = _MemoryStore()
        original = key_file.read_bytes()
        result = migrate(FileKeyStore(key_file), mem, lazy.ca_cert)
        check(result == "moved" and mem.data == original and not key_file.exists(),
              "migration moves the key and deletes the file", f"{result} file={key_file.exists()}")
        check(migrate(FileKeyStore(key_file), mem, lazy.ca_cert) == "none", "migration with no file does nothing")
        moved = LocalCA(d, [mem, FileKeyStore(key_file)]); moved.ensure_ca()
        check(moved.ensure_leaf(["mac.local"]) and moved.key_location == "memory store",
              "after migration the leaf is signed with the key from the new store")

        # Failure cases keep the file.
        FileKeyStore(key_file).save(original)
        try:
            migrate(FileKeyStore(key_file), _MemoryStore(drop_writes=True), lazy.ca_cert); ok = False
        except KeyStoreError:
            ok = key_file.exists()
        check(ok, "write that doesn't read back: file kept")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        other = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        try:
            migrate(FileKeyStore(key_file), _MemoryStore(other), lazy.ca_cert); ok = False
        except KeyStoreError:
            ok = key_file.exists()
        check(ok, "store already holding a different key: file kept")
        stray = d / "stray.key"; FileKeyStore(stray).save(other)
        try:
            migrate(FileKeyStore(stray), _MemoryStore(), lazy.ca_cert); ok = False
        except KeyStoreError:
            ok = stray.exists()
        check(ok, "file key that doesn't match ca.crt: refused, file kept")

        # Key missing: the CA certificate phones trust is never silently replaced.
        key_file.unlink()
        cert_before = (d / "ca.crt").read_bytes()
        gone = LocalCA(d); gone.ensure_ca()
        try:
            gone.ensure_leaf(["elsewhere.local"]); ok = False
        except CAKeyUnavailable:
            ok = True
        check(ok and (d / "ca.crt").read_bytes() == cert_before,
              "missing CA key: clear error, CA certificate left alone")

        # Reset writes the new key to the first store and removes the old copy elsewhere.
        FileKeyStore(key_file).save(original)
        mem2 = _MemoryStore()
        reset = LocalCA(d, [mem2, FileKeyStore(key_file)]); reset.ensure_ca(reset=True)
        check(mem2.data is not None and not key_file.exists() and reset.fingerprint != fp,
              "reset: new key in the first store, old file removed")
    finally:
        shutil.rmtree(d, ignore_errors=True)


_EMBED = r"""
import asyncio, json, socket, sys, threading, time
sys.path.insert(0, sys.argv[1])
import touchpad_server as ts
from dryrun import DryRunInput
port, tls_port = sys.argv[2], int(sys.argv[3])
args = ts.build_parser().parse_args(["--dry-run", "--any-network", "--no-qr", "--host", "127.0.0.1",
                                     "--port", port, "--tls-port", str(tls_port)])
srv = ts.Server(args, DryRunInput(), key_stores=ts.ca_key_stores("file"), exit_on_bind_error=False)
t = threading.Thread(target=lambda: asyncio.run(srv.serve()), daemon=True)
t.start()

def is_open():
    try:
        socket.create_connection(("127.0.0.1", tls_port), 0.3).close(); return True
    except OSError:
        return False

def wait(want, secs=4):
    end = time.time() + secs
    while time.time() < end:
        if is_open() == want:
            return True
        time.sleep(0.1)
    return False

r = {"up": wait(True)}
srv.set_enabled(False)
r["off"] = wait(False) and srv.status()["reason"] == "turned off" and not srv.status()["listening"]
srv.set_enabled(True)
r["on"] = wait(True) and srv.status()["listening"] == "127.0.0.1"
srv.set_allow_when_locked(True)
r["policy"] = srv.app["policy"]["block_when_locked"] is False
srv.stop(); t.join(6)
r["stopped"] = not t.is_alive() and not is_open()
print("RESULT " + json.dumps(r))
"""


def embedded_server_and_settings() -> None:
    """The menu bar app runs Server in a background thread; check that path and the settings file."""
    print("Embedded server (menu bar app path) + settings")
    home = tempfile.mkdtemp(prefix="touchpad-embed-")
    try:
        env = {**os.environ, "HOME": home}
        r = subprocess.run([sys.executable, "-c", _EMBED, str(ROOT / "server"), str(free_port()), str(free_port())],
                           env=env, capture_output=True, text=True, timeout=60)
        line = next((l for l in r.stdout.splitlines() if l.startswith("RESULT ")), None)
        res = json.loads(line[7:]) if line else {}
        detail = (r.stdout + r.stderr)[-800:]
        check(res.get("up", False), "server runs in a background thread", detail)
        check(res.get("off", False), "turning it off stops listening", detail)
        check(res.get("on", False), "turning it back on listens again", detail)
        check(res.get("policy", False), "lock-screen rule changes while running", detail)
        check(res.get("stopped", False), "stop() shuts it down cleanly", detail)
        cfg = Path(home) / "Library/Application Support/mac-touchpad"
        out = cli(home, "--set", "allow_when_locked=on")
        settings = json.loads((cfg / "settings.json").read_text())
        check(settings == {"allow_when_locked": True} and oct((cfg / "settings.json").stat().st_mode & 0o777) == "0o600",
              "--set saves the app setting (mode 600)", out)
        bad = subprocess.run([sys.executable, str(SERVER), "--set", "evil=on"], env=env, capture_output=True, text=True)
        check(bad.returncode != 0 and json.loads((cfg / "settings.json").read_text()) == settings,
              "--set refuses unknown settings")
    finally:
        shutil.rmtree(home, ignore_errors=True)



_NO_AUTO = r"""
import asyncio, json, os, sys, threading
sys.path.insert(0, sys.argv[1])
os.environ.pop("TOUCHPAD_TEST_AUTO_APPROVE", None)
import aiohttp
import touchpad_server as ts
from dryrun import DryRunInput
asked = []
async def fake_dialog(name, ip, code):      # stands in for the osascript dialog
    asked.append(code)
    return "refused"
ts.ask_mac_user_to_pair = fake_dialog
port = sys.argv[2]
args = ts.build_parser().parse_args(["--dry-run", "--no-tls", "--any-network", "--no-qr", "--no-notify",
                                     "--host", "127.0.0.1", "--port", port])
srv = ts.Server(args, DryRunInput(), key_stores=ts.ca_key_stores("file"), exit_on_bind_error=False)
t = threading.Thread(target=lambda: asyncio.run(srv.serve()), daemon=True)
t.start()

async def pair():
    for _ in range(50):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.ws_connect(f"ws://127.0.0.1:{port}/{srv.token}/ws") as ws:
                    await ws.receive()
                    await ws.send_str(json.dumps({"t": "pair", "name": "intruder"}))
                    out = []
                    while not out or out[-1] not in ("paired", "pair_denied"):
                        m = await asyncio.wait_for(ws.receive(), 5)
                        if m.type != aiohttp.WSMsgType.TEXT:
                            break
                        out.append(json.loads(m.data)["t"])
                    return out
        except aiohttp.ClientConnectorError:
            await asyncio.sleep(0.1)
    return None

out = asyncio.run(pair())
srv.stop(); t.join(6)
srv.store.load()
print("RESULT " + json.dumps({"out": out, "asked": len(asked), "devices": len(srv.store.devices)}))
"""


def dry_run_still_asks() -> None:
    """Dry-run shares the real devices.json, so it must not approve pairing by itself."""
    print("Dry-run pairing without the test switch")
    home = tempfile.mkdtemp(prefix="touchpad-noauto-")
    try:
        env = {k: v for k, v in os.environ.items() if k != "TOUCHPAD_TEST_AUTO_APPROVE"}
        env["HOME"] = home
        r = subprocess.run([sys.executable, "-c", _NO_AUTO, str(ROOT / "server"), str(free_port())],
                           env=env, capture_output=True, text=True, timeout=60)
        line = next((l for l in r.stdout.splitlines() if l.startswith("RESULT ")), None)
        res = json.loads(line[7:]) if line else {}
        detail = (r.stdout + r.stderr)[-800:]
        check(res.get("asked") == 1, "dry-run still asks on the Mac before pairing", detail)
        check(res.get("out") == ["pair_wait", "pair_denied"] and res.get("devices") == 0,
              "a refused dry-run pairing saves no device", detail)
    finally:
        shutil.rmtree(home, ignore_errors=True)

def hmac_js_matches() -> None:
    print("web/hmac.js")
    node = shutil.which("node")
    if not node:
        print("  SKIP  node not installed"); return
    key, msg = "ab" * 32, "nonce-1234567890"
    js = (f"require({json.dumps(str(ROOT / 'web' / 'hmac.js'))});"
          f"process.stdout.write(globalThis.MTPCrypto.hmacSha256Hex({json.dumps(key)}, {json.dumps(msg)}))")
    got = subprocess.run([node, "-e", js], capture_output=True, text=True).stdout.strip()
    want = hmac.new(bytes.fromhex(key), msg.encode(), hashlib.sha256).hexdigest()
    check(got == want, "JS HMAC-SHA256 == Python", f"{got} != {want}")


if __name__ == "__main__":
    home = tempfile.mkdtemp(prefix="touchpad-test-")
    port, tls_port = free_port(), free_port()
    log_path = Path(home) / "server.log"
    lock_file = Path(home) / "pretend-locked"
    env = {**os.environ, "HOME": home, "TOUCHPAD_TEST_LOCK_FILE": str(lock_file)}
    with open(log_path, "w") as log:
        proc = subprocess.Popen([sys.executable, str(SERVER), "--dry-run", "--any-network", "--no-qr",
                                 "--idle-timeout", "0.05",      # 3 s, so the idle rule can be tested
                                 "--port", str(port), "--tls-port", str(tls_port)], env=env, stdout=log, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL)
    try:
        for p in (tls_port, port):
            for _ in range(50):
                try:
                    socket.create_connection(("127.0.0.1", p), 0.2).close(); break
                except OSError:
                    time.sleep(0.1)
        SSL = ssl.create_default_context(cafile=str(Path(home) / "Library/Application Support/mac-touchpad/tls/ca.crt"))
        asyncio.run(main(home, port, tls_port, log_path, lock_file))
        hmac_js_matches()
        keystore_unit()
        embedded_server_and_settings()
        dry_run_still_asks()
    finally:
        proc.terminate(); proc.wait(5)
        if any(not ok for ok, _ in results):
            print("\n--- server log ---\n" + log_path.read_text())
        shutil.rmtree(home, ignore_errors=True)
    failed = [n for ok, n in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; FAILED: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)
