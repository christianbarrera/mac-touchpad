#!/usr/bin/env python3
"""Mac Touchpad server.

Serves the phone web app over HTTPS and accepts a secure WebSocket on the same
port. A plain-HTTP port serves only the one-time setup page (certificate profile
for the phone), never the app itself. Touch gestures arriving from the phone
become real cursor moves, clicks, scrolls and key presses via Quartz CGEvent.

Run via ../touchpad (handles the venv) or:  python server/touchpad_server.py --help
"""
from __future__ import annotations

import argparse
import asyncio
import hmac
import html
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import socket
import string
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import WSMsgType, web

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
CONFIG_DIR = Path.home() / "Library" / "Application Support" / "mac-touchpad"
TOKEN_FILE = CONFIG_DIR / "token"
DEVICES_FILE = CONFIG_DIR / "devices.json"
NETWORKS_FILE = CONFIG_DIR / "networks.json"
PAIR_WINDOW_FILE = CONFIG_DIR / "pairing-open-until"
TLS_DIR = CONFIG_DIR / "tls"
SETUP_TEMPLATE = Path(__file__).resolve().parent / "setup.html"
SETUP_WINDOW_FILE = CONFIG_DIR / "setup-open-until"
PAIR_WINDOW_S = 120
SETUP_WINDOW_S = 900       # how long `./touchpad pair` keeps the plain-HTTP setup page reachable
IDLE_TIMEOUT_MIN = 10      # a connected phone that sends no input for this long is disconnected
DEFAULT_PORT = 8765        # plain HTTP: setup page + certificate profile, only while adding a phone (the whole app with --no-tls)
DEFAULT_TLS_PORT = 8766    # HTTPS: the app + secure WebSocket
SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"


# --------------------------------------------------------------------------- #
# Network helpers
# --------------------------------------------------------------------------- #

def lan_ip() -> str | None:
    """IP of the interface that would route to the LAN (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") else ip
    except OSError:
        return None
    finally:
        s.close()


def lan_ips() -> list[str]:
    """All non-loopback IPv4s of this machine (the server certificate covers each)."""
    ips = set()
    for cmd in (["ifconfig"], ["ip", "-o", "-4", "addr", "show"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        ips.update(re.findall(r"\binet (?:addr:)?(\d{1,3}(?:\.\d{1,3}){3})", out))
        if ips:
            break
    ip = lan_ip()
    if ip:
        ips.add(ip)
    return sorted(ip for ip in ips if not ip.startswith("127.") and ip != "0.0.0.0")


def cert_names() -> list[str]:
    """What the server certificate should cover right now."""
    host = bonjour_hostname()
    return [n for n in (host, "localhost", "127.0.0.1", *lan_ips()) if n]


_bonjour_cache: list = [-1e9, None]


def bonjour_hostname() -> str | None:
    """macOS already advertises <LocalHostName>.local over Bonjour/mDNS. Cached for 30 s."""
    if time.monotonic() - _bonjour_cache[0] > 30:
        try:
            name = subprocess.run(["scutil", "--get", "LocalHostName"], capture_output=True, text=True, timeout=2).stdout.strip()
            _bonjour_cache[1] = f"{name}.local" if name else None
        except Exception:
            _bonjour_cache[1] = None
        _bonjour_cache[0] = time.monotonic()
    return _bonjour_cache[1]


def mac_natural_scrolling() -> bool | None:
    """The Mac's own trackpad/mouse scroll direction (System Settings > Trackpad).

    True = natural (content follows fingers), False = traditional, None = unknown.
    The key is absent until the user changes it; macOS's default is natural."""
    if sys.platform != "darwin":
        return None
    try:
        r = subprocess.run(["defaults", "read", "-g", "com.apple.swipescrolldirection"],
                           capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return True
    return r.stdout.strip() not in ("0", "false", "NO")


def load_token(reset: bool = False) -> str:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if TOKEN_FILE.exists() and not reset:
        tok = TOKEN_FILE.read_text().strip()
        if tok:
            return tok
    alphabet = string.ascii_lowercase + string.digits
    tok = "".join(secrets.choice(alphabet) for _ in range(8))
    TOKEN_FILE.write_text(tok + "\n")
    os.chmod(TOKEN_FILE, 0o600)
    return tok


def urls(port: int, token: str, scheme: str = "http") -> dict:
    out = {}
    host = bonjour_hostname()
    ip = lan_ip()
    if host:
        out["bonjour"] = f"{scheme}://{host}:{port}/{token}/"
    if ip:
        out["ip"] = f"{scheme}://{ip}:{port}/{token}/"
    return out


def print_banner(port: int, token: str, show_qr: bool = True, running: bool = True,
                 tls_port: int | None = None, fingerprint: str = "", setup_open: bool = True):
    u = urls(port, token)
    print("\n  Mac Touchpad is running" + (" (HTTPS)." if tls_port else ".") + "\n" if running
          else "\n  Mac Touchpad phone URL:\n")
    if not u:
        print("  ! Could not detect a LAN address. Is Wi-Fi connected?\n")
    if tls_port:
        a = urls(tls_port, token, "https")
        if a:
            print(f"  Phone already set up? Open:          {a.get('bonjour') or a.get('ip')}")
        if not setup_open:
            # A phone is paired, so the plain-HTTP setup page is switched off.
            print("  New phone: run  ./touchpad pair  on the Mac first. That opens the setup page")
            print(f"  for {SETUP_WINDOW_S // 60} minutes and prints its address.")
            if fingerprint:
                print(f"\n  Certificate SHA-256:\n    {fingerprint}")
            print(("\n  Ctrl-C to stop.\n" if running else ""), flush=True)
            return
        print("  New phone (or old http:// icon): open the setup page first,")
        print("  it installs this Mac's certificate:")
    if "bonjour" in u:
        print(f"  On your iPhone (same Wi-Fi), open:   {u['bonjour']}")
    if "ip" in u:
        print(f"  or, if that name doesn't resolve:    {u['ip']}")
    if fingerprint:
        print(f"\n  Certificate SHA-256 (check it matches on the phone):\n    {fingerprint}")
    target = u.get("bonjour") or u.get("ip")
    if show_qr and target:
        try:
            import qrcode
            qr = qrcode.QRCode(border=1)
            qr.add_data(target)
            qr.make(fit=True)
            print("\n  Or scan this with the iPhone camera:\n")
            qr.print_ascii(invert=True)
        except Exception:
            pass
    print(("  Then follow the steps on that page.\n" if tls_port else
           "  Then Share > Add to Home Screen for a full-screen app.\n")
          + ("  Ctrl-C to stop.\n" if running else ""), flush=True)


# --------------------------------------------------------------------------- #
# Accessibility
# --------------------------------------------------------------------------- #

def ensure_accessibility(wait_s: float) -> bool:
    from input_mac import is_trusted, request_trust_prompt

    if is_trusted():
        return True
    request_trust_prompt()  # shows the system dialog / adds us to the list
    exe = os.path.realpath(sys.executable)
    print(
        "\n  Accessibility permission is required to move the cursor and click.\n\n"
        "  1. System Settings > Privacy & Security > Accessibility is opening now.\n"
        "  2. Turn ON the app that launched this server:\n"
        "       - your terminal (Terminal, iTerm, VS Code...) if you ran ./touchpad start/run\n"
        f"       - otherwise the program running this server ({exe})\n"
        "     If it's not listed, click + and add it.\n"
        "  3. If it still isn't detected, quit and reopen that app, then start again.\n",
        flush=True,
    )
    subprocess.run(["open", SETTINGS_URL], check=False)
    deadline = time.monotonic() + wait_s
    if wait_s > 0:
        print(f"  Waiting up to {int(wait_s)} s for permission...", flush=True)
    while time.monotonic() < deadline:
        time.sleep(1.0)
        if is_trusted():
            print("  Permission granted.\n", flush=True)
            return True
    print(
        "\n  ERROR: Accessibility permission not granted, so input can't be injected.\n"
        "  Grant it as described above, then run the server again.\n",
        file=sys.stderr, flush=True,
    )
    return False


# --------------------------------------------------------------------------- #
# Mac-side prompts (osascript; text passed as argv, never interpolated)
# --------------------------------------------------------------------------- #

_PAIR_SCRIPT = """on run argv
  set r to display dialog (item 1 of argv) with title "Mac Touchpad" default answer "" buttons {"Don't Allow", "Allow"} default button "Allow" cancel button "Don't Allow" giving up after 90 with icon caution
  if gave up of r then return "timeout"
  if button returned of r is not "Allow" then return "deny"
  return "code:" & text returned of r
end run"""

_NOTIFY_SCRIPT = """on run argv
  display notification (item 1 of argv) with title "Mac Touchpad"
end run"""


async def ask_mac_user_to_pair(name: str, ip: str, code: str) -> str:
    """Ask on the Mac's screen. Returns "ok", "refused" or "badcode".

    The phone shows a 4-digit code that has to be typed here. Someone else's
    device can make this dialog appear, but then YOUR phone shows no code, so
    there is nothing to type and it can't be approved by mistake."""
    msg = (f"A device wants to use this Mac as a touchpad and keyboard:\n\n"
           f"    {name}  ({ip})\n\n"
           f"To allow it, type the 4-digit code that YOUR phone is showing right now.\n"
           f"If your phone isn't showing a code, click Don't Allow.")
    try:
        proc = await asyncio.create_subprocess_exec(
            "osascript", "-e", _PAIR_SCRIPT, msg,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=105)
    except (asyncio.TimeoutError, OSError):
        return "refused"
    answer = out.decode().strip()
    if proc.returncode != 0 or not answer.startswith("code:"):
        return "refused"
    typed = "".join(ch for ch in answer[5:] if ch.isdigit() and ch.isascii())
    return "ok" if hmac.compare_digest(typed, code) else "badcode"


def clean_name(raw) -> str:
    """Device name for the dialog and logs: one line, printable, at most 40 characters."""
    name = "".join(ch if ch.isprintable() else " " for ch in str(raw or ""))
    return " ".join(name.split())[:40] or "Phone"


def notify_mac(text: str):
    try:
        subprocess.Popen(["osascript", "-e", _NOTIFY_SCRIPT, text],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Web app
# --------------------------------------------------------------------------- #

def open_pairing_window(seconds: int = PAIR_WINDOW_S):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PAIR_WINDOW_FILE.write_text(str(time.time() + seconds))
    SETUP_WINDOW_FILE.write_text(str(time.time() + SETUP_WINDOW_S))


def _window_open(path: Path) -> bool:
    try:
        return float(path.read_text().strip()) > time.time()
    except (FileNotFoundError, ValueError):
        return False


def pairing_window_open() -> bool:
    return _window_open(PAIR_WINDOW_FILE)


def setup_page_wanted(store) -> bool:
    """The plain-HTTP setup page is only reachable while a phone is being added:
    before the first phone is paired, or for a while after `./touchpad pair`."""
    return not store.devices or _window_open(SETUP_WINDOW_FILE)


# --------------------------------------------------------------------------- #
# Request checks + response headers (both apps)
# --------------------------------------------------------------------------- #

_HOST_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?$")


def host_allowed(hostname: str) -> bool:
    """Only answer to names this server can legitimately have: an IP address,
    localhost or a .local name. A public domain pointed at this Mac (DNS
    rebinding) is refused."""
    h = hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        return h == "localhost" or h.endswith((".local", ".localhost"))


@web.middleware
async def check_host(request: web.Request, handler):
    m = _HOST_RE.match(request.headers.get("Host", ""))
    if not m or not host_allowed(m.group(1)):
        raise web.HTTPMisdirectedRequest(text="Unknown host name.")
    request["host"] = m.group(0)        # validated "name[:port]", safe to echo
    request["hostname"] = m.group(1)
    return await handler(request)


def harden(app: web.Application, csp):
    """Same hardening headers on every response; `csp(request)` builds the Content-Security-Policy."""
    async def on_prepare(request: web.Request, response: web.StreamResponse):
        h = response.headers
        h["Server"] = "mac-touchpad"                 # don't advertise Python/aiohttp versions
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "no-referrer"
        h["X-Frame-Options"] = "DENY"
        h["Content-Security-Policy"] = csp(request)
        # (No HSTS on purpose: it applies per host name, not per port, and would
        # break the plain-HTTP setup page on the other port.)
    app.on_response_prepare.append(on_prepare)


def close_pairing_window():
    try:
        PAIR_WINDOW_FILE.unlink()
    except FileNotFoundError:
        pass


def make_app(injector, token: str, verbose: bool, store, allow_pairing: bool = True,
             auto_approve: bool = False, notify: bool = True, idle_s: float = IDLE_TIMEOUT_MIN * 60,
             block_when_locked: bool = True) -> web.Application:
    app = web.Application(middlewares=[check_host])

    def csp(request: web.Request) -> str:
        # 'self' doesn't cover WebSockets in every Safari version, so name ours explicitly.
        ws_origin = ("wss://" if request.secure else "ws://") + request.get("host", "")
        return ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                f"connect-src 'self' {ws_origin}; object-src 'none'; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'")
    harden(app, csp)

    pair_lock = asyncio.Lock()
    denied: dict[str, float] = {}   # ip -> time of last "Don't Allow"
    DENY_COOLDOWN = 300
    clients: set[web.WebSocketResponse] = set()
    sessions: dict[web.WebSocketResponse, dict] = {}   # authenticated sockets -> {"id", "name", "last"}
    policy = {"block_when_locked": block_when_locked}  # changeable while running (menu bar app)
    app["clients"] = clients
    app["sessions"] = sessions
    app["policy"] = policy

    async def sweep():
        """Called every few seconds: drop phones that were forgotten, or that went idle."""
        store.load()
        known = {d["id"] for d in store.devices}
        now = time.monotonic()
        for ws, s in list(sessions.items()):
            if s["id"] not in known:
                why, note = "auth_fail", "was forgotten"
            elif idle_s and now - s["last"] > idle_s:
                why, note = "idle", "is idle"
            else:
                continue
            print(f"  {s['name']} {note}: disconnecting it", flush=True)
            try:
                await ws.send_str(json.dumps({"t": why}))
                await ws.close()
            except Exception:
                pass
            sessions.pop(ws, None)
    app["sweep"] = sweep

    async def ws_handler(request: web.Request):
        # A browser always says which page opened the socket: only our own page may.
        origin = request.headers.get("Origin")
        if origin is not None and urlsplit(origin).netloc.lower() != request["host"].lower():
            print(f"  ! refused a WebSocket opened by another site ({origin[:80]!r}) from {request.remote}", flush=True)
            raise web.HTTPForbidden(text="Cross-origin WebSocket refused.")
        ws = web.WebSocketResponse(heartbeat=None, max_msg_size=64 * 1024, compress=False)
        await ws.prepare(request)
        # Nagle off: tiny packets must go out immediately.
        sock = request.transport.get_extra_info("socket") if request.transport else None
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
        peer = request.remote
        clients.add(ws)
        nonce = secrets.token_hex(16)
        authed = None          # device dict once the phone has proven its key
        pairing = False
        told_locked = False

        def start_session(dev):
            nonlocal authed
            authed = dev
            sessions[ws] = {"id": dev["id"], "name": dev["name"], "last": time.monotonic()}

        await ws.send_str(json.dumps({"t": "hello", "host": bonjour_hostname() or socket.gethostname(),
                                      "nonce": nonce, "v": 3,
                                      "natural": mac_natural_scrolling()}))

        # Unauthenticated sockets get 20 s to prove themselves (not counting the pairing dialog).
        def auth_deadline():
            if authed is None and not pairing and not ws.closed:
                asyncio.ensure_future(ws.close())
        asyncio.get_running_loop().call_later(20, auth_deadline)

        try:
            async for msg in ws:
                if msg.type != WSMsgType.TEXT:
                    continue
                try:
                    batch = json.loads(msg.data)
                except ValueError:
                    continue
                for m in batch if isinstance(batch, list) else (batch,):
                    if not isinstance(m, dict):
                        continue
                    if authed is not None:
                        if ws not in sessions:      # forgotten or idle: sweep() is closing this socket
                            continue
                        kind = m.get("t")
                        if kind == "rekey":
                            # A phone paired with the old shared key hands over a public key instead.
                            if store.rekey(authed["id"], m.get("pub")):
                                print(f"  {authed['name']} now signs in with a public key", flush=True)
                                await ws.send_str(json.dumps({"t": "rekeyed"}))
                            continue
                        if kind != "p":
                            sessions[ws]["last"] = time.monotonic()
                            if policy["block_when_locked"] and injector.locked():
                                if not told_locked:
                                    told_locked = True
                                    print(f"  input from {authed['name']} ignored: the Mac is locked", flush=True)
                                    await ws.send_str(json.dumps({"t": "locked"}))
                                continue
                            told_locked = False
                        reply = handle(injector, m, verbose)
                        if reply is not None:
                            await ws.send_str(reply)
                        continue

                    # ---- not authenticated yet: only "auth" and "pair" are accepted ----
                    t = m.get("t")
                    if t == "auth":
                        dev = store.verify(m.get("id"), nonce, mac=m.get("mac"), sig=m.get("sig"))
                        if dev:
                            start_session(dev)
                            print(f"  {dev['name']} connected ({peer})", flush=True)
                            if notify:
                                notify_mac(f"{dev['name']} connected")
                            await ws.send_str(json.dumps({"t": "auth_ok", "name": dev["name"],
                                                          "pk": bool(dev.get("pub"))}))
                        else:
                            print(f"  ! rejected unknown/forgotten device from {peer}", flush=True)
                            await ws.send_str(json.dumps({"t": "auth_fail"}))
                            await ws.close()
                    elif t == "pair":
                        name = clean_name(m.get("name"))
                        pub = m.get("pub")
                        wait = DENY_COOLDOWN - (time.monotonic() - denied.get(peer, -1e9))
                        store.load()
                        if pub is not None and not store.valid_pub(pub):
                            await ws.send_str(json.dumps({"t": "pair_denied", "reason": "badkey"}))
                            await ws.close()
                        elif not allow_pairing:
                            await ws.send_str(json.dumps({"t": "pair_denied", "reason": "locked"}))
                            await ws.close()
                        elif store.devices and not pairing_window_open():
                            # A phone is already paired: new ones only via `./touchpad pair`.
                            print(f"  ! pairing request from {peer} refused: pairing is closed (./touchpad pair opens it)", flush=True)
                            await ws.send_str(json.dumps({"t": "pair_denied", "reason": "closed"}))
                            await ws.close()
                        elif wait > 0:
                            await ws.send_str(json.dumps({"t": "pair_denied", "reason": "cooldown", "retry_in": int(wait)}))
                            await ws.close()
                        elif pair_lock.locked():
                            await ws.send_str(json.dumps({"t": "pair_denied", "reason": "busy"}))
                            await ws.close()
                        else:
                            code = f"{secrets.randbelow(10000):04d}"
                            async with pair_lock:
                                pairing = True
                                print(f"  pairing request from {name} ({peer}), asking on screen...", flush=True)
                                await ws.send_str(json.dumps({"t": "pair_wait", "code": code}))
                                answer = "ok" if auto_approve else await ask_mac_user_to_pair(name, peer, code)
                                pairing = False
                            if ws.closed:
                                break
                            if answer == "ok":
                                dev = store.add(name, peer, pub)
                                close_pairing_window()
                                start_session(dev)
                                print(f"  paired {dev['name']} (id {dev['id']}, "
                                      f"{'public key' if pub else 'shared key'})", flush=True)
                                reply = {"t": "paired", "id": dev["id"], "name": dev["name"], "pk": bool(pub)}
                                if not pub:
                                    reply["key"] = dev["key"]
                                await ws.send_str(json.dumps(reply))
                            elif answer == "badcode":
                                print(f"  pairing for {peer} failed: the code typed on the Mac didn't match", flush=True)
                                await ws.send_str(json.dumps({"t": "pair_denied", "reason": "badcode"}))
                                await ws.close()
                            else:
                                denied[peer] = time.monotonic()
                                print(f"  pairing refused for {peer}", flush=True)
                                await ws.send_str(json.dumps({"t": "pair_denied", "reason": "refused", "retry_in": DENY_COOLDOWN}))
                                await ws.close()
        finally:
            clients.discard(ws)
            sessions.pop(ws, None)
            try:
                injector.release_all()
            except Exception:
                pass
            if authed is not None:
                print(f"  {authed['name']} disconnected", flush=True)
        return ws

    async def static(request: web.Request):
        name = request.match_info.get("name") or "index.html"
        path = (WEB_DIR / name).resolve()
        if WEB_DIR not in path.parents or not path.is_file():
            raise web.HTTPNotFound()
        resp = web.FileResponse(path)
        resp.headers["Cache-Control"] = "no-cache"
        if name.endswith(".webmanifest"):
            resp.content_type = "application/manifest+json"
        return resp

    async def redirect_to_app(request):
        raise web.HTTPFound(f"/{token}/")

    # Nothing is served outside the pairing-code path: a port scan learns nothing about what this is.
    app.router.add_get(f"/{token}/ws", ws_handler)
    app.router.add_get(f"/{token}", redirect_to_app)
    app.router.add_get(f"/{token}/", static)
    app.router.add_get(f"/{token}/{{name:[A-Za-z0-9._-]+}}", static)

    async def on_shutdown(app):
        for ws in list(clients):
            await ws.close()

    app.on_shutdown.append(on_shutdown)
    return app


def make_setup_app(token: str, ca, tls_port: int) -> web.Application:
    """Plain-HTTP side when HTTPS is on: setup instructions + the CA, never app JS.

    Old http:// Home Screen icons land here too and get told to upgrade.
    """
    app = web.Application(middlewares=[check_host])
    # The page is one self-contained file (inline style + script); its only request is the HTTPS probe.
    harden(app, lambda request: (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        f"connect-src https://{request.get('hostname', 'localhost')}:{tls_port}; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"))
    template = SETUP_TEMPLATE.read_text()

    async def setup_page(request: web.Request):
        host = request["hostname"]     # validated by check_host: an IP, localhost or a .local name
        target = f"https://{host}:{tls_port}/{token}/"
        # "<" escaped so nothing in the URL could ever close the <script> block.
        page = (template.replace("{{https_url_json}}", json.dumps(target).replace("<", "\\u003c"))
                .replace("{{https_url}}", html.escape(target))
                .replace("{{fingerprint}}", html.escape(ca.fingerprint)))
        return web.Response(text=page, content_type="text/html", headers={"Cache-Control": "no-store"})

    async def profile(request):
        return web.Response(body=ca.mobileconfig(), content_type="application/x-apple-aspen-config",
                            headers={"Content-Disposition": 'attachment; filename="mac-touchpad.mobileconfig"'})

    async def crt(request):
        return web.Response(body=ca.ca_der, content_type="application/x-x509-ca-cert",
                            headers={"Content-Disposition": 'attachment; filename="mac-touchpad-ca.crt"'})

    async def redirect_to_setup(request):
        raise web.HTTPFound(f"/{token}/")

    app.router.add_get(f"/{token}", redirect_to_setup)
    app.router.add_get(f"/{token}/", setup_page)
    app.router.add_get(f"/{token}/touchpad-ca.mobileconfig", profile)
    app.router.add_get(f"/{token}/touchpad-ca.crt", crt)
    return app


def _loggable(m: dict) -> dict:
    """Typed text never goes into the log (it may be a password)."""
    return {**m, "s": f"<{len(str(m.get('s', '')))} characters>"} if m.get("t") == "txt" else m


def _num(v) -> float:
    """A finite float (json.loads accepts NaN and Infinity, which would upset CGEvent maths)."""
    x = float(v)
    if not math.isfinite(x):
        raise ValueError(f"not a finite number: {v!r}")
    return x


def handle(inj, m: dict, verbose: bool):
    try:
        t = m.get("t")
        if t == "m":
            inj.move(_num(m.get("x", 0)), _num(m.get("y", 0)))
        elif t == "s":
            ph, mo = m.get("ph"), m.get("mo")
            inj.scroll(_num(m.get("x", 0)), _num(m.get("y", 0)),
                       ph if isinstance(ph, str) else None, mo if isinstance(mo, str) else None)
        elif t == "z":
            inj.magnify(str(m.get("ph", "")), _num(m.get("v", 0)))
        elif t == "rot":
            inj.rotate(str(m.get("ph", "")), _num(m.get("v", 0)))
        elif t == "c":
            inj.click(m.get("b", "l"))
        elif t == "d":
            inj.button_down(m.get("b", "l"))
        elif t == "u":
            inj.button_up()
        elif t == "k":
            inj.key(str(m["k"]), [str(x) for x in m.get("m", [])])
        elif t == "txt":
            inj.text(str(m.get("s", ""))[:500])
        elif t == "media":
            inj.media(str(m["k"]))
        elif t == "p":
            return json.dumps({"t": "p", "i": m.get("i")})
        if verbose and t not in ("m", "s", "p", "z", "rot"):
            print(f"  <- {_loggable(m)}", flush=True)
    except Exception as e:  # never let one bad message kill the connection
        print(f"  ! bad message {_loggable(m)!r}: {e}", file=sys.stderr, flush=True)
    return None


# --------------------------------------------------------------------------- #
# Settings the menu bar app can change (settings.json)
# --------------------------------------------------------------------------- #

SETTINGS_FILE = CONFIG_DIR / "settings.json"
SETTING_DEFAULTS = {"allow_when_locked": False}


def load_settings() -> dict:
    try:
        data = json.loads(SETTINGS_FILE.read_text())
    except (FileNotFoundError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {k: data[k] if isinstance(data.get(k), type(v)) else v for k, v in SETTING_DEFAULTS.items()}


def save_setting(key: str, value) -> dict:
    if key not in SETTING_DEFAULTS or not isinstance(value, type(SETTING_DEFAULTS[key])):
        raise ValueError(f"unknown setting or wrong type: {key}={value!r}")
    settings = {**load_settings(), key: value}
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(settings, f, indent=1)
    tmp.replace(SETTINGS_FILE)
    return settings


def ca_key_stores(kind: str) -> list:
    """Where the CA private key lives: the login keychain (the app) or a file (everything else).

    In keychain mode the file is still read as a fallback, so a key that couldn't be
    migrated yet keeps working."""
    from keystore import FileKeyStore
    file_store = FileKeyStore(TLS_DIR / "ca.key")
    if kind == "keychain":
        from keystore import KeychainKeyStore
        return [KeychainKeyStore(), file_store]
    return [file_store]


# --------------------------------------------------------------------------- #
# The server (CLI: main thread; menu bar app: a background thread)
# --------------------------------------------------------------------------- #

class ListenError(Exception):
    pass


class Server:
    """Listens while the network is trusted and the server is enabled, re-issues the
    certificate when the Mac's addresses change, and drops forgotten or idle phones.

    `serve()` is a coroutine; `stop()`, `set_enabled()`, `poke()` and `status()` may be
    called from another thread."""

    def __init__(self, args, injector, key_stores=None, log=print, exit_on_bind_error: bool = True):
        from devices import DeviceStore
        from networks import NetworkTrust
        self.args = args
        self.log = log
        self.injector = injector
        self.exit_on_bind_error = exit_on_bind_error
        self.token = load_token(reset=args.reset_token)
        self.trust = NetworkTrust(NETWORKS_FILE)
        self.store = DeviceStore(DEVICES_FILE)
        self.ca = None
        if not args.no_tls:
            self.ca = open_ca(key_stores or ca_key_stores("file"), log)
            try:
                self.ca.ensure_leaf(cert_names())
            except Exception as e:
                if not (self.ca.cert_path.exists() and self.ca.key_path.exists()):
                    raise
                log(f"  ! couldn't re-issue the server certificate ({e}); using the existing one", flush=True)
        self.banner = dict(tls_port=None if args.no_tls else args.tls_port,
                           fingerprint=self.ca.fingerprint if self.ca else "")
        self.app = make_app(injector, self.token, args.verbose, self.store,
                            allow_pairing=not args.no_pairing,
                            # Tests skip the Mac dialog. Never dry-run alone: it shares the
                            # real devices.json, so a silent approval would trust that phone
                            # in the real app too.
                            auto_approve=args.dry_run and os.environ.get("TOUCHPAD_TEST_AUTO_APPROVE") == "1",
                            notify=not (args.no_notify or args.dry_run),
                            idle_s=max(0.0, args.idle_timeout) * 60,
                            block_when_locked=not args.allow_when_locked)
        self.enabled = True
        self.bound: str | None = None          # address the sites are listening on
        self.reason = "starting"               # why it isn't listening (when it isn't)
        self.error: str | None = None          # last problem worth showing (bind failure, certificate)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None
        self._stopping = False

    # ---- thread-safe controls --------------------------------------------
    def poke(self):
        """Run the watcher now instead of at the next 5 s tick."""
        loop, wake = self._loop, self._wake
        if loop and wake and not loop.is_closed():
            loop.call_soon_threadsafe(wake.set)

    def stop(self):
        self._stopping = True
        self.poke()

    def set_enabled(self, on: bool):
        self.enabled = bool(on)
        self.poke()

    def set_allow_when_locked(self, on: bool):
        self.app["policy"]["block_when_locked"] = not on

    def status(self) -> dict:
        try:
            phones = [s["name"] for s in list(self.app["sessions"].values())]
        except RuntimeError:        # changed size while copying: try again next time
            phones = []
        return {"enabled": self.enabled, "listening": self.bound, "reason": self.reason,
                "error": self.error, "phones": phones}

    # ---- the watcher loop --------------------------------------------------
    async def serve(self):
        from networks import current_network
        args, ca, app, log = self.args, self.ca, self.app, self.log
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        ssl_ctx: ssl.SSLContext | None = None
        setup_runner = None
        if ca:
            ssl_ctx = ca.server_context()
            setup_runner = web.AppRunner(make_setup_app(self.token, ca, args.tls_port), access_log=None)
            await setup_runner.setup()
        app_site = setup_site = None
        first = True
        last_reason = None
        last_cert_error = None

        def refresh_cert():
            # New IP (DHCP renew, other network) or leaf near expiry: re-issue and hot-swap.
            nonlocal last_cert_error
            try:
                if ca and ca.ensure_leaf(cert_names()):
                    ca.reload(ssl_ctx)
                    log("  Server certificate re-issued for: " + ", ".join(cert_names()), flush=True)
                last_cert_error = None
            except Exception as e:
                if str(e) != last_cert_error:      # say it once, not every 5 s
                    log(f"  ! certificate refresh failed: {e}", file=sys.stderr, flush=True)
                last_cert_error = str(e)

        async def start_site(r, port, ctx, flag, host):
            site = web.TCPSite(r, host, port, ssl_context=ctx, reuse_address=True)
            try:
                await site.start()
            except OSError as e:
                msg = f"can't listen on {host} port {port}: {e.strerror}"
                if self.error != msg:
                    log(f"\n  ERROR: {msg}. Is another copy running? Try ./touchpad stop, or {flag}.\n",
                        file=sys.stderr, flush=True)
                self.error = msg
                return None
            return site

        async def stop_all():
            nonlocal app_site, setup_site
            if app_site or setup_site:
                for ws in list(app["clients"]):
                    await ws.close()
                for site in (app_site, setup_site):
                    if site:
                        await site.stop()
            app_site = setup_site = None
            self.bound = None

        async def listen(host: str | None, reason: str = ""):
            """Listen on `host` (None = don't listen at all, for `reason`)."""
            nonlocal app_site, setup_site, first, last_reason
            if host is None or (self.bound is not None and self.bound != host):
                await stop_all()      # untrusted network, turned off, or this Mac's address changed
            if host is None:
                if reason != last_reason:
                    log(f"  Not listening: {reason}", flush=True)
                last_reason, first, self.reason = reason, False, reason
                return
            last_reason = None
            want_setup = bool(setup_runner) and setup_page_wanted(self.store)
            if app_site is None:
                r, port, ctx, flag = ((runner, args.tls_port, ssl_ctx, "--tls-port") if ca
                                      else (runner, args.port, None, "--port"))
                app_site = await start_site(r, port, ctx, flag, host)
                if app_site is None:
                    if first and self.exit_on_bind_error:
                        raise ListenError(self.error)
                    self.reason = self.error or "can't listen"
                    first = False
                    return
                self.bound, self.error, self.reason = host, None, ""
                log(f"  Listening on {'every interface' if host == '0.0.0.0' else host}.", flush=True)
                print_banner(args.port, self.token, show_qr=not args.no_qr and first,
                             setup_open=want_setup or not ca, **self.banner)
            if want_setup and setup_site is None:
                setup_site = await start_site(setup_runner, args.port, None, "--port", host)
                if setup_site and not first:
                    log(f"  Setup page is open (plain HTTP, port {args.port}) for adding a phone.", flush=True)
            elif not want_setup and setup_site is not None:
                await setup_site.stop()
                setup_site = None
                log(f"  Setup page closed (port {args.port}). `./touchpad pair` opens it again for a new phone.",
                    flush=True)
            first = False

        try:
            while not self._stopping:
                self._wake.clear()
                await asyncio.to_thread(refresh_cert)
                try:
                    await app["sweep"]()      # forgotten / idle phones; also reloads the device list
                except Exception as e:
                    log(f"  ! session sweep failed: {e}", file=sys.stderr, flush=True)
                if not self.enabled:
                    await listen(None, "turned off")
                elif args.any_network:
                    await listen(args.host or "0.0.0.0")
                else:
                    net = await asyncio.to_thread(current_network)
                    if self.trust.is_trusted(net):
                        # Only this Mac's address on the trusted network: other interfaces
                        # (hotspot, VPN, cable to another machine) never see the ports.
                        await listen(args.host or net.get("ip") or "0.0.0.0")
                    elif net is None:
                        await listen(None, "no network (offline or VPN-only). Waiting...")
                    else:
                        await listen(None, f"untrusted network: {describe_network(net)}. "
                                           "If this is your home network: ./touchpad trust-network")
                if self._stopping:
                    break
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass
        finally:
            log("\n  Stopping...", flush=True)
            await stop_all()
            await runner.cleanup()
            if setup_runner:
                await setup_runner.cleanup()
            self._loop = None

    def run_forever(self):
        """CLI: serve until Ctrl-C / SIGTERM."""
        async def main():
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, self.stop)
            await self.serve()
        asyncio.run(main())


def describe_network(net) -> str:
    return f"{net['label']} on {net['iface']}" if net else "no network"


def open_ca(key_stores, log=print):
    """Load (or create) the certificate authority. If the key should live in the
    keychain and is still in the old ca.key file, move it there first."""
    from tls import LocalCA
    from keystore import FileKeyStore, KeyStoreError, migrate
    ca = LocalCA(TLS_DIR, key_stores)
    ca.ensure_ca(label=bonjour_hostname() or socket.gethostname())
    file_store = next((k for k in key_stores if isinstance(k, FileKeyStore)), None)
    primary = key_stores[0]
    if file_store is not None and primary is not file_store:
        try:
            result = migrate(file_store, primary, ca.ca_cert)
        except KeyStoreError as e:
            log(f"  ! CA key not moved to the keychain: {e}", file=sys.stderr, flush=True)
        else:
            if result == "moved":
                log(f"  CA private key moved into the {primary.location}; deleted {file_store.location}", flush=True)
            elif result == "already":
                log(f"  Deleted a leftover copy of the CA key ({file_store.location}); the keychain has it", flush=True)
    return ca


# --------------------------------------------------------------------------- #
# main (CLI)
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Use your iPhone as a touchpad/remote for this Mac.")
    ap.add_argument("--port", type=int, default=int(os.environ.get("TOUCHPAD_PORT", DEFAULT_PORT)),
                    help=f"plain-HTTP setup port (default {DEFAULT_PORT})")
    ap.add_argument("--tls-port", type=int, default=int(os.environ.get("TOUCHPAD_TLS_PORT", DEFAULT_TLS_PORT)),
                    help=f"HTTPS port for the app (default {DEFAULT_TLS_PORT})")
    ap.add_argument("--no-tls", action="store_true",
                    help="serve the app over plain HTTP on --port, like v1 (not recommended)")
    ap.add_argument("--reset-ca", action="store_true",
                    help="make a new certificate authority, then exit (every phone must install the new profile)")
    ap.add_argument("--ca-store", choices=("file", "keychain"), default="file",
                    help="where the CA private key lives (Mac Touchpad.app uses the keychain)")
    ap.add_argument("--host", default=None,
                    help="bind address (default: only this Mac's address on the trusted network; "
                         "every interface with --any-network)")
    ap.add_argument("--idle-timeout", type=float, default=IDLE_TIMEOUT_MIN, metavar="MIN",
                    help=f"disconnect a phone after this many minutes without input (default {IDLE_TIMEOUT_MIN}, 0 = never)")
    ap.add_argument("--allow-when-locked", action="store_true",
                    help="accept input while the Mac's screen is locked (default: ignore it)")
    ap.add_argument("--dry-run", action="store_true", help="log input instead of injecting it (no permission needed)")
    ap.add_argument("--wait-permission", type=float, default=90, help="seconds to wait for Accessibility grant (0 = fail now)")
    ap.add_argument("--no-qr", action="store_true")
    ap.add_argument("--reset-token", action="store_true", help="make a new pairing code (old home-screen icons stop working)")
    ap.add_argument("--print-url", action="store_true", help="print the phone URL and exit")
    ap.add_argument("--no-pairing", action="store_true", help="refuse new devices; only already-paired phones may connect")
    ap.add_argument("--no-notify", action="store_true", help="no Mac notification when a phone connects")
    ap.add_argument("--list-devices", action="store_true", help="list paired devices and exit")
    ap.add_argument("--forget", metavar="ID", help="unpair a device (or 'all') and exit")
    ap.add_argument("--open-pairing", action="store_true",
                    help=f"allow one new phone to pair in the next {PAIR_WINDOW_S} s (and open the setup page for "
                         f"{SETUP_WINDOW_S // 60} min), then exit")
    ap.add_argument("--trust-network", action="store_true", help="trust the network the Mac is on now, then exit")
    ap.add_argument("--untrust-network", metavar="KEY", help="remove a trusted network (id or router IP, or 'all'), then exit")
    ap.add_argument("--list-networks", action="store_true", help="list trusted networks, then exit")
    ap.add_argument("--any-network", action="store_true", help="listen on every network, trusted or not (not recommended)")
    ap.add_argument("--set", metavar="KEY=on|off", dest="set_setting",
                    help="change a Mac Touchpad.app setting (allow_when_locked), then exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap


def run_one_shot(args) -> bool:
    """Commands that do something and exit. True if one ran."""
    from networks import NetworkTrust, current_network
    trust = NetworkTrust(NETWORKS_FILE)
    if args.set_setting:
        key, _, val = args.set_setting.partition("=")
        if val.lower() not in ("on", "off", "true", "false", "1", "0", "yes", "no"):
            print(f"Expected KEY=on|off, got {args.set_setting!r}"); sys.exit(1)
        try:
            print(f"Settings: {save_setting(key, val.lower() in ('on', 'true', '1', 'yes'))}")
        except ValueError as e:
            print(e); sys.exit(1)
        return True
    if args.list_networks or args.trust_network or args.untrust_network:
        if args.trust_network:
            net = current_network()
            if not net:
                print("Can't identify the current network (offline, or only a VPN?)."); sys.exit(1)
            print(("Trusted: " if trust.trust(net) else "Already trusted: ") + describe_network(net))
        if args.untrust_network:
            print(f"Removed {trust.untrust(args.untrust_network)} network(s).")
        nets = trust.load()
        now = current_network()
        print("Trusted networks:" if nets else "No trusted networks yet (./touchpad trust-network while on your home network).")
        for n in nets:
            here = "  <- you are here" if now and now["id"] == n.get("id") else ""
            print(f"  {n.get('id')}  {n['label']}{here}")
        return True

    if args.reset_ca:
        from tls import LocalCA
        ca = LocalCA(TLS_DIR, ca_key_stores(args.ca_store))
        ca.ensure_ca(label=bonjour_hostname() or socket.gethostname(), reset=True)
        print(f"New certificate authority created (key in the {ca.key_location}). SHA-256:\n  {ca.fingerprint}\n"
              "Restart the server, then on each phone remove the old 'Mac Touchpad' profile "
              "(Settings > General > VPN & Device Management) and run the setup page again.")
        return True

    if not (args.open_pairing or args.list_devices or args.forget or args.print_url):
        return False
    from devices import DeviceStore
    store = DeviceStore(DEVICES_FILE)
    token = load_token(reset=args.reset_token)
    banner = dict(tls_port=None, fingerprint="")
    if not args.no_tls:
        # Only the CA *certificate* is needed here (fingerprint), never its private key.
        from tls import LocalCA
        ca = LocalCA(TLS_DIR, ca_key_stores(args.ca_store))
        ca.ensure_ca(label=bonjour_hostname() or socket.gethostname())
        banner = dict(tls_port=args.tls_port, fingerprint=ca.fingerprint)
    if args.open_pairing:
        open_pairing_window()
        print(f"Pairing is open for {PAIR_WINDOW_S} s. On the new phone, open the Touchpad app now "
              f"(tap 'Try again' if it's showing an error).\n"
              f"The phone shows a 4-digit code; type it into the dialog that appears on this Mac.")
        if not args.no_tls:
            print(f"\nPhone not set up yet? The setup page is reachable for the next {SETUP_WINDOW_S // 60} minutes"
                  f" (it can take a few seconds to come up).\nIf pairing has closed by the time the phone is ready,"
                  f" just run this again.")
            print_banner(args.port, token, show_qr=not args.no_qr, running=False, **banner)
    elif args.list_devices:
        if not store.devices:
            print("No paired devices. Open the phone URL to pair one.")
        for d in store.devices:
            seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(d.get("last_seen", 0)))
            kind = "public key" if d.get("pub") else "shared key (upgrades when it next connects)"
            print(f"  {d['id']}  {d['name']:<12} paired from {d.get('paired_ip', '?'):<15} last seen {seen}  {kind}")
    elif args.forget:
        n = store.forget(args.forget)
        print(f"Forgot {n} device(s). A running server disconnects them within a few seconds.")
    else:
        print_banner(args.port, token, show_qr=not args.no_qr, running=False,
                     setup_open=setup_page_wanted(store), **banner)
    return True


def main(argv=None):
    args = build_parser().parse_args(argv)
    if run_one_shot(args):
        return

    if args.no_tls:
        print("\n  WARNING: --no-tls sends everything unencrypted, including what you type and (when\n"
              "  pairing) the phone's key. Anyone on this network can read it or take over. Use only for testing.",
              file=sys.stderr, flush=True)

    if args.dry_run:
        from dryrun import DryRunInput
        injector = DryRunInput()
        print("  DRY RUN: input will be logged, not injected.")
    else:
        if not ensure_accessibility(args.wait_permission):
            sys.exit(2)
        from input_mac import MacInput
        injector = MacInput()

    if not args.any_network:
        from networks import NetworkTrust, current_network
        trust = NetworkTrust(NETWORKS_FILE)
        net = current_network()
        if net and not trust.is_trusted(net) and sys.stdin.isatty():
            print(f"\n  This network isn't trusted yet: {describe_network(net)}.")
            print("  The touchpad only listens on networks you trust. Only trust your own home network.")
            if input("  Trust this network? [y/N] ").strip().lower() in ("y", "yes"):
                trust.trust(net)
                print("  Trusted.")

    try:
        server = Server(args, injector, key_stores=ca_key_stores(args.ca_store))
    except Exception as e:
        from tls import CAKeyUnavailable
        if isinstance(e, CAKeyUnavailable):
            print(f"\n  ERROR: {e}\n  Run Mac Touchpad.app instead, or use --no-tls for testing from source.\n",
                  file=sys.stderr, flush=True)
            sys.exit(4)
        raise
    print(f"  Paired devices: {len(server.store.devices)}" + (
        "  (new pairing disabled)" if args.no_pairing else
        "  (new phones: run ./touchpad pair first)" if server.store.devices
        else "  (the first phone to connect can ask to pair)"))
    try:
        server.run_forever()
    except ListenError:
        sys.exit(3)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
