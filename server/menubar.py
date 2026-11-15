"""Mac Touchpad.app: a menu bar app that runs the touchpad server in a background thread.

The app bundle's launcher (tools/launcher.c) runs this module. Because the process
is the signed app, macOS ties the Accessibility permission and the keychain item
holding the certificate authority's key to Mac Touchpad.app.

    Mac Touchpad.app/Contents/MacOS/Mac Touchpad              the menu bar app
    ... --check        report Accessibility + CA key status (start it with `open` so macOS
                       attributes it to the app), written to ~/Library/Logs/Mac Touchpad/check.log
    ... --selftest     check the bundle itself (imports, TLS, no outside libraries); used by the build
    ... --reset-ca     new certificate authority, key in the keychain (phones must reinstall the profile)
Any other touchpad_server option (e.g. --any-network, -v) is passed through to the server.
"""
from __future__ import annotations

import fcntl
import os
import signal
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

LOG_DIR = Path.home() / "Library" / "Logs" / "Mac Touchpad"
LOG_FILE = LOG_DIR / "touchpad.log"
LOG_MAX = 2 * 1024 * 1024


# --------------------------------------------------------------------------- #
# Logging + single instance
# --------------------------------------------------------------------------- #

class _TimestampedLog:
    """File-like: prefixes each line with the time. Shared by stdout and stderr, all threads."""

    def __init__(self, f):
        self.f, self.lock, self.bol = f, threading.Lock(), True

    def write(self, s: str):
        with self.lock:
            for part in s.splitlines(keepends=True):
                if self.bol and part.strip():
                    self.f.write(time.strftime("%Y-%m-%d %H:%M:%S "))
                self.f.write(part)
                self.bol = part.endswith("\n")
            self.f.flush()
        return len(s)

    def flush(self):
        with self.lock:
            self.f.flush()

    def isatty(self):
        return False


def setup_logging():
    if sys.stdout is not None and sys.stdout.isatty():
        return
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if LOG_FILE.stat().st_size > LOG_MAX:
            LOG_FILE.replace(LOG_FILE.with_suffix(".log.1"))
    except FileNotFoundError:
        pass
    fd = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    sys.stdout = sys.stderr = _TimestampedLog(os.fdopen(fd, "a", buffering=1))


def single_instance_lock(config_dir: Path):
    """An exclusive lock held for the life of the process, or None if another copy has it."""
    config_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(config_dir / "app.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


# --------------------------------------------------------------------------- #
# --selftest / --check
# --------------------------------------------------------------------------- #

def selftest() -> int:
    """Exercise everything the bundle needs, without touching TCC or the keychain."""
    import ssl
    import asyncio
    import aiohttp  # noqa: F401
    import objc
    from AppKit import NSObject
    from cryptography.hazmat.primitives.asymmetric import ec
    import Quartz  # noqa: F401
    import Security  # noqa: F401
    import touchpad_server, tls, keystore, devices, networks, input_mac  # noqa: F401,E401
    ec.generate_private_key(ec.SECP256R1())
    ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    class Probe(NSObject):               # a Python method called from Objective-C (libffi closure)
        def ping_(self, x):
            self.got = x
    p = Probe.alloc().init()
    p.performSelector_withObject_(objc.selector(p.ping_, signature=b"v@:@"), "ok")
    assert p.got == "ok"
    asyncio.run(asyncio.sleep(0))
    # Every loaded library must come from the bundle or from macOS itself.
    import ctypes
    dyld = ctypes.CDLL(None)
    dyld._dyld_get_image_name.restype = ctypes.c_char_p
    contents = str(Path(sys.executable).resolve().parent.parent)
    outside = [n for n in (dyld._dyld_get_image_name(i).decode() for i in range(dyld._dyld_image_count()))
               if not n.startswith((contents + "/", "/System/", "/usr/lib/"))]
    if outside:
        print("selftest FAILED: libraries loaded from outside the bundle:\n  " + "\n  ".join(outside))
        return 1
    print(f"selftest ok: Python {sys.version.split()[0]}, {ssl.OPENSSL_VERSION}, sys.path={sys.path}")
    return 0


def check() -> int:
    """Accessibility + CA key status, as macOS sees this app. Start it with
    `open -W -n "/Applications/Mac Touchpad.app" --args --check` (from a terminal the
    Accessibility answer would be the terminal's)."""
    from Foundation import NSBundle
    from ApplicationServices import AXIsProcessTrusted, AXIsProcessTrustedWithOptions, kAXTrustedCheckOptionPrompt
    from keystore import KeychainKeyStore, key_matches_cert
    import touchpad_server as ts
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    info = NSBundle.mainBundle().infoDictionary()
    lines = [f"{time.strftime('%Y-%m-%d %H:%M:%S')} Mac Touchpad {info.get('CFBundleShortVersionString')} "
             f"build {info.get('CFBundleVersion')} ({info.get('MacTouchpadCommit')}), {sys.executable}"]
    trusted = bool(AXIsProcessTrusted())
    if not trusted:
        AXIsProcessTrustedWithOptions({kAXTrustedCheckOptionPrompt: True})
    lines.append(f"accessibility: {'granted' if trusted else 'NOT granted (asked macOS to show the prompt)'}")
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate((ts.TLS_DIR / "ca.crt").read_bytes())
        key = KeychainKeyStore().load()
        if key is None:
            lines.append("CA key: not in the keychain yet (the app moves it there when it starts)")
        else:
            lines.append("CA key: in the login keychain, " + ("matches ca.crt" if key_matches_cert(key, cert)
                                                               else "DOES NOT match ca.crt"))
    except FileNotFoundError:
        lines.append("CA key: no certificate authority yet")
    except Exception as e:
        lines.append(f"CA key: {e}")
    plain = ts.TLS_DIR / "ca.key"
    lines.append(f"plaintext {plain}: {'STILL PRESENT' if plain.exists() else 'absent'}")
    out = "\n".join(lines) + "\n"
    with open(LOG_DIR / "check.log", "a") as f:
        f.write(out)
    sys.stdout.write(out)
    return 0


# --------------------------------------------------------------------------- #
# The menu bar app
# --------------------------------------------------------------------------- #

def run_app(argv: list[str]) -> int:
    import objc
    from AppKit import (NSAlert, NSAlertFirstButtonReturn, NSApplication, NSApplicationActivationPolicyAccessory,
                        NSImage, NSMenu, NSMenuItem, NSStatusBar, NSVariableStatusItemLength, NSOnState, NSOffState)
    from Foundation import NSBundle, NSObject, NSTimer
    from PyObjCTools import AppHelper
    import touchpad_server as ts

    setup_logging()
    if single_instance_lock(ts.CONFIG_DIR) is None:
        NSApplication.sharedApplication()
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Mac Touchpad is already running")
        alert.setInformativeText_("Look for its icon in the menu bar.")
        alert.runModal()
        return 0

    args = ts.build_parser().parse_args(argv)
    args.no_qr = True
    if not (args.dry_run and "--ca-store" in argv):     # a file store only for dry-run tests
        args.ca_store = "keychain"
    settings = ts.load_settings()
    if args.allow_when_locked and not settings["allow_when_locked"]:
        settings = ts.save_setting("allow_when_locked", True)
    args.allow_when_locked = settings["allow_when_locked"]
    info = NSBundle.mainBundle().infoDictionary() or {}
    version = f"{info.get('CFBundleShortVersionString', '?')} (build {info.get('CFBundleVersion', '?')})"
    print(f"Mac Touchpad {version} starting (pid {os.getpid()}, {info.get('MacTouchpadCommit', '')})", flush=True)

    ICONS = {"connected": "hand.tap.fill", "listening": "hand.tap", "off": "hand.raised.slash",
             "problem": "exclamationmark.triangle"}

    class Delegate(NSObject):
        def init(self):
            self = objc.super(Delegate, self).init()
            self.server = None
            self.thread = None
            self.phase = "starting"        # starting | accessibility | running | failed
            self.failure = ""
            self.ax_prompted = False
            return self

        # ---- lifecycle -----------------------------------------------------
        def applicationDidFinishLaunching_(self, _):
            self.item = NSStatusBar.systemStatusBar().statusItemWithLength_(NSVariableStatusItemLength)
            self.menu = NSMenu.alloc().init()
            self.menu.setAutoenablesItems_(False)
            self.menu.setDelegate_(self)
            self.item.setMenu_(self.menu)
            self.current_icon = None
            self.refresh_(None)
            self.timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                1.0, self, "refresh:", None, True)
            self.thread = threading.Thread(target=self.serve_thread, name="server", daemon=True)
            self.thread.start()

        @objc.python_method
        def serve_thread(self):
            import asyncio
            try:
                if args.dry_run:
                    from dryrun import DryRunInput
                    injector = DryRunInput()
                else:
                    from ApplicationServices import AXIsProcessTrusted, AXIsProcessTrustedWithOptions, \
                        kAXTrustedCheckOptionPrompt
                    if not AXIsProcessTrusted():
                        self.phase = "accessibility"
                        print("Waiting for Accessibility permission (System Settings > Privacy & Security > "
                              "Accessibility > Mac Touchpad)", flush=True)
                        AXIsProcessTrustedWithOptions({kAXTrustedCheckOptionPrompt: True})
                        while not AXIsProcessTrusted():
                            time.sleep(1.0)
                        print("Accessibility permission granted", flush=True)
                    from input_mac import MacInput
                    injector = MacInput()
                self.phase = "starting"
                self.server = ts.Server(args, injector, key_stores=ts.ca_key_stores(args.ca_store),
                                        exit_on_bind_error=False)
                self.phase = "running"
                asyncio.run(self.server.serve())
            except Exception as e:
                self.phase, self.failure = "failed", str(e) or type(e).__name__
                traceback.print_exc()
                print(f"Server stopped: {self.failure}", flush=True)

        def quit_(self, _):
            print("Quit from the menu bar", flush=True)
            self.shutdown()
            NSApplication.sharedApplication().terminate_(None)

        @objc.python_method
        def shutdown(self):
            if self.server:
                self.server.stop()
            if self.thread and self.thread.is_alive():
                self.thread.join(4)

        # ---- status --------------------------------------------------------
        @objc.python_method
        def state(self):
            """(icon key, headline) for the current state."""
            if self.phase == "accessibility":
                return "problem", "Needs Accessibility permission"
            if self.phase == "failed":
                return "problem", f"Stopped: {self.failure}"
            if self.phase != "running" or not self.server:
                return "off", "Starting…"
            st = self.server.status()
            if not st["enabled"]:
                return "off", "Off"
            if st["phones"]:
                names = ", ".join(st["phones"])
                return "connected", f"{names} connected"
            if st["listening"]:
                return "listening", "Listening"
            if st["error"]:
                return "problem", f"Not listening: {st['error']}"
            return "off", f"Not listening: {st['reason']}" if st["reason"] else "Not listening"

        def refresh_(self, _):
            icon, _headline = self.state()
            if icon != self.current_icon:
                self.current_icon = icon
                img = NSImage.imageWithSystemSymbolName_accessibilityDescription_(ICONS[icon], "Mac Touchpad")
                if img is not None:
                    img.setTemplate_(True)
                    self.item.button().setImage_(img)
                    self.item.button().setTitle_("")
                else:
                    self.item.button().setTitle_("TP")
                self.item.button().setToolTip_(f"Mac Touchpad: {_headline}")

        # ---- menu ----------------------------------------------------------
        @objc.python_method
        def add(self, menu, title, action=None, enabled=True, state=None, target=True):
            it = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, action, "")
            if target and action:
                it.setTarget_(self)
            it.setEnabled_(enabled and (action is not None or not target))
            if state is not None:
                it.setState_(NSOnState if state else NSOffState)
            menu.addItem_(it)
            return it

        def menuNeedsUpdate_(self, menu):
            menu.removeAllItems()
            icon, headline = self.state()
            self.add(menu, f"Mac Touchpad: {headline}", enabled=False)
            running = self.phase == "running" and self.server is not None
            st = self.server.status() if running else None
            if st and st["listening"]:
                host = ts.bonjour_hostname() or st["listening"]
                self.add(menu, f"Listening on {host}", enabled=False)
            menu.addItem_(NSMenuItem.separatorItem())
            if self.phase == "accessibility":
                self.add(menu, "Open Accessibility Settings…", "openAccessibility:")
            if running:
                self.add(menu, "Turn Off" if st["enabled"] else "Turn On", "toggle:")
            self.add(menu, "Pair New Phone…", "pair:")
            phones = NSMenu.alloc().init()
            phones.setAutoenablesItems_(False)
            from devices import DeviceStore
            devs = DeviceStore(ts.DEVICES_FILE).devices
            for d in devs:
                seen = time.strftime("%d %b %H:%M", time.localtime(d.get("last_seen", 0)))
                sub = NSMenu.alloc().init()
                sub.setAutoenablesItems_(False)
                self.add(sub, f"Paired from {d.get('paired_ip', '?')}, last seen {seen}", enabled=False)
                f = self.add(sub, "Forget…", "forget:")
                f.setRepresentedObject_(d["id"])
                f.setToolTip_(d["name"])
                self.add(phones, f"{d['name']}  ({d['id']})", enabled=True, target=False).setSubmenu_(sub)
            if not devs:
                self.add(phones, "No paired phones", enabled=False)
            self.add(menu, "Paired Phones", enabled=True, target=False).setSubmenu_(phones)
            self.add(menu, "Allow Input at the Lock Screen", "toggleLocked:",
                     state=ts.load_settings()["allow_when_locked"])
            if st and "untrusted network" in (st["reason"] or ""):
                self.add(menu, "Trust This Network…", "trustNetwork:")
            menu.addItem_(NSMenuItem.separatorItem())
            self.add(menu, "Open Log", "openLog:")
            self.add(menu, f"Version {version}", enabled=False)
            self.add(menu, "Quit Mac Touchpad", "quit:")

        # ---- actions -------------------------------------------------------
        @objc.python_method
        def confirm(self, title, text, ok="OK", cancel=None):
            NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
            alert = NSAlert.alloc().init()
            alert.setMessageText_(title)
            alert.setInformativeText_(text)
            alert.addButtonWithTitle_(ok)
            if cancel:
                alert.addButtonWithTitle_(cancel)
            return alert.runModal() == NSAlertFirstButtonReturn

        def toggle_(self, _):
            if self.server:
                on = not self.server.enabled
                self.server.set_enabled(on)
                print(f"Turned {'on' if on else 'off'} from the menu bar", flush=True)

        def pair_(self, _):
            ts.open_pairing_window()
            if self.server:
                self.server.poke()
            print("Pairing opened from the menu bar", flush=True)
            text = (f"For the next {ts.PAIR_WINDOW_S // 60} minutes one new phone may pair. Open the Touchpad app on it "
                    "(tap Try again if it shows an error); it shows a 4-digit code to type into the dialog "
                    "that appears on this Mac.")
            if self.server and self.server.ca:
                u = ts.urls(args.port, self.server.token)
                text += ("\n\nPhone not set up yet? For the next "
                         f"{ts.SETUP_WINDOW_S // 60} minutes it can open the setup page:\n"
                         f"{u.get('bonjour') or u.get('ip') or '(no network address)'}\n\n"
                         f"Certificate SHA-256 (check it matches on the phone):\n{self.server.ca.fingerprint}")
            self.confirm("Pairing is open", text)

        def forget_(self, sender):
            dev_id, name = sender.representedObject(), sender.toolTip()
            if self.confirm(f"Forget {name}?",
                            "It is disconnected and has to pair again (with approval on this Mac) to reconnect.",
                            "Forget", "Cancel"):
                from devices import DeviceStore
                DeviceStore(ts.DEVICES_FILE).forget(dev_id)
                print(f"Forgot {name} ({dev_id}) from the menu bar", flush=True)
                if self.server:
                    self.server.poke()

        def toggleLocked_(self, _):
            on = not ts.load_settings()["allow_when_locked"]
            ts.save_setting("allow_when_locked", on)
            if self.server:
                self.server.set_allow_when_locked(on)
            print(f"Input at the lock screen {'allowed' if on else 'blocked'} (menu bar)", flush=True)

        def trustNetwork_(self, _):
            from networks import NetworkTrust, current_network
            net = current_network()
            if not net:
                return
            if self.confirm("Trust this network?",
                            f"{ts.describe_network(net)}\n\nThe touchpad only listens on networks you trust. "
                            "Only trust your own home network.", "Trust", "Cancel"):
                NetworkTrust(ts.NETWORKS_FILE).trust(net)
                print(f"Trusted network {ts.describe_network(net)} (menu bar)", flush=True)
                if self.server:
                    self.server.poke()

        def openAccessibility_(self, _):
            subprocess.run(["open", ts.SETTINGS_URL], check=False)

        def openLog_(self, _):
            subprocess.run(["open", "-a", "Console", str(LOG_FILE)], check=False)

    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
    delegate = Delegate.alloc().init()
    app.setDelegate_(delegate)

    def on_term(signum, _frame):     # launchd stop / restart
        print(f"Got signal {signum}, stopping", flush=True)
        delegate.shutdown()
        AppHelper.stopEventLoop()
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    AppHelper.runEventLoop(installInterrupt=False)
    delegate.shutdown()
    return 0


def main():
    argv = sys.argv[1:]
    if "--selftest" in argv:
        sys.exit(selftest())
    if "--check" in argv:
        sys.exit(check())
    if "--reset-ca" in argv:
        import touchpad_server as ts
        ts.main(["--reset-ca", "--ca-store", "keychain"])
        return
    sys.exit(run_app(argv))


if __name__ == "__main__":
    main()
