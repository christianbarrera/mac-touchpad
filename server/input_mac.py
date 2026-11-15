"""Synthesise mouse / keyboard / media-key input on macOS via Quartz CGEvent.

Everything here posts events into the HID event tap, which requires the
Accessibility permission (System Settings > Privacy & Security > Accessibility).
Without it CGEventPost silently does nothing, so call `ensure_accessibility()`
first and refuse to run if it returns False.
"""
from __future__ import annotations

import math
import time

import Quartz
from ApplicationServices import AXIsProcessTrusted, AXIsProcessTrustedWithOptions, kAXTrustedCheckOptionPrompt
from AppKit import NSEvent

# --------------------------------------------------------------------------- #
# Accessibility permission
# --------------------------------------------------------------------------- #

def is_trusted() -> bool:
    return bool(AXIsProcessTrusted())


def request_trust_prompt() -> bool:
    """Ask macOS to show its 'X would like to control this computer' dialog.

    Returns the current trust state (the dialog is asynchronous)."""
    return bool(AXIsProcessTrustedWithOptions({kAXTrustedCheckOptionPrompt: True}))


# --------------------------------------------------------------------------- #
# Displays
# --------------------------------------------------------------------------- #

def _display_rects():
    err, ids, count = Quartz.CGGetActiveDisplayList(16, None, None)
    rects = []
    for d in (ids or [])[:count]:
        b = Quartz.CGDisplayBounds(d)
        rects.append((b.origin.x, b.origin.y, b.size.width, b.size.height))
    return rects or [(0.0, 0.0, 1920.0, 1080.0)]


def _clamp_to_displays(x: float, y: float, rects) -> tuple[float, float]:
    """Keep the point on *some* display (handles extended desktops/TVs)."""
    best = None
    best_d = math.inf
    for rx, ry, rw, rh in rects:
        cx = min(max(x, rx), rx + rw - 1)
        cy = min(max(y, ry), ry + rh - 1)
        d = (cx - x) ** 2 + (cy - y) ** 2
        if d < best_d:
            best_d, best = d, (cx, cy)
            if d == 0:
                break
    return best


# --------------------------------------------------------------------------- #
# Key codes
# --------------------------------------------------------------------------- #

KEYCODES = {
    "return": 36, "enter": 36, "tab": 48, "space": 49, "backspace": 51, "delete": 51,
    "escape": 53, "esc": 53, "forwarddelete": 117, "home": 115, "end": 119,
    "pageup": 116, "pagedown": 121, "left": 123, "right": 124, "down": 125, "up": 126,
    "f": 3, "w": 13, "q": 12, "t": 17, "r": 15, "l": 37, "m": 46, "h": 4, "d": 2,
    "f11": 103,
    "comma": 43, "period": 47, "minus": 27, "equal": 24,
}

MOD_FLAGS = {
    "cmd": Quartz.kCGEventFlagMaskCommand,
    "shift": Quartz.kCGEventFlagMaskShift,
    "alt": Quartz.kCGEventFlagMaskAlternate,
    "opt": Quartz.kCGEventFlagMaskAlternate,
    "ctrl": Quartz.kCGEventFlagMaskControl,
    "fn": Quartz.kCGEventFlagMaskSecondaryFn,
}

MOD_KEYCODES = {"cmd": 55, "shift": 56, "alt": 58, "opt": 58, "ctrl": 59, "fn": 63}

# Trackpad-style scroll and gesture events.
# Scroll phases make apps treat our scrolling like a real trackpad's (elastic
# edges, momentum, Safari/Chrome swipe between pages). The CGEventField numbers
# are the public kCGScrollWheelEvent* ones.
F_SCROLL_CONTINUOUS = 88      # kCGScrollWheelEventIsContinuous
F_SCROLL_PHASE = 99           # kCGScrollWheelEventScrollPhase
F_SCROLL_MOMENTUM = 123       # kCGScrollWheelEventMomentumPhase
SCROLL_PHASES = {"b": 1, "c": 2, "e": 4, "x": 8}       # began / changed / ended / cancelled
MOMENTUM_PHASES = {"b": 1, "c": 2, "e": 3}             # begin / continue / end

# Pinch (magnify) and rotate are NSEventTypeGesture events. There is no public
# API to create them; these private CGEvent fields are the ones the window
# server uses (same as Hammerspoon's hs.eventtap.event.newGesture). Verified on
# macOS 26 to arrive as -magnifyWithEvent: / -rotateWithEvent: with phases.
GESTURE_EVENT = 29            # kCGSEventGesture (NSEventTypeGesture)
F_EVENT_TYPE = 55             # kCGSEventTypeField
F_GESTURE_HID_TYPE = 110
F_GESTURE_ZOOM = 113
F_GESTURE_ROTATION = 114
F_GESTURE_PHASE = 132
HID_ZOOM, HID_ROTATION = 8, 5
GESTURE_PHASES = {"b": 1, "c": 2, "e": 4, "x": 8}

# NX_KEYTYPE_* from IOKit/hidsystem/ev_keymap.h
MEDIA_KEYS = {
    "volup": 0, "voldown": 1, "brightup": 2, "brightdown": 3, "mute": 7,
    "play": 16, "next": 17, "prev": 18, "fastforward": 19, "rewind": 20,
}


# --------------------------------------------------------------------------- #
# Injector
# --------------------------------------------------------------------------- #

class MacInput:
    DOUBLE_CLICK_S = 0.45      # roughly the macOS default double-click interval
    DOUBLE_CLICK_PX = 6.0

    def __init__(self):
        self._src = Quartz.CGEventSourceCreate(Quartz.kCGEventSourceStateHIDSystemState)
        self._rects = _display_rects()
        self._rects_at = time.monotonic()
        self._scroll_rem = [0.0, 0.0]
        self._held = None            # "l" | "r" while dragging
        self._last_click = {"l": (0.0, 0.0, 0.0, 0), "r": (0.0, 0.0, 0.0, 0)}  # t, x, y, count
        self._locked = True
        self._locked_at = -1e9

    def locked(self) -> bool:
        """True while the screen is locked (or this login isn't the one on screen).

        The server drops input then, so a phone can't type at the lock screen.
        Checked at most once a second."""
        now = time.monotonic()
        if now - self._locked_at > 1.0:
            d = Quartz.CGSessionCopyCurrentDictionary()
            self._locked = (d is None or bool(d.get("CGSSessionScreenIsLocked", False))
                            or not d.get("kCGSSessionOnConsoleKey", True))
            self._locked_at = now
        return self._locked

    # -- helpers -------------------------------------------------------------
    def _pos(self) -> tuple[float, float]:
        p = Quartz.CGEventGetLocation(Quartz.CGEventCreate(None))
        return p.x, p.y

    def _displays(self):
        # Displays change when a TV is plugged in / mirrored; refresh every 2 s.
        now = time.monotonic()
        if now - self._rects_at > 2.0:
            self._rects = _display_rects()
            self._rects_at = now
        return self._rects

    def _post(self, ev):
        Quartz.CGEventPost(Quartz.kCGHIDEventTap, ev)

    # -- pointer -------------------------------------------------------------
    def move(self, dx: float, dy: float):
        x, y = self._pos()
        nx, ny = _clamp_to_displays(x + dx, y + dy, self._displays())
        if self._held == "l":
            etype, btn = Quartz.kCGEventLeftMouseDragged, Quartz.kCGMouseButtonLeft
        elif self._held == "r":
            etype, btn = Quartz.kCGEventRightMouseDragged, Quartz.kCGMouseButtonRight
        else:
            etype, btn = Quartz.kCGEventMouseMoved, Quartz.kCGMouseButtonLeft
        ev = Quartz.CGEventCreateMouseEvent(self._src, etype, (nx, ny), btn)
        Quartz.CGEventSetIntegerValueField(ev, Quartz.kCGMouseEventDeltaX, int(round(nx - x)))
        Quartz.CGEventSetIntegerValueField(ev, Quartz.kCGMouseEventDeltaY, int(round(ny - y)))
        self._post(ev)

    def _button_event(self, button: str, down: bool, click_state: int):
        x, y = self._pos()
        if button == "r":
            etype = Quartz.kCGEventRightMouseDown if down else Quartz.kCGEventRightMouseUp
            btn = Quartz.kCGMouseButtonRight
        else:
            etype = Quartz.kCGEventLeftMouseDown if down else Quartz.kCGEventLeftMouseUp
            btn = Quartz.kCGMouseButtonLeft
        ev = Quartz.CGEventCreateMouseEvent(self._src, etype, (x, y), btn)
        Quartz.CGEventSetIntegerValueField(ev, Quartz.kCGMouseEventClickState, click_state)
        self._post(ev)

    def click(self, button: str = "l"):
        button = "r" if button == "r" else "l"
        if self._held:
            self.button_up()
        x, y = self._pos()
        t0, lx, ly, n = self._last_click[button]
        now = time.monotonic()
        if now - t0 < self.DOUBLE_CLICK_S and abs(x - lx) < self.DOUBLE_CLICK_PX and abs(y - ly) < self.DOUBLE_CLICK_PX:
            n = min(n + 1, 3)
        else:
            n = 1
        self._last_click[button] = (now, x, y, n)
        self._button_event(button, True, n)
        self._button_event(button, False, n)

    def button_down(self, button: str = "l"):
        button = "r" if button == "r" else "l"
        if self._held:
            self.button_up()
        self._held = button
        self._button_event(button, True, 1)

    def button_up(self):
        if self._held:
            self._button_event(self._held, False, 1)
            self._held = None

    def scroll(self, dx: float, dy: float, phase: str | None = None, momentum: str | None = None):
        """dx/dy in pixels; positive dy scrolls content *down* (like dragging it).

        phase ("b"egan/"c"hanged/"e"nded/"x" cancelled) marks fingers-on-glass
        scrolling, momentum ("b"/"c"/"e") the coasting after a flick, like a trackpad."""
        phase = phase if phase in SCROLL_PHASES else None
        momentum = momentum if momentum in MOMENTUM_PHASES else None
        if phase == "b":
            self._scroll_rem = [0.0, 0.0]
        self._scroll_rem[0] += dx
        self._scroll_rem[1] += dy
        ix, iy = int(self._scroll_rem[0]), int(self._scroll_rem[1])
        if ix == 0 and iy == 0 and not (phase or momentum):
            return
        self._scroll_rem[0] -= ix
        self._scroll_rem[1] -= iy
        ev = Quartz.CGEventCreateScrollWheelEvent(self._src, Quartz.kCGScrollEventUnitPixel, 2, iy, ix)
        if phase or momentum:
            Quartz.CGEventSetIntegerValueField(ev, F_SCROLL_CONTINUOUS, 1)
            Quartz.CGEventSetIntegerValueField(ev, F_SCROLL_PHASE, SCROLL_PHASES.get(phase, 0))
            Quartz.CGEventSetIntegerValueField(ev, F_SCROLL_MOMENTUM, MOMENTUM_PHASES.get(momentum, 0))
        self._post(ev)

    def _gesture(self, hid_type: int, phase: str, field: int, value: float):
        if phase not in GESTURE_PHASES:
            return
        ev = Quartz.CGEventCreate(self._src)
        Quartz.CGEventSetType(ev, GESTURE_EVENT)
        Quartz.CGEventSetIntegerValueField(ev, F_EVENT_TYPE, GESTURE_EVENT)
        Quartz.CGEventSetIntegerValueField(ev, F_GESTURE_HID_TYPE, hid_type)
        Quartz.CGEventSetIntegerValueField(ev, F_GESTURE_PHASE, GESTURE_PHASES[phase])
        Quartz.CGEventSetDoubleValueField(ev, field, value)
        self._post(ev)

    def magnify(self, phase: str, amount: float = 0.0):
        """Pinch zoom. amount = relative change for this step (0.05 = 5 % bigger)."""
        self._gesture(HID_ZOOM, phase, F_GESTURE_ZOOM, max(-0.5, min(0.5, amount)))

    def rotate(self, phase: str, degrees: float = 0.0):
        """Two-finger rotate. Positive = counter-clockwise, like NSEvent.rotation."""
        self._gesture(HID_ROTATION, phase, F_GESTURE_ROTATION, max(-45.0, min(45.0, degrees)))

    # -- keyboard ------------------------------------------------------------
    def key(self, name: str, mods=()):
        code = KEYCODES.get(name.lower())
        if code is None:
            raise ValueError(f"unknown key {name!r}")
        flags = 0
        mods = [m for m in mods if m in MOD_FLAGS]
        for m in mods:
            flags |= MOD_FLAGS[m]
        # Press modifiers as real keys too: some shortcuts (cmd-tab, spotlight)
        # only react to genuine modifier key-down events, not just flags.
        held = 0
        for m in mods:
            held |= MOD_FLAGS[m]
            ev = Quartz.CGEventCreateKeyboardEvent(self._src, MOD_KEYCODES[m], True)
            Quartz.CGEventSetFlags(ev, held)
            self._post(ev)
        for down in (True, False):
            ev = Quartz.CGEventCreateKeyboardEvent(self._src, code, down)
            if flags or name.lower() in ("left", "right", "up", "down", "f11"):
                f = flags
                if name.lower() in ("left", "right", "up", "down", "f11"):
                    f |= Quartz.kCGEventFlagMaskNumericPad | Quartz.kCGEventFlagMaskSecondaryFn
                Quartz.CGEventSetFlags(ev, f)
            self._post(ev)
        for m in reversed(mods):
            held &= ~MOD_FLAGS[m]
            ev = Quartz.CGEventCreateKeyboardEvent(self._src, MOD_KEYCODES[m], False)
            Quartz.CGEventSetFlags(ev, held)
            self._post(ev)

    def text(self, s: str):
        """Type arbitrary unicode text (letters, emoji, accents...)."""
        for ch in s:
            if ch == "\n":
                self.key("return")
                continue
            for down in (True, False):
                ev = Quartz.CGEventCreateKeyboardEvent(self._src, 0, down)
                Quartz.CGEventSetFlags(ev, 0)
                Quartz.CGEventKeyboardSetUnicodeString(ev, len(ch.encode("utf-16-le")) // 2, ch)
                self._post(ev)

    def media(self, name: str):
        code = MEDIA_KEYS.get(name)
        if code is None:
            raise ValueError(f"unknown media key {name!r}")
        for down in (True, False):
            flags = 0xA00 if down else 0xB00
            data1 = (code << 16) | (0xA << 8 if down else 0xB << 8)
            ev = NSEvent.otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2_(
                14, (0, 0), flags, 0, 0, None, 8, data1, -1  # 14 = NSEventTypeSystemDefined
            )
            Quartz.CGEventPost(Quartz.kCGHIDEventTap, ev.CGEvent())

    def release_all(self):
        self.button_up()
