#!/usr/bin/env python3
"""Rasterise the app icon to PNG with only the standard library.

Run once (output is committed):  python3 tools/make_icons.py
Design: dark indigo tile, a rounded "trackpad" outline, and a glowing fingertip.
"""
import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "web"


def png(path, w, h, rows):
    raw = b"".join(b"\x00" + bytes(r) for r in rows)
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    data += chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    path.write_bytes(data)


def sd_round_rect(px, py, cx, cy, hw, hh, r):
    qx, qy = abs(px - cx) - hw + r, abs(py - cy) - hh + r
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r


def mix(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


def render(size):
    s = size
    rows = []
    top, bot = (32, 40, 78), (10, 12, 20)
    accent = (108, 140, 255)
    for y in range(s):
        row = []
        for x in range(s):
            acc = [0.0, 0.0, 0.0]
            for sy in (0.25, 0.75):          # 2x2 supersampling
                for sx in (0.25, 0.75):
                    u, v = (x + sx) / s, (y + sy) / s
                    col = mix(top, bot, v)
                    # pad outline
                    d = sd_round_rect(u, v, 0.5, 0.47, 0.30, 0.22, 0.07)
                    edge = max(0.0, 1 - abs(d) / 0.012)
                    col = mix(col, (200, 210, 235), edge * 0.9)
                    # two "buttons" bar under the pad
                    db = sd_round_rect(u, v, 0.5, 0.78, 0.30, 0.035, 0.035)
                    if db < 0:
                        col = mix(col, (60, 70, 105), 0.9)
                    dl = abs(u - 0.5) < 0.006 and abs(v - 0.78) < 0.035
                    if dl:
                        col = mix(col, top, 0.9)
                    # fingertip glow
                    r = math.hypot(u - 0.60, v - 0.43)
                    glow = math.exp(-(r / 0.09) ** 2)
                    col = mix(col, accent, min(1, glow * 0.8))
                    if r < 0.045:
                        col = mix(col, (235, 240, 255), 0.95)
                    for i in range(3):
                        acc[i] += col[i] / 4
            row.extend(int(max(0, min(255, c))) for c in acc)
        rows.append(row)
    return rows


if __name__ == "__main__":
    for n in (180, 192, 512):
        png(OUT / f"icon-{n}.png", n, n, render(n))
        print("wrote", OUT / f"icon-{n}.png")
