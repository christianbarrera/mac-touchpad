"""Stand-in for MacInput that logs instead of injecting.

Kept separate from input_mac.py (which imports macOS-only pyobjc) so that
`--dry-run` works anywhere, including Linux CI / cloud dev sessions.
"""
import os


class DryRunInput:
    def locked(self) -> bool:
        """Tests pretend the Mac's screen is locked by creating this file."""
        flag = os.environ.get("TOUCHPAD_TEST_LOCK_FILE")
        return bool(flag) and os.path.exists(flag)

    def __getattr__(self, name):
        def f(*a, **k):
            print(f"[dry-run] {name}{a if a else ''}{k if k else ''}", flush=True)
        return f
