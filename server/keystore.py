"""Where the certificate authority's private key lives.

- KeychainKeyStore: a generic-password item in the login keychain (the classic,
  file-based keychain, which needs no provisioning profile). macOS lets only the
  app that created the item read it without asking, so the signed
  Mac Touchpad.app owns it.
- FileKeyStore: a mode-600 file. Used by --dry-run, on Linux, by the smoke test
  and when running from the source tree.

`migrate()` moves a key from a file into the keychain and deletes the file only
after reading the key back and checking it against the CA certificate.
"""
from __future__ import annotations

import os
from pathlib import Path

SERVICE = "local.mac-touchpad"
CA_ACCOUNT = "ca.key"


class KeyStoreError(Exception):
    pass


class FileKeyStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    @property
    def location(self) -> str:
        return str(self.path)

    def load(self) -> bytes | None:
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            return None

    def save(self, data: bytes):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def delete(self):
        self.path.unlink(missing_ok=True)


class KeychainKeyStore:
    """One generic-password item in the login keychain (macOS only)."""

    # Security.framework status codes we handle by name.
    NOT_FOUND = -25300          # errSecItemNotFound
    DUPLICATE = -25299          # errSecDuplicateItem
    USER_CANCELED = -128        # errSecUserCanceled
    AUTH_FAILED = -25293        # errSecAuthFailed

    def __init__(self, account: str = CA_ACCOUNT, service: str = SERVICE,
                 label: str = "Mac Touchpad: certificate authority key"):
        import Security  # pyobjc-framework-Security; imported here so Linux never needs it
        self._S = Security
        self.account, self.service, self.label = account, service, label

    @property
    def location(self) -> str:
        return f"login keychain, item \"{self.label}\" ({self.service} / {self.account})"

    def _query(self, **extra) -> dict:
        S = self._S
        q = {S.kSecClass: S.kSecClassGenericPassword,
             S.kSecAttrService: self.service,
             S.kSecAttrAccount: self.account,
             # The file-based login keychain, not the data-protection keychain
             # (that one needs an app identifier from a provisioning profile).
             S.kSecUseDataProtectionKeychain: False}
        q.update(extra)
        return q

    def _fail(self, what: str, status: int):
        msg = None
        try:
            msg = self._S.SecCopyErrorMessageString(status, None)
        except Exception:
            pass
        hint = ""
        if status in (self.USER_CANCELED, self.AUTH_FAILED):
            hint = " (the Keychain prompt was cancelled or denied)"
        raise KeyStoreError(f"Keychain {what} failed: {msg or 'error'} ({status}){hint}")

    def load(self) -> bytes | None:
        S = self._S
        status, data = S.SecItemCopyMatching(
            self._query(**{S.kSecReturnData: True, S.kSecMatchLimit: S.kSecMatchLimitOne}), None)
        if status == self.NOT_FOUND:
            return None
        if status != 0:
            self._fail("read", status)
        return bytes(data)

    def save(self, data: bytes):
        S = self._S
        attrs = self._query(**{S.kSecValueData: data,
                               S.kSecAttrLabel: self.label,
                               S.kSecAttrDescription: "private key",
                               S.kSecAttrComment: "Signs the HTTPS certificate Mac Touchpad shows your phone. "
                                                  "Deleting it means every phone must reinstall the profile."})
        status, _ = S.SecItemAdd(attrs, None)
        if status == self.DUPLICATE:
            status = S.SecItemUpdate(self._query(), {S.kSecValueData: data})
        if status != 0:
            self._fail("write", status)

    def delete(self):
        status = self._S.SecItemDelete(self._query())
        if status not in (0, self.NOT_FOUND):
            self._fail("delete", status)


def key_matches_cert(key_pem: bytes, cert) -> bool:
    """True if `key_pem` is the private key belonging to x509 certificate `cert`."""
    from cryptography.hazmat.primitives import serialization
    try:
        key = serialization.load_pem_private_key(key_pem, None)
    except (ValueError, TypeError):
        return False
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    enc = serialization.Encoding.DER
    return key.public_key().public_bytes(enc, pub) == cert.public_key().public_bytes(enc, pub)


def migrate(src: FileKeyStore, dst, cert) -> str:
    """Move the CA key from file `src` into `dst` (normally the keychain).

    Returns what happened: "none" (no file), "moved", or "already" (dst held the
    same key; the leftover file was removed). Raises KeyStoreError, leaving the
    file in place, if anything doesn't check out.
    """
    data = src.load()
    if data is None:
        return "none"
    if not key_matches_cert(data, cert):
        raise KeyStoreError(f"{src.location} does not belong to the CA certificate; left it alone")
    existing = dst.load()
    if existing is not None and existing != data:
        raise KeyStoreError(f"{dst.location} already holds a different key; left {src.location} in place")
    if existing is None:
        dst.save(data)
        back = dst.load()
        if back != data or not key_matches_cert(back, cert):
            raise KeyStoreError(f"read-back from {dst.location} didn't match; left {src.location} in place")
    src.delete()
    return "already" if existing is not None else "moved"
