"""Local certificate authority + server certificate for HTTPS on the LAN.

On first run a root CA is created in <config>/tls/. The phone
trusts it once, via a .mobileconfig profile served by the plain-HTTP setup page.
The server certificate (leaf) is signed by that CA for <LocalHostName>.local
plus the Mac's current IPv4s, and is re-issued automatically when that set
changes or it nears expiry.

The CA is name-constrained to .local, localhost and private IP ranges, so even
if its key leaked it could not be used to impersonate real websites to the phone.

The CA's private key lives in a key store (see keystore.py): the login keychain
for Mac Touchpad.app, a mode-600 file otherwise. It is only read when a server
certificate actually has to be signed (first run, a new IP address, or renewal),
and an existing CA certificate is never silently replaced: phones trust it.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import plistlib
import ssl
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from keystore import FileKeyStore, key_matches_cert

CA_DAYS = 3650
LEAF_DAYS = 397            # well under iOS's 825-day limit for user-installed roots
RENEW_BEFORE_DAYS = 30
# Private, loopback, link-local and CGNAT (e.g. Tailscale) ranges.
PERMITTED_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"]
PERMITTED_DNS = ["local", "localhost"]


def permitted(name: str) -> bool:
    """Whether the CA's name constraints allow `name` (anything else would void the whole leaf)."""
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        n = name.lower().rstrip(".")
        return any(n == d or n.endswith("." + d) for d in PERMITTED_DNS)
    return any(ip in ipaddress.ip_network(net) for net in PERMITTED_NETS)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write_private(path: Path, data: bytes):
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _split_names(names) -> tuple[list[str], list[str]]:
    dns, ips = set(), set()
    for n in names:
        if not n:
            continue
        try:
            ips.add(str(ipaddress.ip_address(n)))
        except ValueError:
            dns.add(n.lower().rstrip("."))
    return sorted(dns), sorted(ips, key=ipaddress.ip_address)


class CAKeyUnavailable(Exception):
    """The CA certificate exists but its private key can't be read."""


class LocalCA:
    def __init__(self, directory: Path, key_stores=None):
        """`key_stores`: where the CA private key may live, in order. New keys go to the
        first; the key is read from the first store that has it. Default: <dir>/ca.key."""
        self.dir = Path(directory)
        self.ca_cert_path = self.dir / "ca.crt"
        self.cert_path = self.dir / "server.crt"
        self.key_path = self.dir / "server.key"
        self.key_stores = list(key_stores) if key_stores else [FileKeyStore(self.dir / "ca.key")]
        self.key_location = None      # where the key was found, once it has been read
        self._ca_cert = None
        self._ca_key = None

    # ------------------------------------------------------------------ CA
    @property
    def ca_cert(self):
        return self._ca_cert

    @property
    def ca_key(self):
        """The CA private key, read from the key stores on first use."""
        if self._ca_key is None:
            for store in self.key_stores:
                data = store.load()
                if data is None:
                    continue
                if not key_matches_cert(data, self._ca_cert):
                    raise CAKeyUnavailable(f"the key in {store.location} doesn't belong to {self.ca_cert_path}")
                self._ca_key = serialization.load_pem_private_key(data, None)
                self.key_location = store.location
                break
            else:
                raise CAKeyUnavailable(
                    "the certificate authority's private key isn't in " + " or ".join(s.location for s in self.key_stores)
                    + ". If it's in the login keychain, only Mac Touchpad.app can use it.")
        return self._ca_key

    def ensure_ca(self, label: str = "", reset: bool = False):
        """Load the CA certificate, or make a new CA if there is none (or `reset`).

        Only the certificate is loaded; the private key is read when it's needed."""
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        if not reset and self.ca_cert_path.exists():
            self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            self._ca_key = None
            return
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"Mac Touchpad Local CA{' (' + label + ')' if label else ''}"[:64]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mac Touchpad"),
        ])
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        now = _now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(d) for d in PERMITTED_DNS]
                + [x509.IPAddress(ipaddress.ip_network(n)) for n in PERMITTED_NETS],
                excluded_subtrees=None), critical=True)
            .add_extension(ski, critical=False)
            .sign(key, hashes.SHA256())
        )
        self.key_stores[0].save(_key_pem(key))
        for store in self.key_stores[1:]:     # an older copy elsewhere would be stale now
            store.delete()
        self.key_location = self.key_stores[0].location
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        for p in (self.cert_path, self.key_path):   # old leaf was signed by the old CA
            p.unlink(missing_ok=True)
        self._ca_cert, self._ca_key = cert, key

    @property
    def ca_der(self) -> bytes:
        return self._ca_cert.public_bytes(serialization.Encoding.DER)

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the CA cert, as iOS shows it under the profile's certificate details."""
        h = hashlib.sha256(self.ca_der).hexdigest().upper()
        return " ".join(h[i:i + 2] for i in range(0, len(h), 2))

    # ---------------------------------------------------------------- leaf
    def leaf_names(self) -> tuple[list[str], list[str]] | None:
        try:
            cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        except (FileNotFoundError, ValueError):
            return None
        if cert.issuer != self._ca_cert.subject:
            return None
        if cert.not_valid_after_utc - _now() < dt.timedelta(days=RENEW_BEFORE_DAYS):
            return None
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return (sorted(san.get_values_for_type(x509.DNSName)),
                sorted((str(i) for i in san.get_values_for_type(x509.IPAddress)), key=ipaddress.ip_address))

    def ensure_leaf(self, names) -> bool:
        """Make sure server.crt covers exactly `names` (DNS names and/or IPs). True if (re)issued.

        Names outside the CA's constraints (public IPs, non-.local hosts) are dropped:
        including one would make phones reject the whole certificate.
        """
        want = _split_names(n for n in names if n and permitted(n))
        if self.leaf_names() == want and self.key_path.exists():
            return False
        dns, ips = want
        key = ec.generate_private_key(ec.SECP256R1())
        now = _now()
        cn = (dns or ips or ["mac-touchpad"])[0]
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn[:64])]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=LEAF_DAYS))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]),
                critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                           critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        _write_private(self.key_path, _key_pem(key))
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return True

    def server_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.reload(ctx)
        return ctx

    def reload(self, ctx: ssl.SSLContext):
        """Swap in the current leaf. Applies to new connections; open ones keep theirs."""
        ctx.load_cert_chain(self.cert_path, self.key_path)

    # ------------------------------------------------------------- profile
    def mobileconfig(self) -> bytes:
        """Unsigned iOS configuration profile that installs the CA as a root.

        UUIDs derive from the CA, so re-downloading replaces the profile instead
        of stacking duplicates. iOS still needs full trust enabled by hand under
        Settings > General > About > Certificate Trust Settings.
        """
        fp = hashlib.sha256(self.ca_der).hexdigest()
        payload_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"mac-touchpad-ca-payload:{fp}")).upper()
        outer_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"mac-touchpad-ca-profile:{fp}")).upper()
        cn = self._ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        profile = {
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": "local.mac-touchpad.ca",
            "PayloadUUID": outer_uuid,
            "PayloadDisplayName": "Mac Touchpad",
            "PayloadDescription": "Lets this phone connect securely to Mac Touchpad on your Mac. "
                                  "Only valid for .local names and private network addresses.",
            "PayloadOrganization": "Mac Touchpad",
            "PayloadRemovalDisallowed": False,
            "PayloadContent": [{
                "PayloadType": "com.apple.security.root",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"local.mac-touchpad.ca.{fp[:16]}",
                "PayloadUUID": payload_uuid,
                "PayloadDisplayName": cn,
                "PayloadCertificateFileName": "mac-touchpad-ca.cer",
                "PayloadContent": self.ca_der,
            }],
        }
        return plistlib.dumps(profile)
