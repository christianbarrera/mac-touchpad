"""Make the self-signed code-signing identity for Mac Touchpad.app.

Writes <out>/identity.p12 (key + certificate, encrypted with the given
passphrase in the legacy format macOS's `security import` understands) and
<out>/cert.pem. Called by tools/setup_signing.sh; the files only live in a
private temporary folder for the few seconds the import takes.

    python tools/make_signing_identity.py OUTDIR "Mac Touchpad Code Signing" PASSPHRASE
"""
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DAYS = 3650


def main(out: str, name: str, passphrase: str):
    out = Path(out)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=DAYS))
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
           .kdf_rounds(50000)
           .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
           .hmac_hash(hashes.SHA1())
           .build(passphrase.encode()))
    (out / "identity.p12").write_bytes(pkcs12.serialize_key_and_certificates(name.encode(), key, cert, None, enc))
    (out / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(cert.fingerprint(hashes.SHA1()).hex().upper())


if __name__ == "__main__":
    main(*sys.argv[1:4])
