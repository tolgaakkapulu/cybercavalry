"""
Generate a self-signed SSL certificate for CAVALRY.
Requires: cryptography (included in requirements.txt)
Usage: python generate_cert.py
"""
import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress

BASE_DIR = Path(__file__).parent
CERT_DIR = BASE_DIR / 'certs'
CERT_DIR.mkdir(exist_ok=True)

CERT_FILE = CERT_DIR / 'cert.pem'
KEY_FILE = CERT_DIR / 'key.pem'


def generate():
    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CYBERCavalry"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CYBERCavalry.local"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("cybercavalry.local"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write key
    with open(KEY_FILE, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    # Write cert
    with open(CERT_FILE, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Self-signed certificate generated:")
    print(f"  Certificate: {CERT_FILE}")
    print(f"  Private key: {KEY_FILE}")
    print(f"  Valid for: 10 years")
    print()
    print("NOTE: This is a self-signed cert. Browsers will show a warning.")
    print("Replace with a proper certificate for production use.")


if __name__ == '__main__':
    generate()
