"""
Self-signed TLS certificate for serving the dashboard over HTTPS on the LAN.

WebAuthn (Touch ID / Face ID) and the PWA service worker both require a SECURE
CONTEXT: browsers only enable them over https:// or on localhost. A LAN appliance
accessed as http://iotsentinel.local can't satisfy that, so we generate a
long-lived self-signed certificate (with SANs for the mDNS name, localhost, the
provisioning-hotspot IP and the current LAN IP) and serve HTTPS. The browser
shows a one-time "not private" warning the user accepts once.

Best-effort: ``ensure_self_signed_cert`` never raises -- it returns None on any
failure so the caller can fall back to plain HTTP and the dashboard always boots.
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _covers(certfile: Path, hostnames, ips) -> bool:
    """True if an existing cert is still valid (>30 days) and already lists every
    requested SAN, so we can reuse it instead of regenerating each boot."""
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(certfile.read_bytes())
        if cert.not_valid_after <= datetime.datetime.utcnow() + datetime.timedelta(days=30):
            return False
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        have_dns = set(san.get_values_for_type(x509.DNSName))
        have_ip = {str(i) for i in san.get_values_for_type(x509.IPAddress)}
        return set(hostnames).issubset(have_dns) and set(ips).issubset(have_ip)
    except Exception:
        return False


def ensure_self_signed_cert(cert_dir, hostnames=None, ips=None, valid_days=3650):
    """Return (certfile, keyfile) paths for a self-signed cert covering the given
    hostnames/IPs, generating it if missing/expired/insufficient. None on failure.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        cert_dir = Path(cert_dir)
        cert_dir.mkdir(parents=True, exist_ok=True)
        certfile = cert_dir / "dashboard.crt"
        keyfile = cert_dir / "dashboard.key"

        # De-dupe while preserving order; CN uses the first hostname.
        hostnames = list(dict.fromkeys(hostnames or ["localhost", "iotsentinel.local"]))
        ips = list(dict.fromkeys(ips or ["127.0.0.1"]))

        if certfile.exists() and keyfile.exists() and _covers(certfile, hostnames, ips):
            return str(certfile), str(keyfile)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoTSentinel"),
        ])
        san = [x509.DNSName(h) for h in hostnames]
        for ip in ips:
            try:
                san.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                continue

        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=valid_days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        keyfile.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        try:
            keyfile.chmod(0o600)
        except OSError:
            pass
        logger.info(f"Generated self-signed cert ({hostnames} / {ips}) -> {certfile}")
        return str(certfile), str(keyfile)
    except Exception as e:
        logger.error(f"Could not create self-signed cert: {e}")
        return None
