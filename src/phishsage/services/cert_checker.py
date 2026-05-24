import ssl
import socket
import asyncio
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
except ImportError as exc:
    raise ImportError(
        "Link analysis requires additional dependencies. "
        "Install with: pip install phishsage[links]"
    ) from exc


from phishsage.models.certificate import CertificateResult



class SSLService:

    def __init__(
        self,
        port: int,
        timeout: int = 10,
        operation_timeout: int = 15,
    ):
        self.port = port
        self.timeout = timeout
        self.operation_timeout = operation_timeout

    async def fetch(self, hostname: str) -> CertificateResult:
        return await asyncio.wait_for(
            asyncio.to_thread(self._fetch_sync, hostname),
            timeout=self.operation_timeout,
        )

    def _fetch_sync(self, hostname: str) -> CertificateResult:
        socket.setdefaulttimeout(self.timeout)
        cert_pem = ssl.get_server_certificate((hostname, self.port))
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        now = datetime.now(timezone.utc)
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc

        days_since_issued = (now - valid_from).total_seconds() / 86400
        days_until_expiry = (valid_to - now).total_seconds() / 86400

        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

        return CertificateResult(
            issuer=issuer_cn[0].value if issuer_cn else None,
            subject=subject_cn[0].value if subject_cn else None,
            valid_from=valid_from.isoformat(),
            valid_to=valid_to.isoformat(),
            days_since_issued=int(days_since_issued),
            days_until_expiry=int(days_until_expiry),
        )