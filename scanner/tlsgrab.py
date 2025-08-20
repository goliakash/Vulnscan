# scanner/tlsgrab.py
"""TLS/SSL certificate grabbing for VulnScan."""
import ssl
import asyncio
from typing import Dict, Any


class TLSGrabber:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def grab(self, host: str, port: int) -> Dict[str, Any]:
        """Attempt to retrieve TLS certificate information from host:port."""
        info: Dict[str, Any] = {"cert": None, "subject": None, "issuer": None}
        try:
            ssl_ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.timeout,
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    cert = ssl_obj.getpeercert()
                    info["cert"] = cert
                    info["subject"] = cert.get("subject")
                    info["issuer"] = cert.get("issuer")
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            # Silent fail to avoid breaking scans
            pass
        return info
