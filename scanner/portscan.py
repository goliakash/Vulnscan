# scanner/portscan.py
"""
Async port scanner that connects to ports, grabs banners, and matches fingerprints.
"""

import asyncio
from typing import Dict, Any

from scanner.httpgrab import BannerGrabber
from scanner.fingerprint import FingerprintMatcher
from models.finding import Finding


class PortScanner:
    def __init__(
        self,
        target: str,
        start_port: int = 1,
        end_port: int = 1024,
        concurrency: int = 200,
        signatures_path: str = None
    ):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.concurrency = concurrency
        self.banner_grabber = BannerGrabber()
        self.matcher = FingerprintMatcher(signatures_path)

    async def _scan_port(self, port: int) -> Dict[str, Any]:
        """
        Attempt to connect to the given port and grab service banners.
        """
        try:
            conn = asyncio.open_connection(self.target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2)
        except Exception:
            return {
                "port": port,
                "status": "CLOSED",
                "banner": None,
                "service": None,
                "vulnerabilities": []
            }

        try:
            banner_info = await self.banner_grabber.grab(self.target, port, reader, writer)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        vulns = self.matcher.match(banner_info)
        identity = self.matcher.identify(banner_info)

        service = banner_info.get("service") if isinstance(banner_info, dict) else None

        product = identity.get("product") if identity else None
        version = identity.get("version") if identity else None
        cpe = identity.get("cpe") if identity else None

        evidence = [
            f"Port {port} is open",
            f"Service detected: {service or 'unknown'}"
        ]

        if product:
            evidence.append(f"Product identified: {product}")

        if version:
            evidence.append(f"Version identified: {version}")

        if cpe:
            evidence.append(f"CPE identified: {cpe}")

        finding = Finding(
            finding_id=f"VS-{port}",
            target=self.target,
            port=port,
            service=service,
            product=product,
            version=version,
            cpe=cpe,
            confidence="MEDIUM",
            evidence=evidence
        )

        return {
            "port": port,
            "status": "OPEN",
            "banner": banner_info,
            "service": service,
            "vulnerabilities": vulns,
            "finding": finding.to_dict(),
        }

    async def run(self) -> Dict[str, Any]:
        """
        Scan the specified range of ports concurrently.
        """
        results = []
        sem = asyncio.Semaphore(self.concurrency)

        async def worker(p):
            async with sem:
                return await self._scan_port(p)

        tasks = [worker(p) for p in range(self.start_port, self.end_port + 1)]
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)

        results.sort(key=lambda x: x["port"])
        return {"target": self.target, "results": results}
