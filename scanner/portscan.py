# scanner/portscan.py
"""
Async port scanner that connects to ports, grabs banners, and matches fingerprints.
"""

import asyncio
from typing import Dict, Any

from scanner.httpgrab import BannerGrabber
from scanner.fingerprint import FingerprintMatcher


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

        return {
            "port": port,
            "status": "OPEN",
            "banner": banner_info,
            "service": banner_info.get("service") if isinstance(banner_info, dict) else None,
            "vulnerabilities": vulns,
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
