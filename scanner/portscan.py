"""
Async port scanner that connects to ports, grabs banners,
matches fingerprints, correlates CVEs, builds findings,
and generates SOC alerts for high-risk findings.
"""

import asyncio
from typing import Dict, Any

from scanner.httpgrab import BannerGrabber
from scanner.fingerprint import FingerprintMatcher
from models.finding import Finding, Vulnerability
from cvelookup.nvd_client import NVDClient
from cvelookup.correlator import CVECorrelator
from risk.engine import RiskEngine
from alerting.manager import AlertManager
from risk.confidence import ConfidenceEngine
from risk.verifier import VerificationEngine


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

        # Scanner components
        self.banner_grabber = BannerGrabber()
        self.matcher = FingerprintMatcher(signatures_path)

        # Vulnerability correlation components
        self.nvd_client = NVDClient()
        self.correlator = CVECorrelator(self.nvd_client)
        self.risk_engine = RiskEngine()

        # SOC escalation component
        self.alert_manager = AlertManager()
        self.confidence_engine = ConfidenceEngine()
        self.verification_engine = VerificationEngine()
    async def _scan_port(self, port: int) -> Dict[str, Any]:
        """
        Attempt to connect to the given port and grab service banners.
        """

        # --------------------------------------------------
        # PORT CONNECTION
        # --------------------------------------------------

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

        # --------------------------------------------------
        # BANNER GRABBING
        # --------------------------------------------------

        try:
            banner_info = await self.banner_grabber.grab(
                self.target,
                port,
                reader,
                writer
            )

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        # --------------------------------------------------
        # SERVICE FINGERPRINTING
        # --------------------------------------------------

        self.matcher.match(banner_info)
        identity = self.matcher.identify(banner_info)

        service = (
            banner_info.get("service")
            if isinstance(banner_info, dict)
            else None
        )

        product = identity.get("product") if identity else None
        version = identity.get("version") if identity else None
        cpe = identity.get("cpe") if identity else None

        # --------------------------------------------------
        # EVIDENCE COLLECTION
        # --------------------------------------------------

        evidence = [
            f"Port {port} is open",
            f"Service detected: {service or 'unknown'}"
        ]

        if product:
            evidence.append(
                f"Product identified: {product}"
            )

        if version:
            evidence.append(
                f"Version identified: {version}"
            )

        if cpe:
            evidence.append(
                f"CPE identified: {cpe}"
            )

        # --------------------------------------------------
        # CVE CORRELATION
        # --------------------------------------------------

        correlated_vulnerabilities = []

        if cpe:
            correlated_vulnerabilities = (
                await self.correlator.correlate(cpe)
            )

            print(
                f"[DEBUG] CVEs returned: "
                f"{len(correlated_vulnerabilities)}"
            )

        # --------------------------------------------------
        # VULNERABILITY MODEL
        # --------------------------------------------------

        vulnerabilities = [
            Vulnerability(
                cve=vulnerability.get("cve"),
                cvss=vulnerability.get("cvss"),
                severity=vulnerability.get("severity") or "UNKNOWN",
                description=vulnerability.get("description"),
                published=vulnerability.get("published"),
                last_modified=vulnerability.get("last_modified"),
            )
            for vulnerability in correlated_vulnerabilities
        ]

        # --------------------------------------------------
        # RISK PRIORITIZATION
        # --------------------------------------------------

        risk_data = [
            vulnerability.to_dict()
            for vulnerability in vulnerabilities
        ]

        prioritized_vulnerabilities = (
            self.risk_engine.prioritize(risk_data)
        )

        highest_risk = (
            prioritized_vulnerabilities[0]
            if prioritized_vulnerabilities
            else None
        )

        finding_severity = (
            highest_risk["calculated_severity"]
            if highest_risk
            else "INFO"
        )

        # --------------------------------------------------
        # FINDING
        # --------------------------------------------------
        confidence = self.confidence_engine.calculate(
            service=service,
            product=product,
            version=version,
            cpe=cpe,
            vulnerabilities=risk_data,
        )
        verification = self.verification_engine.verify(
            product=product,
            version=version,
            cpe=cpe,
            vulnerabilities=risk_data,
            evidence=evidence,
        )
        finding = Finding(
            finding_id=f"VS-{port}",
            target=self.target,
            port=port,
            service=service,
            product=product,
            version=version,
            cpe=cpe,
            vulnerabilities=[
                Vulnerability(
                    cve=v["cve"],
                    cvss=v["cvss"],
                    severity=v["calculated_severity"],
                    description=v.get("description"),
                    published=v.get("published"),
                    last_modified=v.get("last_modified"),
                )
                for v in prioritized_vulnerabilities
            ],
            severity=finding_severity,
            confidence=confidence,
            evidence=evidence,
            verification_status=verification["verification_status"]
        )

        # Convert Finding object into dictionary
        finding_data = finding.to_dict()

        # --------------------------------------------------
        # SOC ESCALATION
        # --------------------------------------------------

        if self.alert_manager.should_escalate(finding_data):
            alert = self.alert_manager.create_alert(
                finding_data
            )

            print("\n🚨 SOC ALERT GENERATED")
            print(alert)

        # --------------------------------------------------
        # DEBUG
        # --------------------------------------------------

        print(
            f"[DEBUG] Returning vulnerabilities: "
            f"{len(correlated_vulnerabilities)}"
        )

        # --------------------------------------------------
        # RESULT
        # --------------------------------------------------

        return {
            "port": port,
            "status": "OPEN",
            "banner": banner_info,
            "service": service,
            "vulnerabilities": correlated_vulnerabilities,
            "finding": finding_data,
        }

    async def run(self) -> Dict[str, Any]:
        """
        Scan the specified range of ports concurrently.
        """

        results = []

        sem = asyncio.Semaphore(self.concurrency)

        async def worker(port):
            async with sem:
                return await self._scan_port(port)

        tasks = [
            worker(port)
            for port in range(
                self.start_port,
                self.end_port + 1
            )
        ]

        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)

        results.sort(
            key=lambda item: item["port"]
        )

        return {
            "target": self.target,
            "results": results
        }
