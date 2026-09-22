import asyncio

from scanner.fingerprint import FingerprintMatcher
from cvelookup.nvd_client import NVDClient
from cvelookup.correlator import CVECorrelator
from risk.engine import RiskEngine
from models.finding import Finding, Vulnerability


async def main():
    # -----------------------------
    # 1. Fingerprint the target
    # -----------------------------
    matcher = FingerprintMatcher("signatures/fingerprints.json")

    banner = {
        "raw": "Apache/2.4.58"
    }

    identity = matcher.identify(banner)

    # -----------------------------
    # 2. Correlate CVEs
    # -----------------------------
    nvd_client = NVDClient()
    correlator = CVECorrelator(nvd_client)

    correlated = await correlator.correlate(identity["cpe"])

    vulnerabilities = [
        Vulnerability(
            cve=v.get("cve"),
            cvss=v.get("cvss"),
            severity=v.get("severity") or "UNKNOWN",
            description=v.get("description"),
            published=v.get("published"),
            last_modified=v.get("last_modified"),
        )
        for v in correlated
    ]

    # -----------------------------
    # 3. Risk prioritization
    # -----------------------------
    risk_engine = RiskEngine()

    risk_data = [
        vulnerability.to_dict()
        for vulnerability in vulnerabilities
    ]

    prioritized = risk_engine.prioritize(risk_data)

    highest_risk = (
        prioritized[0]
        if prioritized
        else None
    )

    finding_severity = (
        highest_risk["calculated_severity"]
        if highest_risk
        else "INFO"
    )

    # -----------------------------
    # 4. Create security finding
    # -----------------------------
    finding = Finding(
        finding_id="VS-8080",
        target="127.0.0.1",
        port=8080,
        service="Apache",
        product=identity["product"],
        version=identity["version"],
        cpe=identity["cpe"],
        vulnerabilities=vulnerabilities,
        severity=finding_severity,
        confidence="MEDIUM",
    )

    # -----------------------------
    # 5. Display results
    # -----------------------------
    print("Product:", finding.product)
    print("Version:", finding.version)
    print("CPE:", finding.cpe)
    print("Total vulnerabilities:", len(finding.vulnerabilities))

    print("\nTop 5:")

    for vulnerability in prioritized[:5]:
        print(
            vulnerability["cve"],
            "| CVSS:",
            vulnerability["cvss"],
            "| Severity:",
            vulnerability["calculated_severity"],
        )

    print("\nFinding severity:")
    print(finding.severity)

    print("\nFinding dictionary:")
    print(finding.to_dict())


if __name__ == "__main__":
    asyncio.run(main())
