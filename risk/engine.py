"""Risk prioritization engine for VulnScan."""

from typing import List, Dict


class RiskEngine:
    """Calculate and prioritize vulnerability risk."""

    SEVERITY_ORDER = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "NONE": 0,
        "UNKNOWN": 0,
    }

    def calculate_severity(self, cvss: float | None) -> str:
        """Convert a CVSS score into a severity category."""

        if cvss is None:
            return "UNKNOWN"

        if cvss >= 9.0:
            return "CRITICAL"

        if cvss >= 7.0:
            return "HIGH"

        if cvss >= 4.0:
            return "MEDIUM"

        if cvss > 0:
            return "LOW"

        return "NONE"

    def prioritize(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Sort vulnerabilities from highest to lowest risk.
        """

        for vulnerability in vulnerabilities:
            cvss = vulnerability.get("cvss")

            vulnerability["calculated_severity"] = self.calculate_severity(
                cvss
            )

        return sorted(
            vulnerabilities,
            key=lambda item: (
                self.SEVERITY_ORDER.get(
                    item.get("calculated_severity", "UNKNOWN"),
                    0,
                ),
                item.get("cvss") or 0,
            ),
            reverse=True,
        )

    def highest_risk(self, vulnerabilities: List[Dict]) -> Dict | None:
        """Return the highest-risk vulnerability."""

        prioritized = self.prioritize(vulnerabilities)

        if not prioritized:
            return None

        return prioritized[0]