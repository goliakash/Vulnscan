from typing import Dict, Any


class AlertManager:
    """Decides whether security findings should be escalated."""

    ESCALATION_SEVERITIES = {"CRITICAL", "HIGH"}
    ESCALATION_CONFIDENCE = {"HIGH", "MEDIUM"}

    def should_escalate(self, finding: Dict[str, Any]) -> bool:
        """
        Determine whether a finding should be escalated to the SOC.
        """

        severity = finding.get("severity", "INFO")
        confidence = finding.get("confidence", "LOW")

        return (
            severity in self.ESCALATION_SEVERITIES
            and confidence in self.ESCALATION_CONFIDENCE
        )

    def get_highest_risk_vulnerability(
        self,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Select the highest-risk vulnerability from a finding.

        Severity is considered first, followed by CVSS score.
        """

        vulnerabilities = finding.get("vulnerabilities", [])

        if not vulnerabilities:
            return {}

        severity_order = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "NONE": 0,
            "UNKNOWN": 0,
        }

        return max(
            vulnerabilities,
            key=lambda vulnerability: (
                severity_order.get(
                    vulnerability.get("severity", "UNKNOWN"),
                    0
                ),
                vulnerability.get("cvss") or 0,
            )
        )

    def create_alert(
        self,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Convert a security finding into a structured SOC alert.
        """

        top_vulnerability = (
            self.get_highest_risk_vulnerability(finding)
        )

        return {
            "alert_type": "VULNERABILITY",
            "finding_id": finding.get("finding_id"),
            "target": finding.get("target"),
            "port": finding.get("port"),
            "service": finding.get("service"),
            "product": finding.get("product"),
            "version": finding.get("version"),

            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),

            "cve": top_vulnerability.get("cve"),
            "cvss": top_vulnerability.get("cvss"),
            "vulnerability_severity": top_vulnerability.get(
                "severity"
            ),

            "evidence": finding.get("evidence", []),

            "status": "ESCALATED",
        }
