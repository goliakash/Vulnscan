from typing import Dict, Any


class VerificationEngine:
    """
    Evaluate the strength of evidence supporting a
    vulnerability correlation.

    This engine does not exploit vulnerabilities.
    """

    def verify(
        self,
        product: str | None,
        version: str | None,
        cpe: str | None,
        vulnerabilities: list[Dict[str, Any]],
        evidence: list[str],
    ) -> Dict[str, Any]:
        """
        Classify a finding based on available evidence.
        """

        score = 0
        verification_status = "POTENTIAL"

        # Product identified
        if product:
            score += 1

        # Exact version identified
        if version:
            score += 2

        # CPE generated
        if cpe:
            score += 2

        # CVE correlation succeeded
        if vulnerabilities:
            score += 2

        # Evidence was collected
        if evidence:
            score += 1

        if score >= 7:
            verification_status = "LIKELY"
        elif score >= 4:
            verification_status = "POTENTIAL"

        return {
            "verification_status": verification_status,
            "verification_score": score,
            "verification_reason": (
                "Finding is supported by observed service, "
                "version, CPE and CVE correlation evidence."
                if verification_status == "LIKELY"
                else
                "Finding is correlated with available asset "
                "information but requires additional verification."
            ),
        }

