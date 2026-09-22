from typing import Dict, Any


class ConfidenceEngine:
    """Calculate confidence for vulnerability findings."""

    def calculate(
        self,
        service: str | None,
        product: str | None,
        version: str | None,
        cpe: str | None,
        vulnerabilities: list[Dict[str, Any]],
    ) -> str:
        """
        Calculate confidence based on the quality of
        asset identification and vulnerability correlation.
        """

        score = 0

        if service:
            score += 1

        if product:
            score += 1

        if version:
            score += 2

        if cpe:
            score += 2

        if vulnerabilities:
            score += 2

        if score >= 7:
            return "HIGH"

        if score >= 4:
            return "MEDIUM"

        return "LOW"

