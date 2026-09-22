from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    finding_id: str
    target: str
    port: int
    protocol: str = "tcp"

    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None

    cpe: Optional[str] = None
    cve: Optional[str] = None
    cvss: Optional[float] = None

    severity: str = "INFO"
    confidence: str = "LOW"

    evidence: List[str] = field(default_factory=list)
    remediation: Optional[str] = None

    status: str = "OPEN"

    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "target": self.target,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "cpe": self.cpe,
            "cve": self.cve,
            "cvss": self.cvss,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "status": self.status,
        }