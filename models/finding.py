from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class Vulnerability:
    """Represents a CVE correlated with a detected asset."""

    cve: str
    cvss: Optional[float] = None
    severity: str = "UNKNOWN"
    description: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve": self.cve,
            "cvss": self.cvss,
            "severity": self.severity,
            "description": self.description,
            "published": self.published,
            "last_modified": self.last_modified,
            "remediation": self.remediation,
        }


@dataclass
class Finding:
    """Represents a security finding for a discovered service."""

    finding_id: str
    target: str
    port: int
    protocol: str = "tcp"

    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None

    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    severity: str = "INFO"
    confidence: str = "LOW"

    evidence: List[str] = field(default_factory=list)

    status: str = "OPEN"
    verification_status: str = "POTENTIAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "target": self.target,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "cpe": self.cpe,
            "vulnerabilities": [
                vulnerability.to_dict()
                for vulnerability in self.vulnerabilities
            ],
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "status": self.status,
            "verification_status": self.verification_status,
        }