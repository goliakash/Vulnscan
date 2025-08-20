# scanner/fingerprint.py
"""Match grabbed banners to known fingerprints."""
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional


class FingerprintMatcher:
    def __init__(self, signatures_path: str):
        self.signatures_path = Path(signatures_path)
        self.signatures: List[Dict[str, Any]] = []
        self._load_signatures()

    def _load_signatures(self) -> None:
        if self.signatures_path.exists():
            try:
                with open(self.signatures_path, "r", encoding="utf-8") as f:
                    self.signatures = json.load(f)
            except Exception:
                self.signatures = []
        else:
            self.signatures = []

    def match(self, banner_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return list of matching signature dicts for the given banner info."""
        text = ""
        if isinstance(banner_info, dict):
            parts = []
            if banner_info.get("raw"):
                parts.append(str(banner_info.get("raw")))
            if banner_info.get("http"):
                parts.append(str(banner_info.get("http")))
            if banner_info.get("tls"):
                parts.append(str(banner_info.get("tls")))
            text = " | ".join(parts).lower()
        else:
            text = str(banner_info).lower()

        matches = []
        for sig in self.signatures:
            patt = sig.get("regex")
            substr = sig.get("substring")
            try:
                if patt and re.search(patt, text, re.IGNORECASE):
                    matches.append(sig)
                    continue
                if substr and substr.lower() in text:
                    matches.append(sig)
            except re.error:
                continue

        return matches
