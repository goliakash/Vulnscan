"""NVD CVE lookup client."""

import asyncio
from typing import List, Dict

import aiohttp


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = None):
        self.api_key = api_key

        # Cache: CPE -> CVE results
        self._cache: Dict[str, List[Dict]] = {}

    async def lookup(self, cpe: str) -> List[Dict]:
        """
        Lookup CVEs associated with a CPE using the NVD API.
        """

        if not cpe:
            return []

        if cpe in self._cache:
            return self._cache[cpe]

        headers = {
            "User-Agent": "VulnScan/2.0"
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {
            "cpeName": cpe,
            "resultsPerPage": 100
        }

        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(
                    self.BASE_URL,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:

                    if response.status == 429:
                        print("NVD API rate limit reached.")
                        return []

                    if response.status != 200:
                        print(f"NVD API error: HTTP {response.status}")
                        return []

                    data = await response.json()

        except asyncio.TimeoutError:
            print("NVD API request timed out.")
            return []

        except aiohttp.ClientError as exc:
            print(f"NVD API connection error: {exc}")
            return []

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            cve_id = cve.get("id")

            descriptions = cve.get("descriptions", [])

            description = ""

            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            cvss_score = None
            severity = None

            metrics = cve.get("metrics", {})

            # Prefer CVSS v3.1
            if metrics.get("cvssMetricV31"):
                metric = metrics["cvssMetricV31"][0]
                cvss_data = metric.get("cvssData", {})

                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")

            # Fall back to CVSS v3.0
            elif metrics.get("cvssMetricV30"):
                metric = metrics["cvssMetricV30"][0]
                cvss_data = metric.get("cvssData", {})

                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")

            # Fall back to CVSS v4.0 if available
            elif metrics.get("cvssMetricV40"):
                metric = metrics["cvssMetricV40"][0]
                cvss_data = metric.get("cvssData", {})

                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")

            vulnerabilities.append({
                "cve": cve_id,
                "description": description,
                "cvss": cvss_score,
                "severity": severity,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified")
            })

        self._cache[cpe] = vulnerabilities

        return vulnerabilities