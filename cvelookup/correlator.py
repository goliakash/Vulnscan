"""Correlate NVD CVEs with detected CPEs."""

from typing import List, Dict, Optional
from packaging.version import Version, InvalidVersion


class CVECorrelator:
    def __init__(self, nvd_client):
        self.nvd_client = nvd_client

    async def correlate(self, cpe: str) -> List[Dict]:
        """
        Return CVEs where the detected CPE/version falls
        within a vulnerable NVD version range.
        """
        if not cpe:
            return []

        candidates = await self.nvd_client.lookup(cpe)

        matches = []

        for cve in candidates:
            if self._cve_matches_cpe(cve, cpe):
                matches.append(cve)

        return matches

    def _cve_matches_cpe(self, cve: Dict, target_cpe: str) -> bool:
        """
        Check whether the detected CPE/version is covered by
        a vulnerable CPE match in the NVD configuration.
        """

        configurations = cve.get("configurations", [])

        target_parts = target_cpe.split(":")

        if len(target_parts) < 6:
            return False

        target_vendor = target_parts[3]
        target_product = target_parts[4]
        target_version = target_parts[5]

        for configuration in configurations:
            nodes = configuration.get("nodes", [])

            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])

                for match in cpe_matches:
                    if not match.get("vulnerable", False):
                        continue

                    criteria = match.get("criteria", "")
                    criteria_parts = criteria.split(":")

                    if len(criteria_parts) < 6:
                        continue

                    criteria_vendor = criteria_parts[3]
                    criteria_product = criteria_parts[4]

                    if criteria_vendor != target_vendor:
                        continue

                    if criteria_product != target_product:
                        continue

                    if self._version_in_range(
                        target_version,
                        match
                    ):
                        return True

        return False

    def _version_in_range(
        self,
        version: str,
        match: Dict
    ) -> bool:
        """
        Check whether a detected version satisfies the
        NVD version constraints.
        """

        try:
            current = Version(version)
        except InvalidVersion:
            return False

        start_including = match.get("versionStartIncluding")
        start_excluding = match.get("versionStartExcluding")
        end_including = match.get("versionEndIncluding")
        end_excluding = match.get("versionEndExcluding")

        if start_including:
            try:
                if current < Version(start_including):
                    return False
            except InvalidVersion:
                return False

        if start_excluding:
            try:
                if current <= Version(start_excluding):
                    return False
            except InvalidVersion:
                return False

        if end_including:
            try:
                if current > Version(end_including):
                    return False
            except InvalidVersion:
                return False

        if end_excluding:
            try:
                if current >= Version(end_excluding):
                    return False
            except InvalidVersion:
                return False

        return True