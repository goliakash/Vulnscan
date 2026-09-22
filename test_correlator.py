import asyncio

from cvelookup.nvd_client import NVDClient
from cvelookup.correlator import CVECorrelator


async def main():
    client = NVDClient()
    correlator = CVECorrelator(client)

    cpe = "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:*:*"

    results = await correlator.correlate(cpe)

    print(f"Total correlated CVEs: {len(results)}")

    for result in results:
        print(
            result["cve"],
            "| CVSS:", result["cvss"],
            "| Severity:", result["severity"]
        )


asyncio.run(main())