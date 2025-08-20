import argparse
import asyncio
import sys
from pathlib import Path

# --- Ensure package imports work even if run directly ---
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.portscan import PortScanner
from output.formatter import ConsoleReporter
from output.formatter import JSONReporter


def parse_args():
    p = argparse.ArgumentParser(description="VulnScan - modular async vulnerability scanner")
    p.add_argument("target", help="Target IP/hostname to scan")
    p.add_argument("--start-port", type=int, default=1)
    p.add_argument("--end-port", type=int, default=1024)
    p.add_argument("--concurrency", type=int, default=200)
    p.add_argument("--save", action="store_true", help="Save JSON results")
    p.add_argument(
        "--signatures",
        default=str(PROJECT_ROOT / "signatures" / "signatures.json"),
        help="Path to signatures JSON file",
    )
    return p.parse_args()


async def main():
    args = parse_args()

    scanner = PortScanner(
        target=args.target,
        start_port=args.start_port,
        end_port=args.end_port,
        concurrency=args.concurrency,
        signatures_path=args.signatures,
    )

    results = await scanner.run()
    ConsoleReporter().report(results)

    if args.save:
        filename = JSONReporter().save(results, target=args.target)
        print(f"Saved results to: {filename}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Scan cancelled by user")
        sys.exit(1)