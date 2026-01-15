import argparse
import json
import os
import time


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis Fusion model monitor (stub)")
    parser.add_argument("--registry-dir", default="./registry", help="Registry directory")
    parser.add_argument("--report-path", default="./monitor_report.json", help="Report output")
    args = parser.parse_args()

    latest_path = os.path.join(args.registry_dir, "latest.json")
    if not os.path.exists(latest_path):
        raise SystemExit("No deployed model found. Run deployer.py first.")

    with open(latest_path, "r", encoding="utf-8") as handle:
        latest = json.load(handle)

    report = {
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_version": latest.get("version"),
        "model_path": latest.get("path"),
        "status": "ok",
        "metrics": {
            "drift_score": 0.02,
            "false_positive_rate": 0.01,
            "latency_ms": 25,
        },
    }

    with open(args.report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    print(f"[MONITOR] report written: {args.report_path}")


if __name__ == "__main__":
    main()
