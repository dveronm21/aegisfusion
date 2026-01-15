import argparse
import json
import os
import shutil
import time


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis Fusion model deployer (stub)")
    parser.add_argument("--model-path", required=True, help="Path to model binary")
    parser.add_argument("--registry-dir", default="./registry", help="Registry directory")
    parser.add_argument("--version", default="", help="Version label override")
    args = parser.parse_args()

    if not os.path.exists(args.model_path):
        raise SystemExit(f"Model not found: {args.model_path}")

    version = args.version or os.path.basename(args.model_path).replace(".bin", "")
    os.makedirs(args.registry_dir, exist_ok=True)

    target = os.path.join(args.registry_dir, os.path.basename(args.model_path))
    shutil.copy2(args.model_path, target)

    payload = {
        "version": version,
        "path": target,
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(args.registry_dir, "latest.json"), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    print(f"[DEPLOY] deployed {target}")


if __name__ == "__main__":
    main()
