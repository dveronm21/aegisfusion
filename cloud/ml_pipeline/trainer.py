import argparse
import hashlib
import json
import os
import time


def write_dummy_model(output_dir: str, version: str, dataset: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, f"aegis-model-{version}.bin")
    with open(model_path, "wb") as handle:
        handle.write(os.urandom(1024 * 128))

    sha256 = hashlib.sha256()
    with open(model_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            sha256.update(chunk)

    metadata = {
        "version": version,
        "dataset": dataset,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sha256": sha256.hexdigest(),
        "size_bytes": os.path.getsize(model_path),
    }
    metadata_path = os.path.join(output_dir, f"aegis-model-{version}.json")
    with open(metadata_path, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)

    return model_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis Fusion ML trainer (stub)")
    parser.add_argument("--output-dir", default="./models", help="Output directory for artifacts")
    parser.add_argument("--version", default="0.1.0", help="Model version label")
    parser.add_argument("--dataset", default="dataset.csv", help="Dataset path or identifier")
    args = parser.parse_args()

    model_path = write_dummy_model(args.output_dir, args.version, args.dataset)
    print(f"[TRAIN] model artifact written: {model_path}")


if __name__ == "__main__":
    main()
