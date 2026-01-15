#!/bin/bash
set -e

echo "Building Aegis Fusion..."

# 1. Build kernel driver (Windows)
echo "Building kernel driver..."
cd kernel/windows
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cd ../..

# 2. Build Rust core
echo "Building core engine..."
cd core
cargo build --release
cd ..

# 3. Train/Export ML models
echo "Exporting ML models..."
cd ml/inference
python onnx_export.py
cd ../..

# 4. Build UI
echo "Building UI..."
cd ui
npm install
npm run build
npm run electron:build
cd ..

echo "Build complete."
