#!/bin/bash
# Build ibctl and create Docker test image
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Building Rust binary ==="
cd "$PROJECT_DIR"
cargo build 2>&1 | tail -3

echo "=== Building Java agent ==="
cd "$PROJECT_DIR/agent"
mkdir -p target/classes
javac --release 17 -d target/classes src/main/java/ibctl/agent/*.java
jar cfm target/ibctl-agent.jar src/main/resources/META-INF/MANIFEST.MF -C target/classes .
echo "Agent jar: $(ls -la target/ibctl-agent.jar | awk '{print $5}') bytes"

echo "=== Copying artifacts to docker context ==="
cp "$PROJECT_DIR/target/debug/ibctl" "$SCRIPT_DIR/ibctl"
cp "$PROJECT_DIR/agent/target/ibctl-agent.jar" "$SCRIPT_DIR/ibctl-agent.jar"

echo "=== Building Docker image ==="
cd "$SCRIPT_DIR"
docker build -t ibctl-test .

echo "=== Done ==="
echo "Run with: cd docker && docker compose up"
