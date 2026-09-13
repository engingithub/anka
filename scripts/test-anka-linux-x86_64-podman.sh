#!/usr/bin/env bash
# Build and test Anka for Linux x86_64 from macOS using Podman.
#
# Usage:
#   ./scripts/test-anka-linux-x86_64-podman.sh
#   ./scripts/test-anka-linux-x86_64-podman.sh --debug
#   ./scripts/test-anka-linux-x86_64-podman.sh --clean
#
# Output:
#   dist/anka-linux-x86_64
#
# The Linux build uses its own target-linux-x86_64/ directory and never
# overwrites the native macOS target/ or anka binary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="${ANKA_LINUX_BUILD_IMAGE:-docker.io/library/rust:bookworm}"
PLATFORM="linux/amd64"

BUILD_TYPE="release"
DO_CLEAN=false

for arg in "$@"; do
    case "$arg" in
        --debug)   BUILD_TYPE="debug" ;;
        --clean)   DO_CLEAN=true ;;
        --help|-h)
            cat <<'EOF'
Build and test Anka for Linux x86_64 inside Podman.

Options:
  --debug       Build debug binary
  --clean       Remove the dedicated Linux target directory first
  --help        Show this help

Environment:
  ANKA_LINUX_BUILD_IMAGE    Container image (default rust:bookworm)

Output:
  dist/anka-linux-x86_64
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

command -v podman >/dev/null 2>&1 || {
    echo "error: podman was not found on PATH" >&2
    exit 1
}

if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "error: Cargo.toml not found at project root: $PROJECT_ROOT" >&2
    exit 1
fi

TARGET_DIR="$PROJECT_ROOT/target-linux-x86_64"
DIST_DIR="$PROJECT_ROOT/dist"

if [ "$DO_CLEAN" = true ]; then
    echo "Cleaning $TARGET_DIR"
    rm -rf "$TARGET_DIR"
fi

mkdir -p "$TARGET_DIR" "$DIST_DIR"

echo "Building Anka for Linux x86_64"
echo "  Project:   $PROJECT_ROOT"
echo "  Platform:  $PLATFORM"
echo "  Image:     $IMAGE"
echo "  Mode:      $BUILD_TYPE"
echo

podman run --rm -i \
    --platform "$PLATFORM" \
    -v "$PROJECT_ROOT:/work:Z" \
    -w /work \
    -e CARGO_TARGET_DIR=/work/target-linux-x86_64 \
    -e ANKA_BUILD_TYPE="$BUILD_TYPE" \
    "$IMAGE" \
    bash -s <<'CONTAINER_SCRIPT'
set -euo pipefail

export PATH="/usr/local/cargo/bin:/usr/local/rustup/bin:$PATH"
export DEBIAN_FRONTEND=noninteractive

echo "Rust toolchain:"
echo "  cargo: $(command -v cargo)"
cargo --version
rustc --version
echo

echo "Installing Linux build dependencies..."
apt-get update

PACKAGES=(
    build-essential
    pkg-config
)

apt-get install -y --no-install-recommends "${PACKAGES[@]}"
rm -rf /var/lib/apt/lists/*

CARGO_ARGS=(build --bin anka)

if [ "$ANKA_BUILD_TYPE" = "release" ]; then
    CARGO_ARGS+=(--release)
    TEST_ARGS=(test --release -- --test-threads=1)
else
    TEST_ARGS=(test -- --test-threads=1)
fi

echo
echo "Running tests (serial — QEMU emulation is memory-hungry)..."
cargo "${TEST_ARGS[@]}"

echo
printf 'Running: cargo'
printf ' %q' "${CARGO_ARGS[@]}"
printf '\n'

cargo "${CARGO_ARGS[@]}"
CONTAINER_SCRIPT

if [ "$BUILD_TYPE" = "release" ]; then
    BUILT_BINARY="$TARGET_DIR/release/anka"
else
    BUILT_BINARY="$TARGET_DIR/debug/anka"
fi

if [ ! -f "$BUILT_BINARY" ]; then
    echo "error: expected binary was not produced:" >&2
    echo "  $BUILT_BINARY" >&2
    exit 1
fi

OUTPUT_BINARY="$DIST_DIR/anka-linux-x86_64"
cp "$BUILT_BINARY" "$OUTPUT_BINARY"
chmod +x "$OUTPUT_BINARY"

echo
echo "Build successful."
echo "Linux binary:"
echo "  $OUTPUT_BINARY"

if command -v file >/dev/null 2>&1; then
    echo
    file "$OUTPUT_BINARY"
fi

echo
echo "Checking Linux dynamic dependencies inside amd64 container..."
podman run --rm \
    --platform "$PLATFORM" \
    -v "$PROJECT_ROOT:/work:Z" \
    "$IMAGE" \
    bash -c 'ldd /work/dist/anka-linux-x86_64 || true'

echo
echo "Output name is intentionally separate from the native macOS binary."
