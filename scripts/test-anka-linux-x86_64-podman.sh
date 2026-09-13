#!/usr/bin/env bash
# Build, test, strip, and package Anka for Linux x86_64 from macOS using Podman.
#
# Default usage:
#   ./test-anka-linux-x86_64-podman.sh
#
# Optional:
#   ./test-anka-linux-x86_64-podman.sh --clean
#
# Environment:
#   ANKA_LINUX_BUILD_IMAGE   Container image (default: docker.io/library/rust:bookworm)
#   ANKA_BIN_TARGET          Cargo binary target (default: anka)
#   ANKA_OUTPUT_NAME         Output filename (default: anka-linux-x86_64)
#
# The test suite is intentionally single-threaded because linux/amd64 under
# QEMU on an ARM Mac can consume excessive memory when Rust tests run in
# parallel.
#
# Output:
#   dist/anka-linux-x86_64
#
# The Linux build uses its own target-linux-x86_64/ directory and never
# overwrites the native macOS target/ directory or native binary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Allow the script to live either in ./scripts/ or directly at project root.
if [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
    PROJECT_ROOT="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../Cargo.toml" ]; then
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    echo "error: could not find Cargo.toml in:" >&2
    echo "  $SCRIPT_DIR" >&2
    echo "  $SCRIPT_DIR/.." >&2
    exit 1
fi

IMAGE="${ANKA_LINUX_BUILD_IMAGE:-docker.io/library/rust:bookworm}"
PLATFORM="linux/amd64"
BIN_TARGET="${ANKA_BIN_TARGET:-anka}"
OUTPUT_NAME="${ANKA_OUTPUT_NAME:-anka-linux-x86_64}"

TARGET_DIR="$PROJECT_ROOT/target-linux-x86_64"
DIST_DIR="$PROJECT_ROOT/dist"
OUTPUT_BINARY="$DIST_DIR/$OUTPUT_NAME"

DO_CLEAN=false

for arg in "$@"; do
    case "$arg" in
        --clean)
            DO_CLEAN=true
            ;;
        --help|-h)
            cat <<EOF
Build, test, strip, and package Anka for Linux x86_64 using Podman.

Usage:
  $0 [--clean]

Options:
  --clean       Remove target-linux-x86_64 before building.
  --help        Show this help.

Environment:
  ANKA_LINUX_BUILD_IMAGE   Container image
                           default: docker.io/library/rust:bookworm
  ANKA_BIN_TARGET          Cargo binary target
                           default: anka
  ANKA_OUTPUT_NAME         Packaged output filename
                           default: anka-linux-x86_64

Output:
  dist/\$ANKA_OUTPUT_NAME
EOF
            exit 0
            ;;
        *)
            echo "error: unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

command -v podman >/dev/null 2>&1 || {
    echo "error: podman was not found on PATH" >&2
    exit 1
}

if [ "$DO_CLEAN" = true ]; then
    echo "Cleaning $TARGET_DIR"
    rm -rf "$TARGET_DIR"
fi

mkdir -p "$TARGET_DIR" "$DIST_DIR"

echo "Anka Linux x86_64 portability build"
echo "  Project:      $PROJECT_ROOT"
echo "  Platform:     $PLATFORM"
echo "  Image:        $IMAGE"
echo "  Cargo binary: $BIN_TARGET"
echo "  Output:       $OUTPUT_BINARY"
echo

podman run --rm -i \
    --platform "$PLATFORM" \
    -v "$PROJECT_ROOT:/work:Z" \
    -w /work \
    -e CARGO_TARGET_DIR=/work/target-linux-x86_64 \
    -e ANKA_BIN_TARGET="$BIN_TARGET" \
    -e ANKA_OUTPUT_NAME="$OUTPUT_NAME" \
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

echo "Installing Linux build/package dependencies..."
apt-get update
apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    binutils \
    file
rm -rf /var/lib/apt/lists/*
echo

echo "============================================================"
echo "1/3  Linux portability test suite (release, single-threaded)"
echo "============================================================"
cargo test --release -- --test-threads=1
echo

echo "============================================================"
echo "2/3  Release build"
echo "============================================================"

# Ask rustc/Cargo not to retain symbol information in the final release
# artifact. We still run GNU strip below as a packaging sanity step.
CARGO_PROFILE_RELEASE_STRIP=symbols \
    cargo build --release --bin "$ANKA_BIN_TARGET"

BUILT_BINARY="/work/target-linux-x86_64/release/$ANKA_BIN_TARGET"
OUTPUT_BINARY="/work/dist/$ANKA_OUTPUT_NAME"

if [ ! -f "$BUILT_BINARY" ]; then
    echo "error: expected binary was not produced:" >&2
    echo "  $BUILT_BINARY" >&2
    exit 1
fi

echo
echo "Built artifact before packaging:"
ls -lh "$BUILT_BINARY"
file "$BUILT_BINARY"

cp "$BUILT_BINARY" "$OUTPUT_BINARY"
chmod +x "$OUTPUT_BINARY"

# The old script copied an unstripped ELF.  Strip inside the Linux/amd64
# container so the host does not need an ELF-aware strip tool.
strip --strip-unneeded "$OUTPUT_BINARY"

echo
echo "============================================================"
echo "3/3  Packaged Linux artifact"
echo "============================================================"
ls -lh "$OUTPUT_BINARY"
file "$OUTPUT_BINARY"

echo
echo "Dynamic dependencies:"
ldd "$OUTPUT_BINARY" || true

echo
printf "Packaged size (bytes): "
stat -c '%s' "$OUTPUT_BINARY"

# Fail loudly if packaging somehow left the ELF unstripped.
if file "$OUTPUT_BINARY" | grep -q 'not stripped'; then
    echo "error: packaged ELF is still reported as not stripped" >&2
    exit 1
fi

echo
echo "Linux x86_64 test + build + strip completed successfully."
CONTAINER_SCRIPT

echo
echo "============================================================"
echo "DONE"
echo "============================================================"
echo "Linux artifact:"
echo "  $OUTPUT_BINARY"
ls -lh "$OUTPUT_BINARY"
echo
echo "If the test stage reported 440/440, the portability seal is:"
echo "  440/440 macOS = 440/440 Linux x86_64"
