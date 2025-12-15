#!/bin/bash
set -e

# Build script for multi-architecture Linux binaries using Docker
# Builds for both AMD64 and ARM64 architectures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/target/linux"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile.build"
IMAGE_NAME="wormhole-rs-builder"
VERSION="${VERSION:-latest}"

echo "wormhole-rs Multi-Architecture Build Script"
echo "============================================"
echo ""
echo "Build directory: $BUILD_DIR"
echo "Dockerfile: $DOCKERFILE"
echo "Version: $VERSION"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    echo "Please install Docker from https://www.docker.com/"
    exit 1
fi

# Check if buildx is available
if ! docker buildx version &> /dev/null; then
    echo "Error: Docker buildx is not available"
    echo "Please update Docker to a version that supports buildx"
    exit 1
fi

# Create build directory
mkdir -p "$BUILD_DIR"

# Create or use existing buildx builder
BUILDER_NAME="wormhole-rs-builder"
if ! docker buildx inspect "$BUILDER_NAME" &> /dev/null; then
    echo "Creating buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --use --driver docker-container
else
    echo "Using existing buildx builder: $BUILDER_NAME"
    docker buildx use "$BUILDER_NAME"
fi

# Build for both platforms in parallel
echo ""
echo "Building for linux/amd64 and linux/arm64 in parallel..."
echo "--------------------------------------------------------"

docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --file "$DOCKERFILE" \
    --target export \
    --output type=local,dest="$BUILD_DIR" \
    "$SCRIPT_DIR"

echo ""
echo "Organizing binaries..."
echo "----------------------"

# The output structure will have platform-specific subdirectories
# Move and rename binaries
if [ -d "$BUILD_DIR/linux_amd64" ]; then
    if [ -f "$BUILD_DIR/linux_amd64/wormhole-rs" ]; then
        mv "$BUILD_DIR/linux_amd64/wormhole-rs" "$BUILD_DIR/wormhole-rs-linux-amd64"
        echo "✓ AMD64 binary saved to: $BUILD_DIR/wormhole-rs-linux-amd64"
    fi
    rm -rf "$BUILD_DIR/linux_amd64"
fi

if [ -d "$BUILD_DIR/linux_arm64" ]; then
    if [ -f "$BUILD_DIR/linux_arm64/wormhole-rs" ]; then
        mv "$BUILD_DIR/linux_arm64/wormhole-rs" "$BUILD_DIR/wormhole-rs-linux-arm64"
        echo "✓ ARM64 binary saved to: $BUILD_DIR/wormhole-rs-linux-arm64"
    fi
    rm -rf "$BUILD_DIR/linux_arm64"
fi

# Show results
echo ""
echo "Build complete!"
echo "==============="
echo ""
ls -lh "$BUILD_DIR"/wormhole-rs-*
echo ""

# Verify binaries
echo "Verifying binaries..."
echo "---------------------"
if command -v file &> /dev/null; then
    file "$BUILD_DIR"/wormhole-rs-*
else
    echo "Note: 'file' command not available, skipping binary verification"
fi

echo ""
echo "Binaries are ready in: $BUILD_DIR/"
echo ""
echo "To test on Linux:"
echo "  # AMD64:"
echo "  scp $BUILD_DIR/wormhole-rs-linux-amd64 user@host:/tmp/wormhole-rs"
echo "  ssh user@host '/tmp/wormhole-rs --help'"
echo ""
echo "  # ARM64:"
echo "  scp $BUILD_DIR/wormhole-rs-linux-arm64 user@host:/tmp/wormhole-rs"
echo "  ssh user@host '/tmp/wormhole-rs --help'"
