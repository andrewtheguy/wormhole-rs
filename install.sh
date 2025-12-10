#!/bin/bash

# Wormhole-rs installer for Linux and Mac
# Downloads latest binary from: https://github.com/andrewtheguy/wormhole-rs/releases
#
# Usage: ./install.sh [RELEASE_TAG]
# Or set RELEASE_TAG environment variable

set -e

REPO_OWNER="andrewtheguy"
REPO_NAME="wormhole-rs"
DOWNLOAD_ONLY=false

# Color output (defined early for use in get_latest_release)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fetch the latest release tag matching yyyymmddhhmmss pattern from GitHub
get_latest_release() {
    local api_url="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/tags"
    local tags_json

    if command -v curl >/dev/null 2>&1; then
        tags_json=$(curl -s "$api_url")
    elif command -v wget >/dev/null 2>&1; then
        tags_json=$(wget -qO- "$api_url")
    else
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi

    # Extract tag names matching yyyymmddhhmmss pattern (14 digits) and get the latest one
    # Tags are returned in reverse chronological order, so first match is latest
    local latest_tag
    latest_tag=$(echo "$tags_json" | grep -o '"name": *"[0-9]\{14\}"' | head -1 | grep -o '[0-9]\{14\}')

    if [ -z "$latest_tag" ]; then
        print_error "Could not find any release tags matching yyyymmddhhmmss pattern"
        exit 1
    fi

    echo "$latest_tag"
}

# Fetch full release info (including asset checksums) from GitHub API
get_release_info() {
    local tag="$1"
    local api_url="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${tag}"

    if command -v curl >/dev/null 2>&1; then
        curl -s "$api_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$api_url"
    else
        print_error "Neither curl nor wget is available."
        return 1
    fi
}

# Extract SHA-256 checksum from release JSON for a specific binary
get_expected_checksum() {
    local release_json="$1"
    local binary_name="$2"

    # Extract sha256 hash for matching asset
    # The digest field appears ~35 lines after the name field due to nested uploader object
    echo "$release_json" | grep -A40 "\"name\": \"${binary_name}\"" | \
        grep '"digest"' | head -1 | grep -o 'sha256:[a-f0-9]*' | cut -d: -f2
}

# Compute SHA-256 checksum of a file (cross-platform)
compute_checksum() {
    local file="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        # Linux
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        # macOS
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        print_error "No SHA-256 tool available (need sha256sum or shasum)"
        return 1
    fi
}

# Verify file checksum against expected value
verify_checksum() {
    local file="$1"
    local expected="$2"

    print_info "Verifying checksum..."
    local actual
    actual=$(compute_checksum "$file")

    if [ $? -ne 0 ]; then
        return 1
    fi

    if [ "$expected" = "$actual" ]; then
        print_info "Checksum verified: ${actual:0:16}..."
        return 0
    else
        print_error "Checksum verification FAILED!"
        print_error "Expected: $expected"
        print_error "Actual:   $actual"
        return 1
    fi
}

# Parse command-line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --download-only)
                DOWNLOAD_ONLY=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                # Assume it's a release tag
                RELEASE_TAG="$1"
                shift
                ;;
        esac
    done

    # If RELEASE_TAG not set via args, check environment variable or fetch latest
    if [ -z "$RELEASE_TAG" ]; then
        if [ -n "${RELEASE_TAG_ENV:-}" ]; then
            RELEASE_TAG="$RELEASE_TAG_ENV"
        else
            print_info "Fetching latest release tag from GitHub..."
            RELEASE_TAG=$(get_latest_release)
        fi
    fi
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)
            OS="linux"
            ;;
        Darwin*)
            OS="macos"
            ;;
        *)
            print_error "Unsupported operating system: $(uname -s)"
            print_error "This script only supports Linux and macOS"
            exit 1
            ;;
    esac
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            print_error "Supported architectures: x86_64/amd64, aarch64/arm64"
            exit 1
            ;;
    esac
}

# Map OS and architecture to binary name
get_binary_name() {
    case "${OS}-${ARCH}" in
        "linux-amd64")
            BINARY_NAME="wormhole-rs-linux-amd64"
            ;;
        "linux-arm64")
            BINARY_NAME="wormhole-rs-linux-arm64"
            ;;
        "macos-arm64")
            BINARY_NAME="wormhole-rs-macos-arm64"
            ;;
        *)
            print_error "Unsupported platform: ${OS}-${ARCH}"
            print_error "Supported platforms:"
            print_error "  - linux-amd64 (x86_64 Linux)"
            print_error "  - linux-arm64 (aarch64 Linux)"
            print_error "  - macos-arm64 (Apple Silicon Mac)"
            exit 1
            ;;
    esac
}

# Download binary and verify checksum
download_binary() {
    local base_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}"
    local url="${base_url}/${BINARY_NAME}"
    local output_path="$1"

    print_info "Downloading ${BINARY_NAME} from ${url}"

    # Download the binary
    if command -v curl >/dev/null 2>&1; then
        if ! curl -L -o "$output_path" "$url"; then
            print_error "Failed to download binary"
            exit 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -O "$output_path" "$url"; then
            print_error "Failed to download binary"
            exit 1
        fi
    else
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi

    # Verify checksum
    if [ -z "$EXPECTED_CHECKSUM" ]; then
        print_error "No checksum available. Aborting."
        rm -f "$output_path"
        exit 1
    fi
    if ! verify_checksum "$output_path" "$EXPECTED_CHECKSUM"; then
        print_error "Binary integrity check failed. Aborting."
        rm -f "$output_path"
        exit 1
    fi
}

# Download only - save to current directory
download_only() {
    local output_file="./${BINARY_NAME}"

    download_binary "$output_file"

    # Make executable
    chmod +x "$output_file"

    # Test the binary
    print_info "Testing downloaded binary..."
    local version_info
    if ! version_info=$("$output_file" --version 2>&1); then
        print_error "Binary test failed. The downloaded file may be corrupted or incompatible."
        print_error "Output: $version_info"
        rm -f "$output_file"
        exit 1
    fi

    print_info "Binary test successful: $version_info"
    print_info "Binary saved to: ${output_file}"
}

# Download binary to temporary location, test it, and install
download_and_install() {
    local temp_dir=$(mktemp -d)
    local temp_binary="${temp_dir}/${BINARY_NAME}"
    local final_path="$HOME/.local/bin/wormhole-rs"

    # Set up trap to clean up temp directory on exit
    trap 'rm -rf "$temp_dir"' EXIT

    download_binary "$temp_binary"

    # Make executable
    chmod +x "$temp_binary"

    # Test the binary
    print_info "Testing downloaded binary..."
    local version_info
    if ! version_info=$("$temp_binary" --version 2>&1); then
        print_error "Binary test failed. The downloaded file may be corrupted or incompatible."
        print_error "Output: $version_info"
        exit 1
    fi

    print_info "Binary test successful: $version_info"

    # Create target directory if it doesn't exist
    local target_dir="$HOME/.local/bin"
    mkdir -p "$target_dir"

    # Move the tested binary to final location
    if ! mv "$temp_binary" "$final_path"; then
        print_error "Failed to move binary to final location"
        exit 1
    fi

    # Clean up temp directory (trap will also handle this)
    rm -rf "$temp_dir"

    print_info "Binary installed successfully to ${final_path}"

    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$target_dir:"* ]]; then
        print_warn "${target_dir} is not in your PATH"
        print_warn "Add the following line to your shell profile (.bashrc, .zshrc, etc.):"
        print_warn "export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# Display usage information
show_usage() {
    echo "Usage: $0 [OPTIONS] [RELEASE_TAG]"
    echo ""
    echo "Download and install wormhole-rs binary"
    echo ""
    echo "Options:"
    echo "  --download-only  Download binary to current directory without installing"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Arguments:"
    echo "  RELEASE_TAG      GitHub release tag to download (default: latest)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Install latest release"
    echo "  $0 20251210172710               # Install specific release"
    echo "  $0 --download-only              # Download latest to current directory"
    echo "  $0 --download-only 20251210172710  # Download specific release"
    echo ""
    echo "Supported platforms: Linux (amd64, arm64), macOS (arm64)"
}

# Main installation function
install() {
    if [ "$DOWNLOAD_ONLY" = true ]; then
        print_info "Wormhole-rs downloader"
    else
        print_info "Wormhole-rs installer"
    fi
    print_info "Release: ${RELEASE_TAG}"
    print_info "Repository: ${REPO_OWNER}/${REPO_NAME}"

    detect_os
    detect_arch
    get_binary_name

    print_info "Platform detected: ${OS}-${ARCH}"
    print_info "Binary name: ${BINARY_NAME}"

    # Fetch release info for checksum verification
    print_info "Fetching release information..."
    RELEASE_JSON=$(get_release_info "$RELEASE_TAG")

    if [ -z "$RELEASE_JSON" ] || echo "$RELEASE_JSON" | grep -q '"message": "Not Found"'; then
        print_error "Could not fetch release info from GitHub. Cannot verify binary integrity."
        exit 1
    fi

    EXPECTED_CHECKSUM=$(get_expected_checksum "$RELEASE_JSON" "$BINARY_NAME")
    if [ -z "$EXPECTED_CHECKSUM" ]; then
        print_error "No checksum found for ${BINARY_NAME} in release. Cannot verify binary integrity."
        exit 1
    fi
    print_info "Expected checksum: ${EXPECTED_CHECKSUM:0:16}..."

    if [ "$DOWNLOAD_ONLY" = true ]; then
        download_only
        print_info "Download completed successfully!"
    else
        download_and_install
        print_info "Installation completed successfully!"
        print_info "You can now run 'wormhole-rs' from your terminal."
    fi
}

# Check if running with proper privileges
check_privileges() {
    if [ "$EUID" -eq 0 ]; then
        print_warn "Running as root. It's recommended to install as a regular user."
    fi
}

# Main execution
main() {
    parse_args "$@"

    if [ "$DOWNLOAD_ONLY" = true ]; then
        print_info "Starting Wormhole-rs download..."
    else
        print_info "Starting Wormhole-rs installation..."
        check_privileges
    fi

    install
}

# Run main function
main "$@"