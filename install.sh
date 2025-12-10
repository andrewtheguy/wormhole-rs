#!/bin/bash

# Wormhole-rs installer for Linux and Mac
# Downloads binary from: https://github.com/andrewtheguy/wormhole-rs/releases/tag/20251210172710
#
# Usage: ./install.sh [RELEASE_TAG]
# Or set RELEASE_TAG environment variable

set -e

# Default release tag (can be overridden by argument or environment variable)
DEFAULT_RELEASE_TAG="20251210172710"

# Allow override via command-line argument or environment variable
RELEASE_TAG="${1:-${RELEASE_TAG:-$DEFAULT_RELEASE_TAG}}"

REPO_OWNER="andrewtheguy"
REPO_NAME="wormhole-rs"
BASE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}"

# Color output
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

# Download binary to temporary location and test it
download_and_test_binary() {
    local url="${BASE_URL}/${BINARY_NAME}"
    local temp_dir=$(mktemp -d)
    local temp_binary="${temp_dir}/${BINARY_NAME}"
    local final_path="$HOME/.local/bin/wormhole-rs"
    local version_info
    
    # Set up trap to clean up temp directory on exit
    trap 'rm -rf "$temp_dir"' EXIT
    
    print_info "Downloading ${BINARY_NAME} from ${url}"
    
    # Download the binary to temporary location
    if command -v curl >/dev/null 2>&1; then
        if ! curl -L -o "$temp_binary" "$url"; then
            print_error "Failed to download binary"
            exit 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -O "$temp_binary" "$url"; then
            print_error "Failed to download binary"
            exit 1
        fi
    else
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi
    
    # Make executable
    chmod +x "$temp_binary"
    
    # Test the binary
    print_info "Testing downloaded binary..."
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
    echo "Usage: $0 [RELEASE_TAG]"
    echo ""
    echo "Download and install wormhole-rs binary"
    echo ""
    echo "Arguments:"
    echo "  RELEASE_TAG    GitHub release tag to download (default: ${DEFAULT_RELEASE_TAG})"
    echo ""
    echo "Environment variables:"
    echo "  RELEASE_TAG    Alternative way to specify release tag"
    echo ""
    echo "Examples:"
    echo "  $0                              # Use default release tag"
    echo "  $0 20251210172710               # Use specific release tag"
    echo "  RELEASE_TAG=latest $0           # Use environment variable"
    echo ""
    echo "Supported platforms: Linux (amd64, arm64), macOS (arm64)"
}

# Main installation function
install() {
    print_info "Wormhole-rs installer"
    print_info "Release: ${RELEASE_TAG}"
    print_info "Repository: ${REPO_OWNER}/${REPO_NAME}"
    print_info "Target: ${OS}-${ARCH}"
    
    detect_os
    detect_arch
    get_binary_name
    
    print_info "Platform detected: ${OS}-${ARCH}"
    print_info "Binary name: ${BINARY_NAME}"
    
    download_and_test_binary
    
    print_info "Installation completed successfully!"
    print_info "You can now run 'wormhole-rs' from your terminal."
}

# Check if running with proper privileges
check_privileges() {
    if [ "$EUID" -eq 0 ]; then
        print_warn "Running as root. It's recommended to install as a regular user."
    fi
}

# Main execution
main() {
    # Handle help flags
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        show_usage
        exit 0
    fi
    
    print_info "Starting Wormhole-rs installation..."
    
    check_privileges
    install
}

# Run main function
main "$@"