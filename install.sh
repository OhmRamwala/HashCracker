#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

GREEN='\033[32m'
CYAN='\033[36m'
RED='\033[31m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info() { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[✔]${RESET} $1"; }
fail() { echo -e "${RED}[✖]${RESET} $1"; exit 1; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install_deps() {
    if command -v apt-get &>/dev/null; then
        info "Detected apt (Kali/Debian/Ubuntu)"
        sudo apt-get update -qq
        sudo apt-get install -y -qq build-essential cmake libssl-dev libboost-program-options-dev
    elif command -v dnf &>/dev/null; then
        info "Detected dnf (Fedora/RHEL)"
        sudo dnf install -y gcc-c++ make cmake openssl-devel boost-program-options
    elif command -v pacman &>/dev/null; then
        info "Detected pacman (Arch)"
        sudo pacman -S --needed --noconfirm gcc make cmake openssl boost
    else
        fail "Unsupported Linux package manager. Install manually: compiler, make, cmake, OpenSSL dev package, and Boost program_options dev package"
    fi
}

build_project() {
    cd "${PROJECT_DIR}"
    info "Configuring release build..."
    cmake --preset release

    info "Building..."
    cmake --build build/release
}

install_binary() {
    info "Installing hashcracker to ~/.local/bin..."
    mkdir -p ~/.local/bin
    ln -sf "${PROJECT_DIR}/build/release/hashcracker" ~/.local/bin/hashcracker
}

info "Installing dependencies..."
install_deps

info "Building hashcracker..."
build_project

install_binary

echo ""
success "hashcracker built successfully!"
echo ""
echo -e "${BOLD}Usage:${RESET}"
echo "  hashcracker --hash <hash> --wordlist wordlists/10k-most-common.txt"
echo "  hashcracker --hash-file tests/data/batch_hashes_sha256.txt --type sha256 --wordlist tests/data/small_wordlist.txt"
echo "  hashcracker --hash <hash> --bruteforce --charset lower,digits"
echo "  hashcracker --hash <hash> --wordlist wordlists/10k-most-common.txt --rules"
echo ""
echo -e "  ${DIM}(Binary symlinked to ~/.local/bin/hashcracker)${RESET}"
echo ""
