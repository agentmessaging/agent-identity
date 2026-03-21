#!/bin/bash
# =============================================================================
# AID Installer — Agent Identity
# =============================================================================
#
# Installs AID scripts alongside your AMP installation.
#
# Usage:
#   ./install.sh              # Install to ~/.local/bin (default)
#   ./install.sh /usr/local/bin  # Install to custom location
#
# =============================================================================

set -e

INSTALL_DIR="${1:-$HOME/.local/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_SRC="${SCRIPT_DIR}/scripts"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Agent Identity (AID) — Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check prerequisites
echo "Checking prerequisites..."

# Check for AMP
if ! command -v amp-init.sh &>/dev/null && [ ! -f "${INSTALL_DIR}/amp-helper.sh" ]; then
    echo -e "${YELLOW}Warning: AMP (Agent Messaging Protocol) not found.${NC}"
    echo "  AID requires AMP for identity and cryptographic operations."
    echo "  Install AMP first: https://github.com/agentmessaging/claude-plugin"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for jq
if ! command -v jq &>/dev/null; then
    echo -e "${RED}Error: jq is required but not installed.${NC}"
    echo "  Install: brew install jq (macOS) or apt install jq (Linux)"
    exit 1
fi

# Check for curl
if ! command -v curl &>/dev/null; then
    echo -e "${RED}Error: curl is required but not installed.${NC}"
    exit 1
fi

echo -e "  ${GREEN}Prerequisites OK${NC}"
echo ""

# Create install directory
mkdir -p "$INSTALL_DIR"

# Install scripts
echo "Installing AID scripts to ${INSTALL_DIR}..."

SCRIPTS=(
    "aid-token.sh"
    "aid-register.sh"
    "aid-status.sh"
)

for script in "${SCRIPTS[@]}"; do
    if [ -f "${SCRIPTS_SRC}/${script}" ]; then
        cp "${SCRIPTS_SRC}/${script}" "${INSTALL_DIR}/${script}"
        chmod +x "${INSTALL_DIR}/${script}"
        echo -e "  ${GREEN}Installed${NC} ${script}"
    else
        echo -e "  ${RED}Missing${NC} ${script}"
    fi
done

echo ""

# Check PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo -e "${YELLOW}Note: ${INSTALL_DIR} is not in your PATH.${NC}"
    echo ""
    echo "  Add it to your shell profile:"
    echo ""

    SHELL_NAME=$(basename "$SHELL")
    case "$SHELL_NAME" in
        zsh)
            echo "    echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.zshrc"
            echo "    source ~/.zshrc"
            ;;
        bash)
            echo "    echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
            echo "    source ~/.bashrc"
            ;;
        *)
            echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
            ;;
    esac
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}AID installed successfully${NC}"
echo ""
echo "  Quick start:"
echo "    aid-register.sh --auth https://auth.example.com/tenant \\"
echo "      --token <admin_jwt> --role-id 2"
echo "    aid-token.sh --auth https://auth.example.com/tenant"
echo ""
echo "  Check status:"
echo "    aid-status.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
