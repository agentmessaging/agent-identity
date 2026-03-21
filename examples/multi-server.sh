#!/bin/bash
# =============================================================================
# AID Multi-Server Example
# =============================================================================
#
# Demonstrates an agent registered with multiple auth servers,
# getting different tokens for different APIs.
#
# =============================================================================

set -e

AUTH_SERVER_1="https://auth.23blocks.com/company-a"
AUTH_SERVER_2="https://auth.23blocks.com/company-b"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Multi-Server Example"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Show all registrations and cached tokens
echo "Current identity and registrations:"
aid-status.sh
echo ""

# Get token from server 1
echo "Getting token from Company A..."
TOKEN_A=$(aid-token.sh --auth "$AUTH_SERVER_1" --quiet 2>/dev/null) && {
    echo "  Token A: ${TOKEN_A:0:20}..."
} || {
    echo "  Not registered with Company A. Register first:"
    echo "    aid-register.sh --auth $AUTH_SERVER_1 --token <jwt> --role-id <id>"
}
echo ""

# Get token from server 2
echo "Getting token from Company B..."
TOKEN_B=$(aid-token.sh --auth "$AUTH_SERVER_2" --quiet 2>/dev/null) && {
    echo "  Token B: ${TOKEN_B:0:20}..."
} || {
    echo "  Not registered with Company B. Register first:"
    echo "    aid-register.sh --auth $AUTH_SERVER_2 --token <jwt> --role-id <id>"
}
echo ""

echo "Each token is scoped to its respective company tenant."
echo "The same Ed25519 identity works across all servers."
