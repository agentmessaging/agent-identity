#!/bin/bash
# =============================================================================
# AID Basic Usage Example
# =============================================================================
#
# Demonstrates the full AID workflow: register, get token, call API.
#
# Prerequisites:
#   - AMP identity initialized (amp-init --auto)
#   - Access to a 23blocks Auth server (or any AID-compatible auth server)
#   - Admin JWT token for registration
#
# =============================================================================

set -e

# Configuration — replace these with your values
AUTH_URL="https://auth.23blocks.com/your-tenant"
ADMIN_TOKEN="eyJhbGciOiJSUzI1NiJ9..."  # Admin JWT for registration
ROLE_ID="2"                              # Role to assign to this agent
API_URL="https://api.23blocks.com"       # API to call with the token

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AID Basic Usage Example"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1: Check identity
echo "Step 1: Checking AMP identity..."
amp-identity.sh --brief
echo ""

# Step 2: Register with auth server (one-time)
echo "Step 2: Registering with auth server..."
aid-register.sh \
  --auth "$AUTH_URL" \
  --token "$ADMIN_TOKEN" \
  --role-id "$ROLE_ID" \
  --description "Example agent for AID demo"
echo ""

# Step 3: Get a token
echo "Step 3: Requesting JWT token..."
aid-token.sh --auth "$AUTH_URL"
echo ""

# Step 4: Use the token to call an API
echo "Step 4: Calling API with JWT..."
TOKEN=$(aid-token.sh --auth "$AUTH_URL" --quiet)
curl -s -H "Authorization: Bearer $TOKEN" \
  "${API_URL}/health" | jq .
echo ""

echo "Done!"
