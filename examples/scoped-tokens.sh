#!/bin/bash
# =============================================================================
# AID Scoped Tokens Example
# =============================================================================
#
# Demonstrates requesting tokens with specific scopes for least-privilege access.
#
# =============================================================================

set -e

AUTH_URL="https://auth.23blocks.com/your-tenant"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Scoped Tokens Example"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Request a read-only token for files
echo "Requesting read-only files token..."
FILES_TOKEN=$(aid-token.sh \
  --auth "$AUTH_URL" \
  --scope "files:read" \
  --quiet)
echo "  Got token: ${FILES_TOKEN:0:20}..."
echo ""

# Request a read-write token for content
echo "Requesting read-write content token..."
CONTENT_TOKEN=$(aid-token.sh \
  --auth "$AUTH_URL" \
  --scope "content:read content:write" \
  --quiet)
echo "  Got token: ${CONTENT_TOKEN:0:20}..."
echo ""

# Request all available scopes (default)
echo "Requesting full-scope token..."
FULL_TOKEN=$(aid-token.sh \
  --auth "$AUTH_URL" \
  --quiet)
echo "  Got token: ${FULL_TOKEN:0:20}..."
echo ""

# Use JSON output to inspect token details
echo "Token details (JSON):"
aid-token.sh --auth "$AUTH_URL" --json | jq '{scope, expires_in, agent_address}'
