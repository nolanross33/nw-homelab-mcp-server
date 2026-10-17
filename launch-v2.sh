#!/bin/bash
# Starts the v2 NetWitness MCP server in Docker (stdio) for Claude Desktop.
# NO credentials are stored in this file. The API password is read from the
# macOS Keychain at launch. Store it once (hidden prompt) with:
#   security add-generic-password -U -a apiuser -s netwitness-v2-api -w
# Incident scan stays unavailable until NW_ADMIN_* values are also supplied.
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:$PATH"

NW_USER="apiuser"
NW_URL="https://192.168.1.38:50103"

NETWITNESS_PASSWORD="$(security find-generic-password -a "$NW_USER" -s netwitness-v2-api -w)"
export NETWITNESS_PASSWORD
export NETWITNESS_USERNAME="$NW_USER"
export NETWITNESS_API_URL="$NW_URL"

exec docker run --rm -i --init --pull never \
  --security-opt no-new-privileges --cpus 1 --memory 2g \
  -e NETWITNESS_API_URL -e NETWITNESS_USERNAME -e NETWITNESS_PASSWORD \
  netwitness-mcp-server:v2
