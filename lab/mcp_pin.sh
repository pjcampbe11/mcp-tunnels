#!/usr/bin/env bash
# mcp-tunnels :: mcp_pin.sh — trust-on-first-use pinning for MCP tool catalogues.
#
# Tool descriptions are functionally instructions: the model treats a tool's
# metadata with the same authority as its system prompt. A server that presents
# benign descriptions at approval time and changes them later — the rug-pull
# pattern — alters agent behaviour with no code change and, in most deployments,
# no re-approval step. OWASP MCP03.
#
# Usage:  ./mcp_pin.sh <server-url> [baseline-file]
#
# Run on a schedule SHORTER than the server's advertised ttlMs, and on every
# reconnect. Alert on any diff, then require human re-approval before use.
set -euo pipefail
URL="${1:?usage: mcp_pin.sh <server-url> [baseline-file]}"
BASE="${2:-tools.baseline}"

curl -sS "$URL" \
  -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
| jq -r '.result.tools[]
         | [.name,
            (({description, inputSchema, title} | tostring) | @base64)]
         | @tsv' \
| while IFS=$'\t' read -r name blob; do
    printf '%s  %s\n' "$name" "$(printf '%s' "$blob" | sha256sum | cut -c1-32)"
  done | sort > tools.current

if [ ! -f "$BASE" ]; then
  cp tools.current "$BASE"
  echo "baseline written to $BASE"
  exit 0
fi

if diff -u "$BASE" tools.current; then
  echo "OK: tool catalogue unchanged"
else
  echo "ALERT: tool description or schema drift detected on $URL" >&2
  exit 1
fi
