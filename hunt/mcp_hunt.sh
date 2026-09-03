#!/usr/bin/env bash
# mcp_hunt.sh - Host-side triage for MCP servers, stdio bridges and reverse tunnels.
# Read-only. Safe to run on production Linux hosts. Requires: ss, ps. Optional: lsof.
#
#   sudo ./mcp_hunt.sh            # human readable
#   sudo ./mcp_hunt.sh --json     # one JSON object per finding, for shipping to SIEM
#
# The high-value correlation is at the bottom: a process holding a loopback
# LISTEN socket at the same time a known tunnel agent holds an outbound
# ESTABLISHED session. Neither alone is remarkable. Together they mean a local
# service is internet-reachable with no inbound firewall change.

set -uo pipefail
JSON=0; [ "${1:-}" = "--json" ] && JSON=1

TUNNEL_RE='cloudflared|ngrok|localtunnel|^lt$|tailscaled|frpc|bore|pagekite|devtunnel|winsw|localhost\.run|serveo'
BRIDGE_RE='mcp-remote|supergateway|mcp-proxy|mcpo|stdio-to-sse|mcp-superassistant'
SERVER_RE='mcp|fastmcp|modelcontextprotocol'

emit() { # emit <category> <detail>
  if [ "$JSON" = 1 ]; then
    printf '{"host":"%s","ts":"%s","category":"%s","detail":%s}\n' \
      "$(hostname)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" \
      "$(printf '%s' "$2" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')"
  else
    printf '[%s] %s\n' "$1" "$2"
  fi
}

hdr() { [ "$JSON" = 1 ] || { echo; echo "=== $1 ==="; }; }

# ---------------------------------------------------------------------------
hdr "1. Loopback listeners (candidate MCP servers invisible to network scans)"
ss -tlnpH 2>/dev/null | awk '$4 ~ /^(127\.|\[::1\])/ {print}' | while read -r line; do
  emit "loopback_listener" "$line"
done

hdr "2. All listeners bound to a routable address (directly exposed)"
ss -tlnpH 2>/dev/null | awk '$4 !~ /^(127\.|\[::1\])/ {print}' | while read -r line; do
  emit "routable_listener" "$line"
done

# ---------------------------------------------------------------------------
hdr "3. Reverse tunnel agents running"
ps -eo pid,ppid,user,etimes,args --no-headers 2>/dev/null \
  | grep -Ei "$TUNNEL_RE" | grep -v grep | while read -r line; do
  emit "tunnel_process" "$line"
done

hdr "4. stdio<->HTTP MCP bridges running (mcp-remote class)"
ps -eo pid,ppid,user,etimes,args --no-headers 2>/dev/null \
  | grep -Ei "$BRIDGE_RE" | grep -v grep | while read -r line; do
  emit "mcp_bridge_process" "$line"
done

hdr "5. Probable MCP server processes"
ps -eo pid,ppid,user,etimes,args --no-headers 2>/dev/null \
  | grep -Ei "$SERVER_RE" | grep -Evi "$TUNNEL_RE|mcp_hunt|grep" | while read -r line; do
  emit "mcp_server_process" "$line"
done

# ---------------------------------------------------------------------------
hdr "6. MCP client configuration files on disk"
for p in \
  "$HOME/.claude.json" "$HOME/.claude/settings.json" "$HOME/.claude/mcp.json" \
  "$HOME/.cursor/mcp.json" "$HOME/.codeium/windsurf/mcp_config.json" \
  "$HOME/.config/Code/User/mcp.json" "$HOME/.config/mcp/config.json" \
  "$HOME/.gemini/settings.json" "$HOME/.vscode/mcp.json" \
  "/etc/claude-code/managed-settings.json" ; do
  [ -f "$p" ] && emit "mcp_config_file" "$p mtime=$(stat -c %y "$p" 2>/dev/null)"
done
# project-scoped configs are the ones that arrive with a git clone
find / -xdev -maxdepth 6 \( -name '.mcp.json' -o -name 'mcp.json' -o -name 'mcp_config.json' \) \
     -not -path '*/node_modules/*' 2>/dev/null | while read -r p; do
  emit "mcp_config_file" "$p mtime=$(stat -c %y "$p" 2>/dev/null)"
done

hdr "7. Outbound sessions to known tunnel provider infrastructure"
ss -tanpH state established 2>/dev/null \
  | grep -Ei 'cloudflared|ngrok|tailscaled|frpc|devtunnel' | while read -r line; do
  emit "tunnel_established" "$line"
done

# ---------------------------------------------------------------------------
hdr "8. CORRELATION: loopback listener + live tunnel agent"
LOOPBACK_COUNT=$(ss -tlnH 2>/dev/null | awk '$4 ~ /^(127\.|\[::1\])/' | wc -l)
TUNNEL_PIDS=$(pgrep -f "$TUNNEL_RE" 2>/dev/null | tr '\n' ' ')
if [ "$LOOPBACK_COUNT" -gt 0 ] && [ -n "${TUNNEL_PIDS// /}" ]; then
  emit "CORRELATION_HIT" "loopback_listeners=$LOOPBACK_COUNT tunnel_pids=$TUNNEL_PIDS \
- a locally bound service may be internet-reachable with no inbound rule change"
else
  emit "correlation_clear" "loopback_listeners=$LOOPBACK_COUNT tunnel_pids=none"
fi
