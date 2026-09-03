#!/usr/bin/env bash
# mcp-tunnels :: Zeek log hunting for reverse tunnels (T2)
# Run against a directory of Zeek logs.

echo "=== SNI matching tunnel providers (ssl.log) ==="
zeek-cut -d ts id.orig_h id.resp_h server_name ja3 ja3s < ssl.log \
  | grep -Ei 'argotunnel|trycloudflare|ngrok|devtunnels\.ms|loca\.lt|ts\.net'

echo
echo "=== Tunnel-shaped connections (conn.log) ==="
echo "    duration > 1h, and more bytes returned to the originator than sent"
echo "    (serving requests, not fetching pages)"
zeek-cut -d ts id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes conn_state < conn.log \
  | awk -F'\t' '$6 > 3600 && $7 > 0 && $8 > 0 && ($8/$7) > 3 { print }'

echo
echo "=== Any connection to port 7844 (cloudflared control plane) ==="
zeek-cut -d ts id.orig_h id.resp_h id.resp_p proto duration < conn.log \
  | awk -F'\t' '$4 == 7844 { print }'
