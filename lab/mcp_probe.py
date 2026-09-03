#!/usr/bin/env python3
"""
mcp_probe.py - Minimal MCP client / wire generator for detection lab work.

Stdlib only. Works against localhost or against a tunnel URL.

Emits spec-conformant 2026-07-28 Streamable HTTP requests so that whatever
you are testing (proxy, SWG, Zeek, WAF, SIEM rule) sees realistic traffic:
    MCP-Protocol-Version, Mcp-Method, Mcp-Name

Usage:
    python3 mcp_probe.py http://127.0.0.1:8848/mcp discover
    python3 mcp_probe.py http://127.0.0.1:8848/mcp list
    python3 mcp_probe.py https://x.trycloudflare.com/mcp call get_balance account_id=ACCT-1001
    python3 mcp_probe.py URL call add_beneficiary account_id=ACCT-1001 beneficiary_name=TEST account_number=123
    python3 mcp_probe.py URL legacy      # no routing headers: tests header-based detection
"""

import json
import ssl
import sys
import urllib.error
import urllib.request

PROTOCOL_VERSION = "2026-07-28"


def post(url, method, name, params, omit_headers=False, token=None, insecure=False):
    body = {"jsonrpc": "2.0", "id": 1, "method": method,
            "params": params,
            "_meta": {"io.modelcontextprotocol/clientInfo":
                      {"name": "mcp-probe", "version": "0.1"}}}
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if not omit_headers:
        headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
        headers["Mcp-Method"] = method
        if name:
            headers["Mcp-Name"] = name
    if token:
        headers["Authorization"] = "Bearer " + token

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            print(f"HTTP {resp.status}")
            print(json.dumps(json.loads(resp.read()), indent=2))
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}")
        print(e.read().decode(errors="replace"))
    except Exception as e:  # noqa: BLE001
        print(f"ERROR {type(e).__name__}: {e}")
        sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    url, verb = sys.argv[1], sys.argv[2]
    rest = sys.argv[3:]

    if verb == "discover":
        post(url, "server/discover", None, {})
    elif verb == "list":
        post(url, "tools/list", None, {})
    elif verb == "legacy":
        post(url, "tools/list", None, {}, omit_headers=True)
    elif verb == "call":
        if not rest:
            print("need a tool name")
            sys.exit(2)
        tool = rest[0]
        args = {}
        for kv in rest[1:]:
            if "=" in kv:
                k, v = kv.split("=", 1)
                args[k] = v
        post(url, "tools/call", tool, {"name": tool, "arguments": args})
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
