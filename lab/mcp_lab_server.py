#!/usr/bin/env python3
"""
mcp_lab_server.py - Minimal MCP server for tunnel/detection lab work.

Stdlib only. No pip install. Python 3.9+.

Speaks enough of MCP Streamable HTTP (2026-07-28 stateless core) to be a
realistic detection target:
  - single /mcp endpoint, POST
  - requires MCP-Protocol-Version, Mcp-Method, Mcp-Name headers
  - rejects requests where headers and JSON-RPC body disagree
  - server/discover, tools/list, tools/call
  - writes a structured audit record for every request (the log an MCP
    server SHOULD emit and usually does not)

Binds to loopback by default. That is the point of the lab: a service that
is unreachable from the network becomes internet-reachable the moment a
reverse tunnel agent runs beside it, with no inbound firewall change.

Usage:
    python3 mcp_lab_server.py                      # 127.0.0.1:8848
    python3 mcp_lab_server.py --host 0.0.0.0       # for contrast testing
    python3 mcp_lab_server.py --audit /var/log/mcp-audit.jsonl
"""

import argparse
import hashlib
import json
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = "2026-07-28"
SERVER_NAME = "lab-treasury-tools"
SERVER_VERSION = "0.1.0"

AUDIT_LOCK = threading.Lock()
AUDIT_PATH = None

# ---------------------------------------------------------------------------
# Tool surface. Deliberately modelled on a payments/treasury copilot: two
# reads and one write. The write is the one that matters for control design.
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_balance",
        "title": "Get account balance",
        "description": "Return the current available balance for an internal account.",
        "riskTier": "read",
        "inputSchema": {
            "type": "object",
            "properties": {"account_id": {"type": "string"}},
            "required": ["account_id"],
        },
    },
    {
        "name": "list_beneficiaries",
        "title": "List payment beneficiaries",
        "description": "Return saved payment beneficiaries for an internal account.",
        "riskTier": "read-sensitive",
        "inputSchema": {
            "type": "object",
            "properties": {"account_id": {"type": "string"}},
            "required": ["account_id"],
        },
    },
    {
        "name": "add_beneficiary",
        "title": "Add payment beneficiary",
        "description": "Register a new payment beneficiary against an internal account.",
        "riskTier": "write-critical",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "beneficiary_name": {"type": "string"},
                "routing_number": {"type": "string"},
                "account_number": {"type": "string"},
            },
            "required": ["account_id", "beneficiary_name", "account_number"],
        },
    },
]

TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}

FAKE_BALANCES = {"ACCT-1001": "182450.22", "ACCT-1002": "9310.00"}
FAKE_BENEFICIARIES = {
    "ACCT-1001": [
        {"name": "NORTHWIND SUPPLY LLC", "account_number": "****4417"},
        {"name": "CONTOSO FACILITIES", "account_number": "****8890"},
    ]
}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def audit(record):
    """Emit one structured audit line. This is the artifact incident response
    will ask for and almost never gets."""
    record["ts"] = utcnow()
    line = json.dumps(record, sort_keys=True)
    with AUDIT_LOCK:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
        if AUDIT_PATH:
            with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


def arg_digest(arguments):
    """Hash arguments rather than logging them raw. Arguments routinely carry
    account numbers and PII; the hash still supports replay correlation."""
    blob = json.dumps(arguments or {}, sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()[:32]


def call_tool(name, arguments):
    arguments = arguments or {}
    if name == "get_balance":
        acct = arguments.get("account_id", "")
        bal = FAKE_BALANCES.get(acct)
        if bal is None:
            return {"content": [{"type": "text", "text": f"No such account {acct}"}],
                    "isError": True}
        return {"content": [{"type": "text",
                             "text": f"Available balance for {acct}: USD {bal}"}]}

    if name == "list_beneficiaries":
        acct = arguments.get("account_id", "")
        rows = FAKE_BENEFICIARIES.get(acct, [])
        return {"content": [{"type": "text", "text": json.dumps(rows)}]}

    if name == "add_beneficiary":
        # No approval gate on purpose. In the lab this shows what an
        # unguarded write tool looks like in the audit trail.
        return {"content": [{"type": "text", "text": json.dumps({
            "status": "SIMULATED_ONLY",
            "note": "lab server performs no real write",
            "beneficiary": arguments.get("beneficiary_name"),
        })}]}

    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "lab-mcp/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # audit() is the log

    def _send(self, status, payload, req_id=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("MCP-Protocol-Version", PROTOCOL_VERSION)
        self.end_headers()
        self.wfile.write(body)

    def _rpc_error(self, req_id, code, message, http_status=400):
        self._send(http_status, {"jsonrpc": "2.0", "id": req_id,
                                 "error": {"code": code, "message": message}})

    def do_GET(self):
        if self.path.split("?")[0] == "/healthz":
            self._send(200, {"ok": True, "server": SERVER_NAME})
            return
        self._send(405, {"error": "use POST /mcp"})

    def do_POST(self):
        req_uuid = str(uuid.uuid4())
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        hdr_version = self.headers.get("MCP-Protocol-Version")
        hdr_method = self.headers.get("Mcp-Method")
        hdr_name = self.headers.get("Mcp-Name")
        peer = self.client_address[0]
        xff = self.headers.get("X-Forwarded-For")
        cf_ray = self.headers.get("Cf-Ray")
        ua = self.headers.get("User-Agent")
        authz = self.headers.get("Authorization")

        base = {
            "event": "mcp.request",
            "request_uuid": req_uuid,
            "path": path,
            "peer_ip": peer,
            "x_forwarded_for": xff,
            "cf_ray": cf_ray,              # present => arrived via Cloudflare
            "user_agent": ua,
            "auth_present": bool(authz),
            "hdr_protocol_version": hdr_version,
            "hdr_mcp_method": hdr_method,
            "hdr_mcp_name": hdr_name,
            "body_bytes": len(raw),
        }

        if path != "/mcp":
            audit(dict(base, outcome="reject", reason="bad_path"))
            self._send(404, {"error": "not found"})
            return

        try:
            msg = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            audit(dict(base, outcome="reject", reason="bad_json"))
            self._rpc_error(None, -32700, "Parse error")
            return

        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        tool_name = params.get("name") if method == "tools/call" else None

        base.update({"rpc_id": req_id, "rpc_method": method, "tool": tool_name})

        # Spec 2026-07-28: routing headers are mandatory and must agree with
        # the body. Enforcing this is cheap and it is a real detection signal:
        # a mismatch means something is rewriting one and not the other.
        if not hdr_version:
            audit(dict(base, outcome="reject", reason="missing_protocol_version"))
            self._rpc_error(req_id, -32600, "MCP-Protocol-Version header required")
            return
        if not hdr_method:
            audit(dict(base, outcome="reject", reason="missing_mcp_method_header"))
            self._rpc_error(req_id, -32600, "Mcp-Method header required")
            return
        if hdr_method != method:
            audit(dict(base, outcome="reject", reason="header_body_method_mismatch"))
            self._rpc_error(req_id, -32600, "Mcp-Method disagrees with body method")
            return
        if method == "tools/call" and hdr_name != tool_name:
            audit(dict(base, outcome="reject", reason="header_body_name_mismatch"))
            self._rpc_error(req_id, -32600, "Mcp-Name disagrees with params.name")
            return

        if method == "server/discover":
            audit(dict(base, outcome="ok"))
            self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "capabilities": {"tools": {}},
            }})
            return

        if method == "tools/list":
            audit(dict(base, outcome="ok", tool_count=len(TOOLS)))
            listed = [{k: v for k, v in t.items() if k != "riskTier"} for t in TOOLS]
            self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                "tools": listed, "ttlMs": 300000, "cacheScope": "shared",
            }})
            return

        if method == "tools/call":
            spec = TOOLS_BY_NAME.get(tool_name)
            if spec is None:
                audit(dict(base, outcome="reject", reason="unknown_tool"))
                self._rpc_error(req_id, -32602, f"Unknown tool {tool_name}")
                return
            arguments = params.get("arguments") or {}
            entry = dict(base,
                         risk_tier=spec["riskTier"],
                         args_digest=arg_digest(arguments),
                         arg_keys=sorted(arguments.keys()))
            result = call_tool(tool_name, arguments)
            audit(dict(entry, outcome="ok",
                       result_digest=arg_digest(result)))
            self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": result})
            return

        audit(dict(base, outcome="reject", reason="method_not_found"))
        self._rpc_error(req_id, -32601, f"Method not found: {method}")


def main():
    global AUDIT_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8848)
    ap.add_argument("--audit", default=None, help="append JSONL audit records here")
    args = ap.parse_args()
    AUDIT_PATH = args.audit

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    audit({"event": "mcp.server.start", "bind": f"{args.host}:{args.port}",
           "protocol": PROTOCOL_VERSION, "tools": [t["name"] for t in TOOLS]})
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        audit({"event": "mcp.server.stop"})


if __name__ == "__main__":
    main()
