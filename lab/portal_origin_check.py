#!/usr/bin/env python3
"""
mcp-tunnels :: portal_origin_check.py

Reference implementation of origin-side rejection of non-portal traffic (T5).

Network policy only covers managed devices on managed paths. An MCP server must
independently refuse requests that did not arrive via the sanctioned portal.
This is the control that survives an end user switching clients, disabling a
local hook, or working off the corporate network — and it is the last point at
which a request can be denied before a tool runs.

Drop arrived_via_portal() into your request handler and call it BEFORE any tool
dispatch. The portal adds X-Portal-Signature and X-Portal-Timestamp; the origin
verifies them against a shared key it holds and the portal holds.

In production, prefer mTLS or a signed JWT with a short lifetime over a shared
HMAC key. This version is deliberately minimal so it is easy to read and easy
to bolt onto the lab server.
"""

import hashlib
import hmac
import os
import time

PORTAL_SHARED_SECRET = os.environ["MCP_PORTAL_HMAC_KEY"]
REPLAY_WINDOW_SECONDS = 60


def arrived_via_portal(headers) -> bool:
    sig = headers.get("X-Portal-Signature")
    ts = headers.get("X-Portal-Timestamp")
    if not sig or not ts:
        return False
    try:
        age = abs(time.time() - int(ts))
    except (TypeError, ValueError):
        return False
    if age > REPLAY_WINDOW_SECONDS:
        return False
    expected = hmac.new(
        PORTAL_SHARED_SECRET.encode(), ts.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig, expected)


def sign_for_portal() -> dict:
    """What the portal side emits. Included so you can test both halves."""
    ts = str(int(time.time()))
    sig = hmac.new(
        PORTAL_SHARED_SECRET.encode(), ts.encode(), hashlib.sha256
    ).hexdigest()
    return {"X-Portal-Timestamp": ts, "X-Portal-Signature": sig}


# --- Wiring into mcp_lab_server.py -----------------------------------------
#
# In Handler.do_POST(), immediately after parsing headers and before any
# method dispatch:
#
#     if not arrived_via_portal(self.headers):
#         audit(dict(base, outcome="reject", reason="portal_bypass"))
#         self._rpc_error(req_id, -32001,
#                         "Direct access denied; use the MCP portal")
#         return
#
# Then retry through the tunnel. The tunnel still exists and still forwards
# traffic — but the server refuses to act. That is the point.
