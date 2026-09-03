# Gateway policy: MCP classification and portal enforcement

As of 14 August 2026 Cloudflare Gateway classifies TLS-inspected requests as MCP
by inspecting the `MCP-Protocol-Version` header, exposed as a boolean selector
in Gateway HTTP logs and policies. A Traffic Source selector distinguishes
portal-proxied requests from direct connections, which is what makes T5
detectable.

## Observe first

Both the MCP detection and the Traffic Source appear in HTTP logs for decrypted
traffic without any policy in place. Run in observation mode until the sanctioned
path covers what your teams actually need — a portal that cannot reach the
servers people require guarantees bypass.

## Baseline enforcement

```
experimental.is_mcp == true and not traffic.onramp in ("mcp_portal")
Action: Block
```

Any detected MCP traffic that did not arrive through a portal is blocked;
portal traffic is unaffected.

## Limits — state these when you brief coverage

- Requires TLS decryption.
- Does not see local `stdio` servers, off-network devices, Do-Not-Inspect
  categories, or traffic that never traverses the proxy.
- Presence of the header is a strong positive indicator. **Absence proves
  nothing** — legacy clients, custom transports and non-conforming
  implementations may never send it.
- Any dashboard built on this is a **floor** on your MCP traffic, not a total.

## Generalising to other gateways

The technique is product-independent: **classify on the header, not the
hostname.** Hostname and path heuristics (`*mcp*`, `/mcp`, `/sse`) miss servers
at ordinary URLs like `https://tools.example.com/api` and produce false
positives on unrelated services. They remain useful for finding traffic from
older clients and for historical visibility.

Write the equivalent of the following for your own SWG:

| Condition | Value |
|---|---|
| Request header present | `MCP-Protocol-Version` |
| Operation | `Mcp-Method` — separate `tools/call` from `tools/list` |
| Tool name | `Mcp-Name` — policy on a specific tool, e.g. block a write-tier tool from non-portal sources |
| Body inspection | DLP patterns for JSON-RPC methods `initialize`, `tools/call`, `resources/read` |

## Origin-side enforcement is not optional

Network policy only covers managed devices on managed paths. Your own MCP
servers must independently refuse requests that did not arrive via the portal —
an Access policy, a source-IP restriction, or a signed header the portal adds
and the origin verifies. See `lab/portal_origin_check.py` for a reference HMAC
implementation. Without this, T5 is unaddressed for anyone off the corporate
network.
