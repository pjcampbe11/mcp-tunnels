# lab/

Stdlib-only tooling for reproducing MCP tunnel exposure end to end. No `pip
install`, no external dependencies — these run on incident-response hosts and
locked-down build agents where installing packages is not an option.

Full step-by-step walkthrough: **guide §9**.

| File | Purpose |
|---|---|
| `mcp_lab_server.py` | Minimal MCP server speaking Streamable HTTP (2026-07-28 stateless core). Binds loopback by default. Doubles as a **reference implementation of the audit record** the NSA CSI asks for. |
| `mcp_probe.py` | Minimal MCP client. Generates conformant and deliberately non-conformant wire traffic for testing proxies, SWGs, Zeek and SIEM rules. |
| `mcp_pin.sh` | Trust-on-first-use pinning of tool descriptions. Detects rug-pull metadata changes (OWASP MCP03). |
| `portal_origin_check.py` | Reference origin-side rejection of non-portal traffic (T5). |

## mcp_lab_server.py

Speaks enough of MCP to be a realistic detection target:

- single `/mcp` endpoint, POST
- requires `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers
- **rejects requests where headers and body disagree** — a real tamper signal
  worth alerting on, and a spec requirement under 2026-07-28
- `server/discover`, `tools/list`, `tools/call`
- writes a structured audit record for every request

The tool surface is deliberately modelled on a payments workflow: two reads and
one write, with the write tagged `write-critical`. All data is synthetic and the
write tool performs no write.

```bash
python3 mcp_lab_server.py                          # 127.0.0.1:8848
python3 mcp_lab_server.py --host 0.0.0.0           # for contrast testing
python3 mcp_lab_server.py --audit /var/log/mcp-audit.jsonl
```

### The audit record

This is the shape to require of every internal MCP server. Arguments are
**hashed, not logged** — they routinely carry account numbers and PII — while
argument *key names* stay in clear so an analyst can see the shape of the call.

```json
{
  "arg_keys": ["account_id","account_number","beneficiary_name"],
  "args_digest": "sha256:7651c4569a3e038e36c31edb56d8c5ab",
  "event": "mcp.request",
  "hdr_mcp_method": "tools/call",
  "hdr_mcp_name": "add_beneficiary",
  "hdr_protocol_version": "2026-07-28",
  "outcome": "ok",
  "peer_ip": "127.0.0.1",
  "request_uuid": "327805e5-208d-4a72-92a1-5249a7471aa9",
  "risk_tier": "write-critical",
  "rpc_method": "tools/call",
  "tool": "add_beneficiary",
  "ts": "2026-09-02T14:22:31.004+00:00"
}
```

Note `cf_ray` and `x_forwarded_for` in the schema. **On a server that is supposed
to be internal-only, the presence of a CDN trace header is a high-confidence
indicator that the request arrived through a tunnel.** That is a one-line
detection you can add to any internal MCP server today.

## mcp_probe.py

```bash
python3 mcp_probe.py http://127.0.0.1:8848/mcp discover
python3 mcp_probe.py http://127.0.0.1:8848/mcp list
python3 mcp_probe.py URL call get_balance account_id=ACCT-1001
python3 mcp_probe.py URL call add_beneficiary account_id=ACCT-1001 \
        beneficiary_name=TEST account_number=123
python3 mcp_probe.py URL legacy      # omits routing headers — tests header-based detection
```

The `legacy` verb is how you test whether your detection depends on headers that
older clients never send.
