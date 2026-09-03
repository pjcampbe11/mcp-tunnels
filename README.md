# mcp-tunnels

**How MCP tunnels work, why your firewall never sees them, what telemetry actually exists, and how to prevent them — with a reproducible lab, deployable detections, and host triage tooling.**

Protocol baseline: **MCP 2026-07-28** (stateless core), with 2025-11-25 and 2025-06-18 compatibility notes.

---

## The short version

A Model Context Protocol server bound to `127.0.0.1` becomes reachable from the public internet the moment a reverse tunnel agent runs beside it. No inbound firewall rule changes. No port opens. An external port scan stays clean before and after.

This is not a misconfiguration. It is how reverse tunnels work, and it means a whole category of ingress control is structurally incapable of seeing the exposure:

```
[1] MCP server binds 127.0.0.1:8848         → invisible to any external scan
[2] Tunnel agent starts on the same host
[3] Agent opens an OUTBOUND session to the provider edge  → conntrack: ESTABLISHED
[4] Provider publishes a public hostname in ITS OWN DNS zone
[5] Internet request terminates at the PROVIDER's edge
[6] Provider multiplexes it back down the session YOUR host already opened
    → stateful firewall sees established-session return traffic. Permitted by definition.
[7] Tunnel agent forwards to 127.0.0.1:8848 over loopback
```

A reverse tunnel converts an **ingress** problem, which perimeter controls govern, into an **egress** problem, which most enterprises govern loosely.

The full analysis, including a table of exactly why security groups, NACLs, host firewalls, port scans and VPC Flow Logs each fail, is in [the practitioner's guide](docs/MCP-Tunnels-Practitioners-Guide.pdf) (53 pages, §5).

---

## What's here

| Path | Contents |
|---|---|
| [`docs/`](docs/) | The practitioner's guide (PDF, 53 pp) — threat model, transport primer, tunnel taxonomy, detection, prevention, lab, control matrix, assessment checklist |
| [`lab/`](lab/) | Stdlib-only MCP server and client for reproducing the whole thing end to end |
| [`hunt/`](hunt/) | Point-in-time host triage for Linux and Windows |
| [`detections/`](detections/) | Sigma, KQL, SPL, osquery, auditd, Sysmon, Zeek and gateway policy content |
| [`checklists/`](checklists/) | Per-agent assessment checklist |

---

## The tunnel taxonomy

Five different things get called "an MCP tunnel." They have different mechanics, different telemetry and different fixes. The repo uses these labels consistently.

| Type | Mechanism | Exposure created | Primary control |
|---|---|---|---|
| **T1** | stdio↔HTTP bridge (`mcp-remote`, `supergateway`, `mcp-proxy`) | A stdio-only client reaches a remote server; credentials and arguments leave the host | Package control, egress proxy, client policy |
| **T2** | Reverse ingress tunnel (`cloudflared`, `ngrok`, Tailscale Funnel, dev tunnels, `ssh -R`) | **Inbound reachability from the internet with no inbound firewall rule** | Binary allowlisting, DNS, egress allowlist |
| **T3** | Direct client→remote MCP ("shadow MCP") | Data egress in tool arguments to an unvetted destination; tool-poisoning exposure | TLS-inspecting SWG with MCP classification; MCP portal |
| **T4** | MCP as the transport for a covert channel | C2 or exfiltration hidden inside legitimate-looking tool calls | Behavioural analytics on tool-call sequences; server-side audit |
| **T5** | Governed-path bypass | An *approved* server reached directly, skipping identity, tool catalogue, DLP and audit | Origin-side rejection of non-portal traffic |

---

## Quick start: reproduce the exposure

Requires one throwaway VM you own. Ten minutes.

```bash
git clone https://github.com/<you>/mcp-tunnels.git && cd mcp-tunnels

# 1. Stand up an MCP server on loopback only
python3 lab/mcp_lab_server.py --port 8848 --audit ./mcp-audit.jsonl &
ss -tlnp | grep 8848          # → LISTEN 127.0.0.1:8848

# 2. Confirm it is unreachable from outside (run from another machine)
nmap -Pn -p 8848 <YOUR_PUBLIC_IP>     # → nothing
curl -m 5 http://<YOUR_PUBLIC_IP>:8848/mcp   # → timeout

# 3. Open a reverse tunnel. No account, no firewall change.
cloudflared tunnel --url http://localhost:8848

# 4. From that same outside machine, invoke a write-tier tool
python3 lab/mcp_probe.py https://<assigned>.trycloudflare.com/mcp \
        call add_beneficiary account_id=ACCT-1001 \
        beneficiary_name=EXTERNAL-CALLER account_number=1234509876

# 5. Rescan. Still clean. Nothing at the network layer changed.
nmap -Pn -p 8848 <YOUR_PUBLIC_IP>
```

Screenshot steps 2 and 5 side by side. That pairing is the most persuasive artifact this repo produces.

Then run the triage:

```bash
sudo bash hunt/mcp_hunt.sh                  # Linux
.\hunt\Find-McpTunnel.ps1                   # Windows
```

Both implement the same high-precision correlation: **a process holding a loopback LISTEN socket while a known tunnel agent holds an outbound ESTABLISHED session on the same host.** Neither condition alone is remarkable. Together they mean a locally bound service is very likely internet-reachable and no inbound rule changed to make that true.

Full step-by-step, including telemetry arming, TLS-inspection recovery of the tool name, and control testing, is §9 of the guide.

---

## Two findings worth reading even if you skip the rest

**Blocking QUIC alone does not stop the tunnel.** Block UDP/7844 and `cloudflared` falls back to HTTP/2 over TCP/7844 and keeps working. Any egress rule that only kills QUIC gives you false coverage. Block both transports, for every provider. (Guide §9b.)

**The 2026-07-28 spec made this materially easier to control.** The stateless core requires `Mcp-Method` and `Mcp-Name` headers on every Streamable HTTP request, and `MCP-Protocol-Version` on every POST. The tool name is now on the wire, so "block `add_beneficiary` from any non-portal source" is a network policy rather than an application change. This is what Cloudflare's `experimental.is_mcp` selector keys on. Requires TLS decryption — without it you have an opaque flow. (Guide §3.3, §8.)

---

## Where control actually lives

Every control that works sits somewhere other than the inbound ACL. In descending order of durability:

1. **Execution control on the endpoint.** If the tunnel binary cannot run, there is no tunnel. WDAC/AppLocker, `fapolicyd`. Denying execution from user-writable paths stops the whole class, including tools nobody has heard of yet.
2. **Egress architecture.** Default-deny outbound through a TLS-inspecting forward proxy, with UDP/443 and UDP/7844 blocked so QUIC cannot route around it.
3. **DNS policy.** Blocks *new* tunnels; does not tear down live ones. Trivially evaded by an IP literal. Excellent detection value regardless.
4. **Identity and authorization.** Pre-registered OAuth clients, no DCR, RFC 9207 `iss` validation, audience validation, no token passthrough.
5. **Server-side tool authorization.** Risk-tier every tool. The last point of denial before execution, and the only control an end user cannot bypass by switching clients or disabling a local hook.

---

## Known blind spots

State these explicitly whenever you report coverage. Overclaiming here is worse than a gap.

- **stdio MCP servers are invisible to the network. Entirely.** No socket, no packet, no flow log, no proxy record. Coverage comes only from the client, the host and the filesystem.
- **No TLS inspection means no MCP classification.** Everything header-based depends on decryption.
- **Off-network and BYOD devices sit outside every network control you own.**
- **Encrypted Client Hello removes SNI** where deployed, taking the last no-decrypt signal with it.
- **Third-party MCP servers emit no audit you can read.** Your only record is your own client-side or gateway-side telemetry.
- **Network scanning for rogue MCP servers misses every loopback-bound server behind a tunnel.** Sound advice with a real gap; say so when you cite it.

---

## Standards mapping

Findings in this repo map to:

- **NSA AISC**, *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, CSI U/OO/6030316-26, May 2026
- **OWASP MCP Top 10 (2025)** — chiefly MCP01, MCP02, MCP03, MCP07, MCP08, MCP09, MCP10
- **MITRE ATT&CK** — T1572 Protocol Tunneling, T1567 Exfiltration Over Web Service, T1090 Proxy
- **MCP 2026-07-28 specification**, including the security best practices section

The control matrix in guide §10 maps each control to the types it addresses, the authority that recommends it, and the lab step that validates it.

---

## Scope and posture

Defensive. Everything here runs against infrastructure you own and data you invented. The lab MCP server ships with synthetic accounts and its write tool performs no write.

This repo contains no exploit code, no C2 framework and no evasion tooling. The lab uses a vendor-documented developer workflow — run a local server, tunnel it, connect an assistant — to demonstrate a control gap and then close it.

See [SECURITY.md](SECURITY.md) before running anything against a corporate host.

---

## Contributing

Detection content, provider endpoint corrections and additional tunnel-agent coverage are all welcome. Provider domains and ports change; if you find something stale, open a PR against [`detections/`](detections/) and note the date you verified it.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
