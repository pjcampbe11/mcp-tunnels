# hunt/

Point-in-time host triage. **Read-only** — no process termination, no config
changes, no network egress. Safe to run on production hosts subject to your
normal change process for endpoint-touching tools.

| File | Platform |
|---|---|
| `mcp_hunt.sh` | Linux. Requires `ss` and `ps`. |
| `Find-McpTunnel.ps1` | Windows. PowerShell 5.1 or 7. Most checks need no admin. |

```bash
sudo ./mcp_hunt.sh                 # human readable
sudo ./mcp_hunt.sh --json          # one JSON object per finding, for SIEM
```

```powershell
.\Find-McpTunnel.ps1
.\Find-McpTunnel.ps1 -AsJson | Out-File triage.json
```

## What they check

1. Loopback listeners — candidate MCP servers invisible to any network scan
2. Listeners on routable addresses — directly exposed servers
3. Reverse tunnel agents (T2), including `ssh -R`
4. stdio-to-HTTP MCP bridges (T1)
5. Probable MCP server processes
6. MCP client configuration files on disk, with hashes
7. Established sessions to tunnel provider infrastructure
8. **The correlation** (below)

## The finding that matters

> **A process holds a loopback LISTEN socket, and within the same window a known
> reverse tunnel agent holds an outbound ESTABLISHED session, on the same host.**

Neither condition alone is remarkable — developers run local servers constantly,
and tunnel agents have legitimate uses. Together they mean a locally bound
service is very likely reachable from the public internet, and no inbound
firewall rule changed to make that true.

Add a third condition — the loopback listener's command line matches an MCP
server pattern — and precision goes up sharply.

Both scripts emit this as `CORRELATION_HIT`. For continuous detection rather
than point-in-time triage, implement it in your SIEM using
[`detections/kql/tunnel_loopback_correlation.kql`](../detections/kql/tunnel_loopback_correlation.kql)
as the pattern.

## Tuning

Both scripts carry a hardcoded list of tunnel agent names and MCP bridge
patterns. Extend them for your estate. Self-hosted agents (`frp`, plain `ssh -R`)
have no provider domain, so process matching is the only thing that reaches them.
