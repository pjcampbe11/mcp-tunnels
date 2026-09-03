# detections/

Deployable detection content. Every rule is tagged with the tunnel type it
covers (T1–T5) and the relevant MITRE ATT&CK technique.

| Directory | Contents |
|---|---|
| `sigma/` | Four rules: tunnel agent execution, MCP stdio bridge, client config tampering, tunnel provider network connections |
| `kql/` | Defender XDR / Sentinel — including the loopback correlation |
| `spl/` | Splunk — process execution, and flow-based tunnel shape |
| `osquery/` | Scheduled pack for fleet-wide MCP and tunnel discovery |
| `auditd/` | Linux audit rules, plus a `fapolicyd` execution-control policy |
| `sysmon/` | Rule groups to merge into an existing Sysmon config |
| `zeek/` | Cleartext MCP header detection script and log hunt queries |
| `gateway/` | SWG classification and portal-only enforcement policy |

## Before you enable any of this

**Baseline your developer population first.** On an engineering-heavy estate the
tunnel rules will fire on legitimate work — this is the vendor-documented
workflow for remote MCP development. The initial volume is itself a useful
measurement of your exposure. Allowlist known-good build agents and dev VDI
before you route anything to an on-call queue.

## Highest value, lowest effort

Start here if you are picking two things:

1. **DNS on tunnel provider zones** (`sigma/net_connection_tunnel_provider_domains.yml`,
   `kql/tunnel_provider_dns.kql`). Cheap, low volume, high signal.
2. **The loopback correlation** (`kql/tunnel_loopback_correlation.kql`). Highest
   precision available at the host.

## Two things to verify in your own environment

**Provider endpoints go stale.** Domains and ports in these rules were verified
2 September 2026. Re-check against current vendor documentation before you build
egress or DNS policy on them, and open a PR if you find a change.

**Sysmon defaults will hurt you.** Most configurations exclude loopback in Event
ID 3 — exactly where the tunnel-to-MCP-server hop lives. See
`sysmon/sysmon-mcp-additions.xml`.

## What none of this covers

- **stdio MCP servers.** No socket, no packet. Coverage comes only from the
  client, the host and the filesystem.
- **Anything without TLS inspection.** Header-based MCP classification requires
  decryption.
- **Off-network devices.**
- **Semantic abuse (T4).** A malicious server participating in a legitimate
  workflow produces ordinary-looking tool invocations. There is no network-only
  answer. That signal lives in the server-side audit record.
