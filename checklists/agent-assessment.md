# Agent assessment checklist

Work through this per agent or per tool surface. **"Unknown" is a finding, not a
blank.**

Derived from guide §11. Reference frameworks: NSA CSI U/OO/6030316-26 (May 2026),
OWASP MCP Top 10 (2025), MCP 2026-07-28 security best practices.

---

## 0. The trifecta test — do this first

An agent becomes dangerous when three properties hold simultaneously. Any two
are usually survivable.

- [ ] Does this agent **access sensitive or regulated data**?
- [ ] Is it **exposed to content the organisation does not control** — email,
      documents, web pages, tickets, supplier portals, CRM notes?
- [ ] Does it have an **outbound channel** — a write tool, an email action, a
      generic HTTP connector, a web-fetch tool?

**Three yeses requires a documented compensating control and named risk
acceptance.** Everything below is secondary to this.

---

## 1. Inventory and governance

- [ ] Can you enumerate every MCP server reachable from every copilot, agent and
      developer client, on demand? Include stdio servers, project-scoped
      `.mcp.json` in repositories, and CI-only servers.
- [ ] Is there an approval gate before a new MCP server is added to any client,
      and is it enforced **technically** rather than by policy alone?
- [ ] Do you have an AI Bill of Materials listing MCP servers, versions and
      their tool catalogues?
- [ ] Are archived or unmaintained MCP server projects flagged? The MCP project
      maintains a list of archived servers, some of which touch filesystems and
      developer tooling.
- [ ] Is agent definition — topics, tools, knowledge sources — reviewed as code
      before publication?

---

## 2. High-consequence actions

Applies to any tool that moves money, changes payment instructions, modifies
entitlements, or writes to a system of record.

- [ ] List every such tool. Is each **risk-tiered in its definition** and
      enforced at the handler, not just documented?
- [ ] Is dual control / maker-checker enforced **in the system of record**, or
      only as a step in the agent's workflow definition?
- [ ] Are details shown to a human for confirmation **re-read from the system of
      record**, not echoed from the agent's context? If the model was
      manipulated, the summary it renders is manipulated too.
- [ ] Are **idempotency keys** mandatory on every state-changing tool? MCP does
      not enforce idempotency; a retried `tools/call` is a duplicate action.
- [ ] Are per-identity, per-tool **velocity limits** in place on `tools/call`?
      A limit that would never inconvenience a human is a hard stop for a
      runaway agent.
- [ ] Is orchestration **deterministic** for these agents, or does the model
      choose which tool to call? Generative orchestration makes tool selection
      itself an injection target.
- [ ] **Write it out:** the worst single sequence of tool calls a fully
      compromised model could execute before a human sees anything. If that
      sequence completes a consequential action, the control is in the wrong
      place.

---

## 3. Data boundary

- [ ] Are tools and models aligned with data classification zones? No agent
      should hold, in a single context, both a tool that reads regulated data
      and a tool that can reach an uncontrolled external destination.
- [ ] For private data, is a local MCP server instance used in preference to a
      remote one?
- [ ] Are tool **outputs** filtered and logged before being passed downstream?
      Every tool result is untrusted input to the next stage.
- [ ] Are generic HTTP connectors blocked or explicitly justified? On some
      platforms they bypass tenant isolation by design.
- [ ] Are outbound email actions from agents restricted, or recipients
      constrained?

---

## 4. Transport and tunnels

- [ ] Do you know which **MCP protocol versions** your clients speak? This
      determines achievable detection fidelity. Pre-2025-06-18 clients are
      invisible to header-based classification.
- [ ] Is **TLS inspection** enabled on paths carrying agent traffic? Without it,
      MCP classification is unavailable to you.
- [ ] Are **UDP/443 and UDP/7844 blocked outbound** from agent-hosting subnets?
      Blocking QUIC alone downgrades the tunnel to HTTP/2 — it does not stop it.
- [ ] Is execution of tunnel binaries **prevented**, or only detected?
- [ ] Does that policy cover `ssh -R`, `plink.exe`, and self-hosted agents with
      no provider domain?
- [ ] Is there a **governed MCP path** (portal or gateway), and do your own
      servers **reject requests that bypass it**? Network policy alone does not
      cover off-network devices.
- [ ] Have you run the **loopback-listener plus tunnel-process correlation**
      across your developer estate? What did it return?
- [ ] Are DNS-over-HTTPS requests to third-party resolvers blocked?

---

## 5. Identity and authorization

- [ ] Are OAuth clients **pre-registered**? Dynamic Client Registration is
      deprecated as of 2026-07-28 — a DCR event should alert.
- [ ] Is the `iss` parameter validated per RFC 9207 before redeeming an
      authorization code?
- [ ] Is **token audience validated on every request**? Reject any token whose
      `aud` does not match the server identifier.
- [ ] Is **token passthrough** eliminated? The specification forbids it. Use
      token exchange where a downstream service must act on the user's behalf.
- [ ] Is there a **per-client consent registry** for any proxying server?
- [ ] Is each request bound to a specific client identity, approved scope and
      approved operation server-side? Server-level access control alone leaves
      confused deputy wide open.

---

## 6. Logging and response

- [ ] Do your MCP servers log tool name, caller identity, argument digest, risk
      tier and outcome? Does it reach the SIEM?
- [ ] Are tool arguments **hashed rather than written in clear**?
- [ ] Is W3C Trace Context (`traceparent`, `tracestate`, `baggage` in `_meta`)
      propagated so a tool call correlates from host application through gateway
      to server?
- [ ] Do you alert on **header-versus-body method mismatches**?
- [ ] Do you alert on **provider trace headers** (e.g. `Cf-Ray`) arriving at
      internal-only servers?
- [ ] Does the IR playbook cover an agentic incident: identify every tool call
      in a session, revoke the agent's credentials, determine what data left?
- [ ] Are platform injection-shield events actually arriving in the SIEM,
      **verified by test** rather than assumed?

---

## 7. Supply chain

- [ ] Is `mcp-remote` present anywhere, and is every instance at **0.1.16 or
      later**? (CVE-2025-6514, CVSS 9.6 — OS command injection via a
      server-supplied `authorization_endpoint`.)
- [ ] Is MCP Inspector present, and at **0.14.1 or later**? (CVE-2025-49596.)
- [ ] Are tool descriptions **hash-pinned at approval and diffed on reconnect**?
      See `lab/mcp_pin.sh`.
- [ ] Do you scan tool descriptions for **invisible Unicode** (tag characters,
      zero-width spaces) and instruction-injection phrasing?
- [ ] Is `.mcp.json` in repositories treated as executable content — reviewed on
      change, included in pre-merge checks?
- [ ] Is there a defined process for tracking MCP CVEs, as the NSA CSI
      recommends?

---

## Scoring

There is no score. Every unchecked box is a finding with an owner and a date.
The trifecta test in section 0 is the one that decides whether the agent should
exist in its current form at all.
