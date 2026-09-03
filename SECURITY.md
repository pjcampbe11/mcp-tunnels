# Security and rules of engagement

## Before you run anything

Everything in this repository is intended to run against infrastructure you own,
in a non-production account, with data you invented.

**Do not:**

- Point a tunnel agent at a corporate host or expose a real internal service.
- Authenticate a tunnel agent with corporate credentials, even in a lab.
- Run the hunt scripts against production endpoints without the same change
  approval you would need for any endpoint-touching tool.
- Download a tunnel binary onto a managed device where policy prohibits it.

If your organisation restricts tunnel binaries, get the exception in writing
first. An unannounced tunnel from a security engineer's workstation looks
exactly like the thing these detections were written for.

## What this repository does not contain

No exploit code. No command-and-control framework. No evasion tooling. No
technique for defeating a control that is not immediately followed by the
control that defeats it.

The lab uses a vendor-documented developer workflow — run a local MCP server,
expose it with a tunnel, connect an assistant — to demonstrate a control gap and
then close it. The lab MCP server uses synthetic account data and its
write-tier tool performs no write.

## Lab hygiene

- Security group inbound: TCP/22 from your own address only. Nothing else.
- Use a personal or sandbox tunnel account, never a corporate one.
- Tear down per guide §9 Step 11 and terminate the instance. A tunnel left
  running is permanent internet exposure of whatever is behind it.

## Reporting an issue

Open a GitHub issue for detection false positives, stale provider endpoints or
documentation errors.

For anything you believe should not be public, use GitHub's private security
advisory reporting on this repository rather than a public issue.
