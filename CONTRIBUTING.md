# Contributing

## What is most useful

1. **Provider endpoint corrections.** Tunnel provider control-plane domains and
   ports change. If a value in `detections/` or guide §5.4 is stale, correct it
   and note the date you verified it.
2. **Additional tunnel agent coverage.** The T2 list is not exhaustive and grows
   monthly. Self-hosted agents with no fixed provider domain (`frp`, plain
   `ssh -R`) are the hardest and the most valuable to cover.
3. **Detection content in formats not yet represented** — Elastic EQL, Chronicle
   YARA-L, Panther, Sumo.
4. **False positive reports.** A rule that fires on legitimate developer work is
   a rule nobody will keep enabled. Tell us what fired and why.

## Standards for detection content

- Every rule needs a `description` that says what it detects **and what it
  misses**. Overclaiming coverage is the failure mode this repo exists to fight.
- Every rule needs a realistic `falsepositives` section. "None" is not an answer
  for anything in this space.
- Tag with the tunnel type (T1–T5) and the relevant MITRE ATT&CK technique.
- Sigma rules should validate against `sigma-cli check`.

## Standards for code

- Lab and hunt scripts stay **stdlib-only** where the language allows it. These
  run on incident-response hosts and locked-down build agents where `pip install`
  is not an option.
- Hunt scripts are **read-only**. No process termination, no config changes, no
  network egress. Triage tooling that modifies state will not be merged.
- Shell must pass `bash -n`; PowerShell must run under 5.1 as well as 7.

## Scope boundary

Pull requests adding exploit code, C2 functionality, or evasion techniques
without a corresponding detection or control will be closed. See
[SECURITY.md](SECURITY.md).
