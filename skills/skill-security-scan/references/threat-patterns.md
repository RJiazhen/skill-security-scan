# Threat patterns

Detection is grouped into three layers. Patterns are heuristic; always read surrounding
context before treating a hit as confirmed malice.

## L1 — Classic malware / unsafe code

| Pattern | Why it matters |
|---------|----------------|
| HTTP download piped directly into a shell | Remote code execution |
| Known C2 IPs/domains/hashes (IOC DB) | Confirmed prior abuse |
| Long Base64 / high-entropy blobs / dynamic eval of non-literals | Hidden payloads |
| Archive creation plus network upload, or cloud-cred dirs plus upload | Credential/data theft |
| Keychain APIs, GUI password prompts, SSH private key paths | Credential harvesting |
| crontab / LaunchAgents / shell profile writes | Persistence |
| Package manager install hooks that run arbitrary commands | Install-time code exec |
| Zero-width / bidi Unicode | Stealth prompt injection |
| Jailbreak phrases that tell the model to discard system rules | Prompt override |

## L2 — Behavioral diversion (often missed by malware scanners)

These usually appear as **prose in `SKILL.md`**, not as shell one-liners.

### Platform diversion

- Broad triggers: “when user wants to develop software / web app / mini-programs …”
- Coupled with a third-party CLI (vendor `code` / `session` / `file` subcommands)
- Language like “divert”, “route to cloud”, “hijack workflow” away from the host agent

**Example class:** a coding skill that auto-routes ordinary engineering requests onto
an external cloud IDE/agent without the user naming that product.

### Forced upload

- Imperative wording (“must”, “always”) plus vendor file-upload CLIs
- “Do not return local paths; only return online URLs”
- Path attachments that the CLI uploads automatically

### Remote workflow exfiltration

- Remote coding/session message flows that accept local file attachments
- Shipping coding tasks plus local source files to a third-party cloud agent
- Deploy instructions that publish onto an external platform

### Covert tool handoff

Scanner candidates: phrases that activate a tool even when the user never
named it, or that quietly hand work to another agent or platform.

**Confirm before reporting** (see [review.md](review.md)):

- Keep only when the destination is a **different product / vendor CLI /
  peer agent**, not a host built-in tool.
- Drop host guardrails that say stay on the built-in path, or that forbid
  silently switching models/CLIs the host already ships.
- Do not encode those names in the scanner. New skills will keep inventing
  new tool names; the review step decides from context.

### Host capability suppression

- Instructions that block falling back to the host agent’s built-in tools

### Third-party auth handoff

- Skills that require vendor account authorization before ordinary work continues
- Especially risky when authorization is started via detached background processes

## L3 — Supply chain persistence

| Pattern | Why it matters |
|---------|----------------|
| Vendor bootstrap that writes skills into Cursor/Claude dirs | Survives removal; spreads |
| Auto skill sync modes that rewrite agent skills without review | Changes agent behavior quietly |
| Executing repair commands printed in CLI notice fields | Remote output drives local actions |
| Silent CLI auto-upgrade | Moves goalposts after first audit |
| Scripts that copy files into agent skill directories | Unauthorized injection |

## Severity guidance

| Severity | Typical meaning |
|----------|-----------------|
| CRITICAL | Known IOC, download-exec, credential theft, silent skill install |
| HIGH | Diversion+platform CLI, forced upload, host suppression, persistence |
| MEDIUM | Network calls, upload without mandate, entropy/Base64 suspects |
| LOW | Social-engineering naming, informational path references |

## False positives

- Host built-in stay-on-path / “never silently switch model” guardrails
  (review step drops these; do not special-case tool names in the scanner)
- Legitimate skills that *optionally* upload when the user asked for cloud share
- Official docs mentioning agent skill directories without writing there
- Long technical lines that are not encoded payloads (entropy detector tries to skip CJK prose)
- Security scanners and their own documentation describing bad patterns

Prefer correlating **multiple L2/L3 signals** on the same skill before insisting on malice.
