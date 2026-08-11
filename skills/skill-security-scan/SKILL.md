---
name: skill-security-scan
description: >-
  Comprehensively audits installed AI agent skills for malware, data exfiltration,
  prompt injection, platform workflow diversion, forced uploads, covert tool handoff,
  and supply-chain persistence. Use when the user asks to scan skills, check for
  malicious skills, audit skill security, review CLI-injected skills, or
  mentions 恶意 skill、技能安全、导流、静默上传.
---

# Skill Security Scan

Comprehensive security audit for **installed** AI agent skills across Cursor, Claude,
Codex, OpenClaw, and related agent skill directories.

## When to use

- Periodic audit of skills already on the machine
- After installing skills from npm, CLI tools, or marketplaces
- When investigating unexpected workflow diversion, uploads, or third-party platform handoff
- Before trusting a newly added skill

## Layers

| Layer | Focus |
|-------|--------|
| **L1** | Classic malware: download-exec, IOC, obfuscation, credential theft, persistence, network, privilege escalation, prompt injection |
| **L2** | Behavioral: platform diversion, forced upload, covert tool handoff, host-capability suppression |
| **L3** | Supply chain: silent skill install, writes into agent skill directories, install hooks |

## Quick workflow

### 1. Run the scanner

From this skill's install location (adjust if symlinked elsewhere):

```bash
python3 skills/skill-security-scan/scripts/scan.py --no-color
```

If this skill is installed globally under Cursor:

```bash
python3 ~/.cursor/skills/skill-security-scan/scripts/scan.py --no-color
```

Auto-discovers skills under:

- `~/.cursor/skills`, project `.cursor/skills`
- `~/.claude/skills`, `~/.agents/skills`, `~/.codex/skills`
- `~/.openclaw/**/skills`, `~/.coze/skills` (and common Coze app support paths)

### 2. Optional targets

```bash
# Single skill directory
python3 scripts/scan.py --path /path/to/suspect-skill --no-color

# JSON for tooling
python3 scripts/scan.py --json --severity medium

# Custom IOC database
python3 scripts/scan.py --ioc-db /path/to/ioc_database.json
```

**Exit codes:** `0` clean · `1` low/medium · `2` high · `3` critical

### 3. Report to the user

Summarize:

```markdown
## Audit summary
- Skills scanned: N
- Files scanned: N
- CRITICAL / HIGH / MEDIUM / LOW: n / n / n / n

## Critical & high (action required)
- Skill · detector · layer · why it matters · recommended action

## Medium & low
- Brief list; note likely false positives
```

Call out **L2/L3** findings explicitly (diversion, forced upload, silent install) —
these are often missed by malware-only scanners.

### 4. Remediate

For CRITICAL/HIGH:

1. Quarantine or remove the skill directory
2. Rotate credentials if exfiltration or credential theft was flagged
3. Check whether a CLI auto-reinstalled skills into agent directories
4. See [references/remediation.md](references/remediation.md)

## Detector cheat sheet

| Detector | Layer | Catches |
|----------|-------|---------|
| DownloadExecDetector | L1 | Download piped to shell / PowerShell IEX |
| IOCMatchDetector | L1 | Known bad IPs/domains/hashes |
| ExfiltrationDetector | L1 | Sensitive dirs + upload / archive+upload |
| CredentialTheftDetector | L1 | Keychain, SSH keys, password dialogs |
| PromptInjectionDetector | L1 | Jailbreak / discard-system-rules language |
| PlatformDiversionDetector | L2 | Broad “software dev → third-party CLI” hijack |
| ForcedUploadDetector | L2 | Imperative remote uploads / auto path attach |
| CovertToolHandoffDetector | L2 | Route work without user naming the tool |
| HostCapabilitySuppressionDetector | L2 | Forbid host agent fallback |
| SilentSkillInstallDetector | L3 | Silent install of skills into agents |
| SkillPathWriteDetector | L3 | Scripts writing into agent skill directories |

Full pattern notes: [references/threat-patterns.md](references/threat-patterns.md)

## Manual review checklist

When a finding needs human judgment:

1. Was the skill installed with clear user consent?
2. Does the trigger scope match the stated purpose (or hijack unrelated coding tasks)?
3. Does it require uploading local files or code to a remote platform?
4. Does it suppress the host agent's normal tools?
5. Does it install or sync itself into agent skill directories without review?

## Trust boundary

This scanner is heuristic. Clean ≠ safe; HIGH ≠ proven malware. Prefer removal when
L2 diversion + forced upload + silent install appear together on an unsolicited skill.
