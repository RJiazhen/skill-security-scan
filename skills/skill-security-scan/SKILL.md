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

If this skill is installed globally (Cursor agent / skills CLI):

```bash
python3 ~/.agents/skills/skill-security-scan/scripts/scan.py --no-color --lang zh
```

Also try `~/.cursor/skills/skill-security-scan/...` if present on older layouts.

Auto-discovers skills under (skips this scanner's own package; identical
copies under multiple agent roots are hashed and scanned once):

- `~/.cursor/skills`, project `.cursor/skills`
- `~/.claude/skills`, `~/.agents/skills`, `~/.codex/skills`
- `~/.trae/skills`, `~/.trae-cn/skills`, project `.trae/skills` (Trae / Trae CN)
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

**Default = full report.** Do **not** pass `--summary-only` unless the user
explicitly asks for a short / summary-only view.

**Match the user's language.** If the user writes in Chinese, run with `--lang zh`.
English chats use `--lang en` or omit it.

**Output the scanner report as-is.** You may run the scan yourself or via a
sub-agent. Paste the markdown report body with no extra narration — no
“完整 N 条命中已写入…”, no “下面按 skill 列出”, no recap before the `#` title.

After the report body, add **only** one line with the written file path
(stderr: `报告已写入: …` / `Report written to: …`):

报告已写入：`/abs/path/skill-security-scan-report.md`

Hard rules:

1. Default CLI (Chinese chat):
   `python3 ~/.agents/skills/skill-security-scan/scripts/scan.py --no-color --lang zh`
   (no `--summary-only`; default `--severity low` so MEDIUM/LOW are included).
   The scanner **writes** `./skill-security-scan-report.md` unless the user says
   not to, or the environment cannot create the file (then stdout only).
   Pass `--no-md` only when the user explicitly does not want a file
   (不要写文件 / 只输出到终端). Use `--md PATH` to choose another location.
2. Use `--summary-only` **only** when the user asks for 摘要 / summary only.
3. Relay the scanner markdown **verbatim**: `#` title (name + scan time),
   `## 总体检查情况`, `## 风险项` with `###` severity and `####` risk-item
   headings, then `## 处置方案`. Do not rename headings or drop fields.
4. Keep **Skill** / **风险类型** / **出处** / **原文摘录** (or the English
   equivalents). Never call the risk type a「检测器」/ detector. Preserve
   clickable `出处` links (`file://…#L18`) and ` ```md ` excerpt fences.
   Do not add `L18 |` prefixes or rewrite excerpts.
5. Keep `处置方案` / `Remediation plan` **verbatim**, including `###` sub-plans
   and ` ```bash ` command fences.

Chinese conversation shape (`--lang zh`, default full report):

````markdown
# Skill 安全扫描报告 · 2026-08-13 21:05

## 总体检查情况
- **检查时间**：2026-08-13 21:05
- **Skill 数**：N
- **文件数**：N
- **风险级别统计**：🔴 严重 n · 🟠 高 n · 🟡 中 n · 🔵 低 n

## 风险项

### 严重

#### <风险项名称>

- **Skill**：`skill-name`
- **风险类型**：<风险项名称>
- **出处**：[ /path/to/SKILL.md:18 ](file:///path/to/SKILL.md#L18)
- **原文摘录**：

```md
<命中原文>
```

## 处置方案

### skill-name（严重 — 建议立即处理）

1. 隔离该 skill

```bash
mkdir -p ~/quarantine/skills
mv /path/to/skill ~/quarantine/skills/
```
````

English conversation shape (default full report):

````markdown
# Skill Security Scan Report · 2026-08-13 21:05

## Scan overview
…

## Findings

### CRITICAL

#### <risk item name>

- **Skill**: `skill-name`
- **Risk type**: <risk item name>
- **Source**: [ /path/to/SKILL.md:18 ](file:///path/to/SKILL.md#L18)
- **Excerpt**:

```md
<hit line>
```

## Remediation plan

### skill-name (CRITICAL — act immediately)

1. Quarantine this skill

```bash
mkdir -p ~/quarantine/skills
mv /path/to/skill ~/quarantine/skills/
```
````

Keep emoji severity markers in chat replies (same mapping as the CLI).
Use `--no-emoji` only for plain text / CI logs.

Example CLI:

```bash
# Default: full Chinese report + ./skill-security-scan-report.md
python3 ~/.agents/skills/skill-security-scan/scripts/scan.py --no-color --lang zh

# No markdown file (only when the user asks)
python3 ~/.agents/skills/skill-security-scan/scripts/scan.py --no-color --lang zh --no-md

# Summary only when the user asks
python3 ~/.agents/skills/skill-security-scan/scripts/scan.py --summary-only --no-color --lang zh

python3 scripts/scan.py --json --lang zh
```

### 4. Remediate (include at end of the report)

Always end the user-facing report with the scanner’s **处置方案** /
**Remediation plan** section (also in JSON `remediation`). Keep numbered
steps and ` ```bash ` fences when skill paths are known. Source quotes use
the `原文摘录` / `Excerpt` block (`source_excerpt` in JSON).

For CRITICAL/HIGH:

1. Quarantine or remove the skill directory (use the printed `mv` commands when present)
2. Rotate credentials if exfiltration or credential theft was flagged
3. Check whether a CLI auto-reinstalled skills into agent directories
4. Re-scan at `--severity high` to confirm cleanup
5. See [references/remediation.md](references/remediation.md)

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
| RemoteWorkflowExfiltrationDetector | L2 | Remote message workflows that pull in local files |
| CovertToolHandoffDetector | L2 | Route work without user naming the tool |
| HostCapabilitySuppressionDetector | L2 | Forbid host agent fallback |
| ThirdPartyAuthHandoffDetector | L2 | Vendor account authorization (esp. background) |
| SilentSkillInstallDetector | L3 | Silent install of skills into agents |
| OutputDrivenCommandDetector | L3 | Run commands suggested by tool/CLI output |
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
