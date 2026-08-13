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

### 3. Review candidates, then report

The script only flags **candidate language**. It does not know whether a
named tool is this host’s built-in capability or another product. **Do not
paste the scanner file as the final report.** Do not add tool-name
allowlists to `scan.py` when a new skill appears — apply
[references/review.md](references/review.md) instead.

**Before presenting anything, Read [references/review.md](references/review.md)
and every cited 出处 file** around the hit line.

Then:

1. **Drop** hits that fail the destination test (host built-in / stay-on-path
   guardrails are not covert handoff).
2. **Rewrite 说明 / Note** from the source: name the real destination and
   the user-visible effect. A generic “交给外部工具” is not enough when the
   excerpt names a CLI (for example: may invoke `vendor code` to start a
   software project on that platform). Do not recopy the excerpt.
3. Recalculate 风险级别统计. Remove empty severity headings and remediation
   subsections for dropped skills.
4. Overwrite the markdown report file with this reviewed text.

**Default = full report.** Do **not** pass `--summary-only` unless the user
explicitly asks for a short / summary-only view.

**Match the user's language.** If the user writes in Chinese, run with `--lang zh`.
English chats use `--lang en` or omit it.

**Do not use captured CLI stdout as the report.** After review, `Read` the
overwritten markdown file and paste **that** body. No extra narration — no
“完整 N 条命中已写入…”, no “下面按 skill 列出”, no “终端输出被截断…”,
no “已过滤误报”, no recap before the `#` title.

After the report body, add **only** one line with the written file path
(stderr: `报告已写入: …` / `Report written to: …`):

报告已写入：`/abs/path/skill-security-scan-report.md`

Hard rules:

1. Default CLI (Chinese chat):
   `python3 ~/.agents/skills/skill-security-scan/scripts/scan.py --no-color --lang zh --quiet`
   (no `--summary-only`; default `--severity low` so MEDIUM/LOW are included).
   `--quiet` keeps the long report out of the terminal capture so it is not
   truncated. The scanner **writes** `./skill-security-scan-report.md` unless
   the user says not to, or the environment cannot create the file (then
   omit `--quiet` / use `--no-md` and print stdout).
   Pass `--no-md` only when the user explicitly does not want a file
   (不要写文件 / 只输出到终端). Use `--md PATH` to choose another location.
2. Use `--summary-only` **only** when the user asks for 摘要 / summary only.
3. Keep the report **shape**: `#` title (name + scan time),
   `## 总体检查情况`, `## 风险项` with `###` severity and `####` risk-item
   headings, then `## 处置方案`. Do not rename headings or drop fields on
   items you keep.
4. Keep **Skill** / **风险类型** / **说明** / **出处** / **原文摘录** (or
   the English equivalents). H4 is the risk-item name; **风险类型** is the
   short type (`L3 · 供应链持久化`), not the same sentence as the H4.
   **说明** is your reviewed impact note (what the hit *does*), not the
   scanner draft and not a recopy of the excerpt. Never call the type a
   「检测器」/ detector. Preserve clickable `出处` links (`file://…#L18`)
   and ` ```md ` excerpt fences. Do not add `L18 |` prefixes or rewrite
   excerpts.
5. Keep `处置方案` / `Remediation plan` **shape**, including `###` sub-plans
   and ` ```bash ` command fences, for skills that still have findings.

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
- **风险类型**：L3 · 供应链持久化
- **说明**：`skill-name` 一旦执行 `example self skill install`，会把自带 skills 写入本机 Agent 目录并可能被自动加载。
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
- **Risk type**: L3 · Supply-chain persistence
- **Note**: `skill-name` would write bundled skills into local agent directories via `example self skill install`, so they can keep loading later.
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
# Default for agents: write the md file, do not dump it to stdout
python3 ~/.agents/skills/skill-security-scan/scripts/scan.py --no-color --lang zh --quiet

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
| CovertToolHandoffDetector | L2 | Candidate: route-without-naming language (review destination) |
| HostCapabilitySuppressionDetector | L2 | Forbid host agent fallback |
| ThirdPartyAuthHandoffDetector | L2 | Vendor account authorization (esp. background) |
| SilentSkillInstallDetector | L3 | Silent install of skills into agents |
| OutputDrivenCommandDetector | L3 | Run commands suggested by tool/CLI output |
| SkillPathWriteDetector | L3 | Scripts writing into agent skill directories |

Full pattern notes: [references/threat-patterns.md](references/threat-patterns.md)

## Manual review checklist

Required for every report. Full rules: [references/review.md](references/review.md).

1. Destination: another product / vendor CLI / peer agent, or this host’s
   own built-in tool? Host stay-on-path guardrails are not handoff.
2. Was the skill installed with clear user consent?
3. Does the trigger scope match the stated purpose (or hijack unrelated coding tasks)?
4. Does it require uploading local files or code to a remote platform?
5. Does it suppress the host agent's normal tools so only the vendor path remains?
6. Does it install or sync itself into agent skill directories without review?
7. Is 说明 concrete (named destination + effect), not “交给外部工具”?

## Trust boundary

This scanner is heuristic. Clean ≠ safe; HIGH ≠ proven malware. The script
over-flags routing phrases; the review step decides. Prefer removal when
confirmed L2 diversion + forced upload + silent install appear together on
an unsolicited skill.
