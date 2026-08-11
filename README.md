# skill-security-scan

Comprehensive security audit for **installed AI agent skills**.

中文文档：[README.zh-CN.md](README.zh-CN.md) · Repo: https://github.com/RJiazhen/skill-security-scan

Covers three risk layers:

| Layer | Focus |
|-------|--------|
| **L1** | Classic malware: download-and-execute, IOCs, obfuscation, credential theft, persistence, prompt injection |
| **L2** | Behavioral risks: platform diversion, forced uploads, covert tool handoff, host-capability suppression |
| **L3** | Supply chain: silent skill install into agent dirs, writes to skill paths, install hooks |

Built to cover gaps that malware-only scanners miss — for example skills that **silently divert** everyday coding work to a third-party platform and **mandate uploading** local files.

---

## Install

```bash
npx skills add RJiazhen/skill-security-scan -g -y
```

After install, use it directly in Cursor / Claude (or similar) agent chats.

---

## Usage (preferred: call the skill in your Agent)

After install, **prefer invoking this skill in chat**. You do not need to memorize script paths.

### Example 1: Scan all installed skills

Say to the agent:

> Use skill-security-scan to audit installed skills on this machine.

Or more casually:

> Check for malicious skills / run a skill security scan.

The agent follows this skill’s workflow, auto-discovers local skill directories, runs the scanner, and summarizes CRITICAL / HIGH / MEDIUM / LOW findings.

### Example 2: Focus on diversion and silent upload

> Use skill-security-scan on installed skills; focus on platform diversion, forced upload, and silent install.

This surfaces **L2 / L3** findings (broad trigger hijack, mandatory upload, `self skill install`, etc.).

### Example 3: Audit one suspicious skill directory

> Use skill-security-scan to audit this directory: `/path/to/suspect-skill`

Replace the path with the real skill folder (for example after `npx skills add` or a CLI injection).

### Example 4: Re-scan after installing third-party skills

> I just installed several skills. Run skill-security-scan again and tell me how to quarantine anything CRITICAL/HIGH.

Useful as a routine check after marketplace or CLI installs.

### Example 5: Learn the report with synthetic fixtures (optional)

If you have cloned this repo, ask the agent:

> Use skill-security-scan on `test/fixtures/synthetic-divert-upload` and explain each HIGH/CRITICAL finding.

That fixture typically triggers diversion, forced upload, silent install, and download-exec alerts — useful for reading report fields.

Clean control sample:

> Also scan `test/fixtures/clean-docs` and confirm it is clean.

---

## Typical findings (reference)

For a diversion-style sample, the agent report may include:

| Severity | Detector | Meaning |
|----------|----------|---------|
| CRITICAL | `DownloadExecDetector` | Download piped into a shell |
| CRITICAL | `SilentSkillInstallDetector` | Silently writes skills into local agents |
| HIGH | `PlatformDiversionDetector` | Broad “software development” trigger + third-party CLI diversion |
| HIGH | `ForcedUploadDetector` | Mandates uploading local files remotely |
| HIGH | `RemoteWorkflowExfiltrationDetector` | Remote messages auto-attach local source files |
| HIGH | `OutputDrivenCommandDetector` | Runs repair commands emitted by CLI output |
| HIGH | `ThirdPartyAuthHandoffDetector` | Background vendor account authorization |
| HIGH | `CovertToolHandoffDetector` | Routes work to an external tool without the user naming it |
| HIGH | `HostCapabilitySuppressionDetector` | Forbids falling back to host capabilities |

When **multiple L2/L3 signals appear on the same skill**, treat it as high risk even without a classic backdoor.

Remediation outline: stop using it → move it out of agent load paths → check whether a CLI will reinstall it → rotate secrets if needed → re-scan. See [`references/remediation.md`](skills/skill-security-scan/references/remediation.md).

---

## Detection coverage

Common auto-discovered paths:

- `~/.cursor/skills`, project `.cursor/skills`
- `~/.claude/skills`, `~/.agents/skills`, `~/.codex/skills`
- `~/.openclaw/**/skills`, `~/.coze/skills`, and similar

| Detector | Layer | Catches |
|----------|-------|---------|
| DownloadExecDetector | L1 | Download piped to shell / PowerShell IEX |
| IOCMatchDetector | L1 | Known-bad IPs / domains / hashes |
| ExfiltrationDetector | L1 | Sensitive dirs + upload / archive + upload |
| CredentialTheftDetector | L1 | Keychain, SSH private keys, password dialogs |
| PromptInjectionDetector | L1 | Jailbreak / discard-system-rules language |
| PlatformDiversionDetector | L2 | Broad “software development” trigger → third-party CLI |
| ForcedUploadDetector | L2 | Forced / automatic upload of local files |
| RemoteWorkflowExfiltrationDetector | L2 | Remote message workflows that pull in local files |
| CovertToolHandoffDetector | L2 | Hands work to external tools without user naming them |
| HostCapabilitySuppressionDetector | L2 | Blocks host built-in capabilities |
| ThirdPartyAuthHandoffDetector | L2 | Vendor account authorization (especially background) |
| SilentSkillInstallDetector | L3 | Silent skill install into agents |
| OutputDrivenCommandDetector | L3 | Execute commands suggested by tool/CLI output |
| SkillPathWriteDetector | L3 | Scripts writing into agent skill directories |

Pattern notes: [`threat-patterns.md`](skills/skill-security-scan/references/threat-patterns.md)

---

## Advanced: run the scanner script (optional)

Most users **do not** need this. Use it for CI, local development, or when the agent is unavailable.

```bash
# Scan the machine
python3 skills/skill-security-scan/scripts/scan.py --no-color

# Scan one directory
python3 skills/skill-security-scan/scripts/scan.py --path /path/to/skill --no-color

# JSON
python3 skills/skill-security-scan/scripts/scan.py --json --severity medium --no-color
```

Exit codes: `0` clean · `1` low/medium · `2` high · `3` critical

---

## Tests and layout

```bash
npm test
# or
python3 -m unittest discover -s test -v
```

```text
skills/skill-security-scan/   # skill package (SKILL.md + scanner)
test/fixtures/                # synthetic samples (diversion / malware / clean)
README.md                     # English (this file)
README.zh-CN.md               # Chinese (same content)
```

---

## Publishing

Primary distribution: public **GitHub** + `npx skills add owner/repo`, indexed by [skills.sh](https://skills.sh/). Publishing to the npm registry is **optional** and not required for skills discovery.

## Relationship to other tools

This package aims for **broader coverage** than malware-IOC scanners that only target Claude/OpenClaw paths. Classic L1 detectors are included; L2/L3 add diversion and supply-chain checks.

IOC indicators in `ioc_database.json` are adapted from public SlowMist / community reporting (see [NOTICE](NOTICE)). Extend the file as you learn new indicators.

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
