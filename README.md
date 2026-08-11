# skill-security-scan

Comprehensive security audit for **installed AI agent skills**.

Covers three layers:

| Layer | What it catches |
|-------|-----------------|
| **L1** | Malware-style patterns: download-exec, IOCs, obfuscation, credential theft, persistence, prompt injection |
| **L2** | Behavioral risks: platform workflow diversion, forced uploads, covert tool handoff, host-capability suppression |
| **L3** | Supply chain: silent skill install into agent dirs, skill-path writes, install hooks |

Designed to catch cases malware-only scanners miss — for example skills that quietly
route coding work to a third-party platform and **mandate** uploading local files.

## Install

```bash
# From a GitHub repo (recommended for skills.sh / npx skills)
npx skills add <owner>/skill-security-scan --skill skill-security-scan

# From a local checkout
npx skills add /path/to/skill-security-scan --skill skill-security-scan
```

## Usage

Ask the agent to run a skill security scan, or invoke the script directly:

```bash
python3 skills/skill-security-scan/scripts/scan.py --no-color

# Single skill
python3 skills/skill-security-scan/scripts/scan.py --path /path/to/skill --no-color

# JSON
python3 skills/skill-security-scan/scripts/scan.py --json --severity medium
```

Auto-discovers Cursor, Claude, Agents, Codex, OpenClaw, and common CLI skill dirs.

Exit codes: `0` clean · `1` low/medium · `2` high · `3` critical

## Tests

```bash
npm test
# or
python3 -m unittest discover -s test -v
```

Fixtures under `test/fixtures/` cover clean docs, classic malware, prompt injection,
and platform diversion / forced upload / silent install.

## Package layout

```
skills/skill-security-scan/
  SKILL.md                 # Agent instructions
  scripts/scan.py          # Pure-Python scanner (stdlib only)
  scripts/ioc_database.json
  references/
    threat-patterns.md
    remediation.md
test/
  fixtures/                # Synthetic skills for regression tests
  test_scan.py
```

## Publishing

Agent skills are primarily distributed via **GitHub** and installed with
`npx skills add owner/repo`. The [skills.sh](https://skills.sh/) registry indexes
public GitHub skill repos. Publishing to the npm registry is optional and not
required for `npx skills` discovery.

## Relationship to other tools

This package aims for **broader coverage** than malware-IOC scanners that only target
Claude/OpenClaw paths. Classic detectors are included; L2/L3 add diversion and
supply-chain checks (e.g. forced file upload, silent skill install).

IOC indicators in `ioc_database.json` are adapted from public SlowMist / community
reporting (see [NOTICE](NOTICE)). Extend the file as you learn new indicators.

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
