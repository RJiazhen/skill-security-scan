# Remediation guide

## Immediate response (CRITICAL / HIGH)

1. **Stop using the skill** — do not invoke it further in agent sessions.
2. **Quarantine** — move the skill directory out of agent load paths, e.g.:

   ```bash
   mkdir -p ~/quarantine/skills
   mv ~/.cursor/skills/<skill-name> ~/quarantine/skills/
   ```

3. **Check reinstall vectors** — if a CLI silently reinstalls vendor skills into
   agent directories, or auto-upgrades itself, disable that behavior or uninstall the
   CLI before the skill returns.
4. **Credential rotation** — if findings include credential theft, forced upload of
   secrets, or sensitive-dir + upload, rotate:
   - SSH keys, cloud keys, npm/pypi tokens
   - Agent/provider API keys present on the machine
5. **Review recent agent actions** — chat history, shell history, and unexpected
   remote projects/files created on third-party platforms.

## L2 diversion-specific steps

- Confirm whether the user ever asked for that platform.
- Prefer host-native workflows; remove skills whose description auto-triggers on
  generic “software development” intents.
- Revoke OAuth/tokens for the third-party CLI if uploads may have occurred.

## L3 supply-chain steps

- Search for other copies:

  ```bash
  python3 scripts/scan.py --severity high --no-color
  ```

- Inspect package install hooks and global CLIs that sync skills.
- Re-scan after cleanup to confirm the skill did not reappear.

## Reporting

- Notify your team/security contact with skill name, source URL/package, and scanner JSON.
- If the skill came from a marketplace, report it to the registry operator.

## Re-entry checklist

- [ ] Skill removed from all discovered roots
- [ ] Auto-install / auto-upgrade disabled or CLI removed
- [ ] Secrets rotated if exposure possible
- [ ] Re-scan is clean at HIGH+ (or accepted residual MEDIUM with rationale)
