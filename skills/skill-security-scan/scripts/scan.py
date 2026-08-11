#!/usr/bin/env python3
"""
Comprehensive security scanner for installed AI agent skills.
skill-security-scan:scanner

Covers classic malware patterns, prompt/behavior diversion (platform hijack,
forced upload, covert tool handoff), and supply-chain persistence.
Pure stdlib — zero third-party dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Iterable, Optional


# ─── Severity ────────────────────────────────────────────────────────────────


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


# ─── Finding ─────────────────────────────────────────────────────────────────


@dataclass
class Finding:
    """A single detector hit with severity and evidence."""

    detector: str
    severity: Severity
    layer: str
    category: str
    file_path: str
    line_number: int
    line_content: str
    description: str
    confidence: int
    skill_name: str = ""

    def to_dict(self) -> dict:
        """Serialize the finding for JSON output."""
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d


# ─── IOC database ────────────────────────────────────────────────────────────


class IOCDatabase:
    """Loads known-bad IPs, domains, URL patterns, and file hashes."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "ioc_database.json")
        self.ips: set[str] = set()
        self.domains: set[str] = set()
        self.url_patterns: list[re.Pattern[str]] = []
        self.hashes: set[str] = set()
        self._load(db_path)

    def _load(self, path: str) -> None:
        """Populate IOC sets from a JSON database file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[WARN] Could not load IOC database ({path}): {e}", file=sys.stderr)
            return
        for entry in data.get("malicious_ips", []):
            self.ips.add(entry["ip"])
        for entry in data.get("malicious_domains", []):
            self.domains.add(entry["domain"])
        for entry in data.get("malicious_url_patterns", []):
            try:
                self.url_patterns.append(re.compile(entry["pattern"]))
            except re.error:
                pass
        for entry in data.get("malicious_hashes", []):
            self.hashes.add(entry["sha256"].lower())


# ─── Skill discovery ─────────────────────────────────────────────────────────


SKIP_DIRS = {
    "venv",
    "node_modules",
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    ".egg-info",
    "fixtures",
    "test",
    "tests",
}
TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".sh",
    ".bash",
    ".zsh",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".html",
    ".css",
    ".xml",
    ".svg",
    ".env",
    ".plist",
    ".ps1",
    ".bat",
    ".cmd",
    ".mjs",
    ".cjs",
}
MAX_FILE_SIZE = 1_000_000
MAX_FILES_PER_SKILL = 1000
SKIP_FILE_NAMES = {"ioc_database.json"}
SCANNER_SELF_MARKER = "skill-security-scan:scanner"


class SkillDiscovery:
    """Finds skill directories across Cursor, Claude, Codex, OpenClaw, and agents."""

    def discover(self, project_root: Optional[Path] = None) -> list[dict]:
        """Return skill records for all known install locations."""
        home = Path.home()
        search_roots: list[Path] = [
            home / ".cursor" / "skills",
            home / ".claude" / "skills",
            home / ".agents" / "skills",
            home / ".codex" / "skills",
            home / ".gemini" / "skills",
            home / ".openclaw" / "workspace" / "skills",
            home / ".openclaw" / "skills",
            home / ".kimi-code" / "skills",
        ]

        if project_root is None:
            project_root = Path.cwd()
        search_roots.extend(
            [
                project_root / ".cursor" / "skills",
                project_root / ".claude" / "skills",
                project_root / ".agents" / "skills",
            ]
        )

        openclaw_cfg = home / ".openclaw" / "openclaw.json"
        if openclaw_cfg.exists():
            try:
                with open(openclaw_cfg, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                for d in cfg.get("skills", {}).get("load", {}).get("extraDirs", []):
                    p = Path(os.path.expanduser(d))
                    if p.is_dir():
                        search_roots.append(p)
            except (json.JSONDecodeError, KeyError, TypeError, OSError):
                pass

        # CLI / npm packages that silently install skills into agent dirs
        for pattern in (
            home / ".npm" / "**" / "skills",
            home / ".local" / "share" / "**" / "skills",
        ):
            # Avoid expensive recursive walks; only check shallow known CLI homes.
            pass

        coze_skill_dirs = [
            home / ".coze" / "skills",
            home / "Library" / "Application Support" / "coze" / "skills",
        ]
        search_roots.extend(coze_skill_dirs)

        return self._collect_from_roots(search_roots)

    def discover_single(self, path: str) -> list[dict]:
        """Treat a single directory as one skill and collect its files."""
        p = Path(path).resolve()
        if not p.is_dir():
            print(f"[ERROR] Not a directory: {p}", file=sys.stderr)
            return []
        return [{"name": p.name, "path": p, "files": self._collect_files(p), "source_root": str(p.parent)}]

    def _collect_from_roots(self, roots: list[Path]) -> list[dict]:
        """Walk search roots and return unique skill directories."""
        skills: list[dict] = []
        seen: set[Path] = set()
        for root in roots:
            if not root.is_dir():
                continue
            for child in sorted(root.iterdir()):
                if not child.is_dir():
                    continue
                resolved = child.resolve()
                if resolved in seen:
                    continue
                # Prefer directories that look like skills (SKILL.md) but include all
                # immediate children of known skill roots.
                seen.add(resolved)
                skills.append(
                    {
                        "name": child.name,
                        "path": child,
                        "files": self._collect_files(child),
                        "source_root": str(root),
                    }
                )
        return skills

    def _collect_files(self, skill_dir: Path) -> list[Path]:
        """Collect text files under a skill directory with size/count caps."""
        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(skill_dir):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
            for name in filenames:
                if len(files) >= MAX_FILES_PER_SKILL:
                    return files
                if name in SKIP_FILE_NAMES:
                    continue
                path = Path(dirpath) / name
                if path.suffix.lower() not in TEXT_EXTENSIONS and name != "SKILL.md":
                    continue
                try:
                    if path.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                # Skip this package's own scanner implementation (pattern source)
                if path.suffix == ".py":
                    try:
                        head = path.read_text(encoding="utf-8", errors="replace")[:400]
                    except OSError:
                        continue
                    if SCANNER_SELF_MARKER in head:
                        continue
                files.append(path)
        return files


# ─── Base detector ───────────────────────────────────────────────────────────


class BaseDetector:
    """Shared helpers for line- and file-oriented detectors."""

    name = "BaseDetector"
    layer = "L1"
    category = "generic"

    def scan_file(self, content: str, file_path: str) -> list[Finding]:
        """Scan an entire file; default implementation walks lines."""
        findings: list[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            findings.extend(self.scan_line(line, i, file_path))
        return findings

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Scan a single line; override in subclasses that are line-based."""
        return []

    def _finding(
        self,
        severity: Severity,
        file_path: str,
        line_number: int,
        line: str,
        description: str,
        confidence: int,
        category: Optional[str] = None,
    ) -> Finding:
        """Build a Finding with this detector's metadata."""
        return Finding(
            detector=self.name,
            severity=severity,
            layer=self.layer,
            category=category or self.category,
            file_path=file_path,
            line_number=line_number,
            line_content=line.strip()[:200],
            description=description,
            confidence=confidence,
        )


# ─── L1 classic malware detectors ────────────────────────────────────────────


class Base64Detector(BaseDetector):
    """Flags long Base64 blobs that may hide payloads."""

    name = "Base64Detector"
    layer = "L1"
    category = "obfuscation"
    _pat = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{50,}={0,2}(?![A-Za-z0-9+/])")
    _data_uri = re.compile(r"data:image/", re.IGNORECASE)

    _cjk = re.compile(r"[\u4e00-\u9fff]")

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Detect long Base64 strings excluding data:image URIs and CJK prose."""
        if self._data_uri.search(line):
            return []
        # Markdown tables / Chinese docs often contain long alphanumeric tokens that
        # are not Base64 payloads.
        if self._cjk.search(line) or line.lstrip().startswith("|"):
            return []
        findings = []
        for m in self._pat.finditer(line):
            blob = m.group(0)
            # Require mixed case + digits typical of encoded blobs
            if not (re.search(r"[A-Z]", blob) and re.search(r"[a-z]", blob) and re.search(r"\d", blob)):
                continue
            sev = Severity.HIGH if len(blob) > 200 else Severity.MEDIUM
            findings.append(
                self._finding(
                    sev,
                    file_path,
                    line_num,
                    line,
                    f"Long Base64 string ({len(blob)} chars) — possible encoded payload",
                    55 if len(blob) > 200 else 40,
                )
            )
        return findings


class DownloadExecDetector(BaseDetector):
    """Detects download-and-execute patterns (curl|bash, wget|sh, etc.)."""

    name = "DownloadExecDetector"
    layer = "L1"
    category = "remote_code_execution"
    _patterns = [
        (re.compile(r"curl\s+[^|\n]*\|\s*(ba)?sh", re.IGNORECASE), "curl piped to shell", 95),
        (re.compile(r"wget\s+[^|\n]*\|\s*(ba)?sh", re.IGNORECASE), "wget piped to shell", 95),
        (re.compile(r"fetch\s*\([^)]*\)\s*\.then\([^)]*eval", re.IGNORECASE), "fetch then eval", 90),
        (re.compile(r"invoke-expression\s*\(\s*\(.*webclient", re.IGNORECASE), "PowerShell download+IEX", 95),
        (re.compile(r"iwr\s+.*\|\s*iex", re.IGNORECASE), "PowerShell IWR|IEX", 95),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match download-and-execute shell/JS patterns."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                findings.append(
                    self._finding(Severity.CRITICAL, file_path, line_num, line, desc, conf)
                )
        return findings


class IOCMatchDetector(BaseDetector):
    """Matches content against the known-bad IOC database."""

    name = "IOCMatchDetector"
    layer = "L1"
    category = "threat_intelligence"

    def __init__(self, ioc_db: IOCDatabase) -> None:
        self.ioc_db = ioc_db

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Flag known malicious IPs, domains, and URL patterns."""
        findings = []
        for ip in self.ioc_db.ips:
            if ip in line:
                findings.append(
                    self._finding(
                        Severity.CRITICAL,
                        file_path,
                        line_num,
                        line,
                        f"Known malicious IP address: {ip}",
                        95,
                    )
                )
        for domain in self.ioc_db.domains:
            if domain in line:
                findings.append(
                    self._finding(
                        Severity.CRITICAL,
                        file_path,
                        line_num,
                        line,
                        f"Known malicious domain: {domain}",
                        95,
                    )
                )
        for pat in self.ioc_db.url_patterns:
            if pat.search(line):
                findings.append(
                    self._finding(
                        Severity.CRITICAL,
                        file_path,
                        line_num,
                        line,
                        f"Known malicious URL pattern: {pat.pattern}",
                        90,
                    )
                )
        return findings

    def scan_file(self, content: str, file_path: str) -> list[Finding]:
        """Also hash the file and compare against known-bad hashes."""
        findings = super().scan_file(content, file_path)
        digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        if digest in self.ioc_db.hashes:
            findings.append(
                self._finding(
                    Severity.CRITICAL,
                    file_path,
                    0,
                    digest,
                    f"File SHA-256 matches known malicious hash: {digest}",
                    99,
                )
            )
        return findings


class ObfuscationDetector(BaseDetector):
    """Detects eval/exec obfuscation and encoded character chains."""

    name = "ObfuscationDetector"
    layer = "L1"
    category = "obfuscation"
    _patterns = [
        (re.compile(r"\beval\s*\(\s*(?!['\"])"), "eval() with non-literal argument", 70),
        (re.compile(r"\bexec\s*\(\s*(?!['\"])"), "exec() with non-literal argument", 70),
        (re.compile(r"\\\\x[0-9a-fA-F]{2}(?:\\\\x[0-9a-fA-F]{2}){5,}"), "Long hex-escaped string", 65),
        (re.compile(r"(chr\s*\(\s*\d+\s*\)\s*\+\s*){5,}"), "chr() concatenation chain", 70),
        (re.compile(r"String\.fromCharCode\s*\(", re.IGNORECASE), "String.fromCharCode obfuscation", 60),
        (re.compile(r"atob\s*\(|Buffer\.from\([^,]+,\s*['\"]base64['\"]", re.IGNORECASE), "Runtime Base64 decode", 55),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match common obfuscation idioms."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                findings.append(self._finding(Severity.HIGH, file_path, line_num, line, desc, conf))
        return findings


class ExfiltrationDetector(BaseDetector):
    """Detects archive+upload and sensitive-dir+upload exfiltration combos."""

    name = "ExfiltrationDetector"
    layer = "L1"
    category = "data_exfiltration"
    _sensitive_dir = re.compile(
        r"(\.ssh|\.aws|\.gnupg|\.kube|\.config/gcloud|\.npmrc|\.pypirc)"
    )
    _upload = re.compile(
        r"(requests\.(post|put)|urllib\.request\.(urlopen|Request)|http\.client|"
        r"fetch\s*\(|\.upload|curl\s+.*(-F|--data|-d\s))",
        re.IGNORECASE,
    )
    _zip = re.compile(r"zipfile|ZipFile|make_archive|tarfile", re.IGNORECASE)

    def scan_file(self, content: str, file_path: str) -> list[Finding]:
        """Correlate sensitive access with upload/archive capabilities."""
        findings: list[Finding] = []
        lines = content.splitlines()
        sensitive: list[tuple[int, str]] = []
        uploads: list[tuple[int, str]] = []
        zips: list[tuple[int, str]] = []

        for i, line in enumerate(lines, 1):
            if self._sensitive_dir.search(line):
                sensitive.append((i, line))
            if self._upload.search(line):
                uploads.append((i, line))
            if self._zip.search(line):
                zips.append((i, line))

        if zips and uploads:
            i, line = zips[0]
            findings.append(
                self._finding(
                    Severity.HIGH,
                    file_path,
                    i,
                    line,
                    "Archive creation combined with upload — possible data exfiltration",
                    75,
                )
            )
        if sensitive and uploads:
            i, line = sensitive[0]
            findings.append(
                self._finding(
                    Severity.HIGH,
                    file_path,
                    i,
                    line,
                    "Sensitive directory access combined with upload capability",
                    70,
                )
            )
        return findings


class CredentialTheftDetector(BaseDetector):
    """Detects password prompts, keychain access, and secret-file reads."""

    name = "CredentialTheftDetector"
    layer = "L1"
    category = "credential_theft"
    _patterns = [
        (re.compile(r"osascript.*password|display\s+dialog.*password", re.IGNORECASE), "Password dialog via osascript", 90),
        (re.compile(r"security\s+find-(generic|internet)-password", re.IGNORECASE), "macOS keychain password read", 85),
        (re.compile(r"~/\.ssh/(id_rsa|id_ed25519|id_ecdsa)", re.IGNORECASE), "SSH private key path access", 80),
        (re.compile(r"AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS", re.IGNORECASE), "Cloud credential env var access", 70),
        (re.compile(r"getpass\.getpass|keyring\.get_password", re.IGNORECASE), "Password capture API", 65),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match credential theft indicators."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                findings.append(
                    self._finding(Severity.CRITICAL, file_path, line_num, line, desc, conf)
                )
        return findings


class PersistenceDetector(BaseDetector):
    """Detects persistence via cron, launchd, systemd, or shell profiles."""

    name = "PersistenceDetector"
    layer = "L1"
    category = "persistence"
    _patterns = [
        (re.compile(r"crontab\s+-[er]|launchctl\s+load|systemctl\s+enable", re.IGNORECASE), "Scheduler/service persistence", 75),
        (re.compile(r"~/Library/LaunchAgents|\.config/systemd/user", re.IGNORECASE), "User persistence path write", 70),
        (re.compile(r"(>>?\s+~/?\.(bashrc|zshrc|profile|bash_profile))", re.IGNORECASE), "Shell profile modification", 70),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match persistence mechanism patterns."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                findings.append(self._finding(Severity.HIGH, file_path, line_num, line, desc, conf))
        return findings


class PostInstallHookDetector(BaseDetector):
    """Detects package install hooks that can run arbitrary code."""

    name = "PostInstallHookDetector"
    layer = "L1"
    category = "supply_chain"
    _patterns = [
        (re.compile(r'["\']postinstall["\']\s*:'), "npm postinstall hook", 70),
        (re.compile(r'["\']preinstall["\']\s*:'), "npm preinstall hook", 70),
        (re.compile(r"cmdclass\s*=.*install", re.IGNORECASE), "Python setup.py install cmdclass", 75),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match package manager install hooks."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                sev = Severity.CRITICAL if "postinstall" in desc else Severity.HIGH
                findings.append(self._finding(sev, file_path, line_num, line, desc, conf))
        return findings


class HiddenCharDetector(BaseDetector):
    """Detects zero-width and bidi override characters used in prompt injection."""

    name = "HiddenCharDetector"
    layer = "L1"
    category = "prompt_injection"
    _hidden = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]")

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Flag invisible Unicode that can hide instructions."""
        if self._hidden.search(line):
            return [
                self._finding(
                    Severity.MEDIUM,
                    file_path,
                    line_num,
                    line,
                    "Hidden/bidi Unicode characters — possible stealth prompt injection",
                    70,
                )
            ]
        return []


class EntropyDetector(BaseDetector):
    """Flags high-entropy lines while reducing false positives on CJK prose."""

    name = "EntropyDetector"
    layer = "L1"
    category = "obfuscation"
    _cjk = re.compile(r"[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]")

    def _shannon(self, s: str) -> float:
        """Compute Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Skip markdown prose and CJK-heavy lines; flag opaque high-entropy blobs."""
        stripped = line.strip()
        if len(stripped) < 80:
            return []
        # Skip YAML/markdown description prose with lots of CJK or spaces
        cjk_ratio = len(self._cjk.findall(stripped)) / max(len(stripped), 1)
        if cjk_ratio > 0.15:
            return []
        if stripped.count(" ") > len(stripped) * 0.12:
            return []
        if stripped.startswith(("description:", "#", "-", "*", ">")):
            return []
        ent = self._shannon(stripped)
        if ent >= 5.5:
            return [
                self._finding(
                    Severity.MEDIUM,
                    file_path,
                    line_num,
                    line,
                    f"High entropy line (Shannon {ent:.2f}) — possible encoded payload",
                    min(90, int(ent * 12)),
                )
            ]
        return []


class SocialEngineeringDetector(BaseDetector):
    """Detects crypto/wallet/airdrop naming used in social-engineering skills."""

    name = "SocialEngineeringDetector"
    layer = "L1"
    category = "social_engineering"
    _names = re.compile(
        r"(crypto[_-]?wallet|airdrop|free[_-]?token|security[_-]?update|urgent[_-]?fix|"
        r"claim[_-]?reward|seed[_-]?phrase|private[_-]?key[_-]?recovery|metamask[_-]?fix)",
        re.IGNORECASE,
    )

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match social-engineering naming patterns."""
        if self._names.search(line):
            return [
                self._finding(
                    Severity.LOW,
                    file_path,
                    line_num,
                    line,
                    "Social-engineering naming pattern (crypto/wallet/airdrop/urgent fix)",
                    45,
                )
            ]
        return []


class NetworkCallDetector(BaseDetector):
    """Detects direct network APIs and CLI HTTP tools in skill code/docs."""

    name = "NetworkCallDetector"
    layer = "L1"
    category = "network_access"
    _patterns = [
        (re.compile(r"\bsocket\.(socket|connect|create_connection)\b"), "Python socket usage", 50),
        (re.compile(r"\brequests\.(get|post|put|delete|patch)\s*\("), "Python requests call", 35),
        (re.compile(r"\bfetch\s*\(\s*['\"]https?://"), "JavaScript fetch() call", 35),
        (re.compile(r"\bcurl\s+-"), "curl command invocation", 45),
        (re.compile(r"\bwget\s+"), "wget command invocation", 45),
        (re.compile(r"\baxios\.(get|post|put|delete)\s*\("), "axios HTTP call", 35),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match network-capable APIs and CLIs."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                findings.append(
                    self._finding(Severity.MEDIUM, file_path, line_num, line, desc, conf)
                )
        return findings


class PrivilegeEscalationDetector(BaseDetector):
    """Detects sudo, chmod 777, setuid, and admin group changes."""

    name = "PrivilegeEscalationDetector"
    layer = "L1"
    category = "privilege_escalation"
    _patterns = [
        (re.compile(r"\bsudo\s+"), "sudo usage", 55),
        (re.compile(r"chmod\s+([0-7]*7[0-7]{2}|777)\b"), "World-writable or setuid chmod", 70),
        (re.compile(r"chmod\s+[u+]s|\bsetuid\b", re.IGNORECASE), "setuid privilege escalation", 75),
        (re.compile(r"dscl.*admin|usermod\s+-aG\s+sudo", re.IGNORECASE), "Admin group modification", 80),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match privilege escalation patterns."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                findings.append(self._finding(Severity.HIGH, file_path, line_num, line, desc, conf))
        return findings


class PromptInjectionDetector(BaseDetector):
    """Detects classic prompt-injection override phrases."""

    name = "PromptInjectionDetector"
    layer = "L1"
    category = "prompt_injection"
    _patterns = [
        (
            re.compile(
                r"(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)|"
                r"disregard\s+(your|all)\s+(system|safety)|"
                r"you\s+are\s+now\s+(unrestricted|jailbroken)|"
                r"DAN\s+mode|developer\s+mode\s+enabled)",
                re.IGNORECASE,
            ),
            "Prompt-injection override phrase",
            85,
        ),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match jailbreak / ignore-previous-instructions language."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                findings.append(
                    self._finding(Severity.HIGH, file_path, line_num, line, desc, conf)
                )
        return findings


# ─── L2 behavioral / diversion detectors ─────────────────────────────────────


class PlatformDiversionDetector(BaseDetector):
    """Detects skills that hijack normal workflows onto a third-party platform."""

    name = "PlatformDiversionDetector"
    layer = "L2"
    category = "platform_diversion"
    _trigger = re.compile(
        r"(导流|调起|接管|redirect(?:s|ed|ing)?\s+(?:to|work)|hijack|"
        r"when\s+the\s+user\s+(?:intends?|wants?|asks?).{0,40}(develop|code|build|软件|开发|修改|调试)|"
        r"核心触发|必须优先.*(coze|cursor|claude|codex|gemini|devin|replit|v0)|"
        r"load\s+this\s+skill\s+and\s+.+(instead|rather\s+than))",
        re.IGNORECASE,
    )
    _platform_cli = re.compile(
        r"(?<![\w./-])(coze|bolt|replit|v0|devin|windsurf)(?![\w.-])\s+(code|project|session|agent|file)\b|"
        r"\b(coze\s+code|coze\s+session|coze\s+file)\b|"
        r"通过\s+[\w.-]+\s+code\s+调起|"
        r"导流到\s*\S+|"
        r"(?<![\w./-])[a-z][\w-]*\s+file\s+upload\b|"
        r"(?<![\w./-])[a-z][\w-]*\s+code\s+(project|message|deploy)\b",
        re.IGNORECASE,
    )
    _wide_dev_scope = re.compile(
        r"(用户意图是开发|软件产品|创建或迭代网页|Web\s*App|小程序|"
        r"any\s+(software|coding|development)\s+(task|request|intent))",
        re.IGNORECASE,
    )

    def scan_file(self, content: str, file_path: str) -> list[Finding]:
        """Score diversion: wide triggers + platform CLI + redirect language."""
        findings: list[Finding] = []
        lines = content.splitlines()
        has_trigger = False
        has_platform = False
        has_wide = False
        evidence: list[tuple[int, str, str]] = []

        for i, line in enumerate(lines, 1):
            if self._trigger.search(line):
                has_trigger = True
                evidence.append((i, line, "Workflow diversion / hijack language"))
            if self._platform_cli.search(line):
                has_platform = True
                evidence.append((i, line, "Third-party platform CLI invocation"))
            if self._wide_dev_scope.search(line):
                has_wide = True
                evidence.append((i, line, "Broad software-development trigger scope"))

        # Frontmatter description often carries the real auto-trigger
        if file_path.endswith("SKILL.md") or file_path.endswith("MODULE.md"):
            if has_wide and has_platform:
                i, line, _ = evidence[0]
                findings.append(
                    self._finding(
                        Severity.HIGH,
                        file_path,
                        i,
                        line,
                        "Broad coding/dev triggers combined with third-party platform CLI — "
                        "likely silent workflow diversion away from the host agent",
                        85,
                    )
                )
            elif has_trigger and has_platform:
                i, line, _ = evidence[0]
                findings.append(
                    self._finding(
                        Severity.HIGH,
                        file_path,
                        i,
                        line,
                        "Explicit diversion language plus platform CLI — may hijack user workflows",
                        80,
                    )
                )
            elif has_wide and has_trigger:
                i, line, _ = evidence[0]
                findings.append(
                    self._finding(
                        Severity.MEDIUM,
                        file_path,
                        i,
                        line,
                        "Broad auto-trigger with diversion wording — review whether user consent is required",
                        65,
                    )
                )
        return findings


class ForcedUploadDetector(BaseDetector):
    """Detects mandatory uploads of local content to remote platforms."""

    name = "ForcedUploadDetector"
    layer = "L2"
    category = "forced_exfiltration"
    _forced = re.compile(
        r"(必须|必须继续|务必|强制|mandatory|must\s+(?:always\s+)?(?:continue\s+to\s+)?(?:execute|run|call|upload)|"
        r"do\s+not\s+return\s+local\s+(?:path|file)|不要返回本地路径|"
        r"必须返回在线链接)",
        re.IGNORECASE,
    )
    _upload_cmd = re.compile(
        r"((?:coze|openai|anthropic|huggingface|aws|gcloud|az)\s+\S*\s*upload|"
        r"file\s+upload|files\.upload|blob\.upload|"
        r"scp\s+|rsync\s+.*:|"
        r"curl\s+[^\n]*(-F|--upload-file|-T)\b|"
        r"@[\w./-]+.{0,40}(自动上传|auto(?:matic(?:ally)?)?\s+upload))",
        re.IGNORECASE,
    )

    def scan_file(self, content: str, file_path: str) -> list[Finding]:
        """Flag forced or policy-mandated uploads of local files."""
        findings: list[Finding] = []
        lines = content.splitlines()
        forced_lines: list[tuple[int, str]] = []
        upload_lines: list[tuple[int, str]] = []

        for i, line in enumerate(lines, 1):
            if self._forced.search(line):
                forced_lines.append((i, line))
            if self._upload_cmd.search(line):
                upload_lines.append((i, line))

        # Same-line or nearby combination
        for i, line in upload_lines:
            window = "\n".join(lines[max(0, i - 3) : min(len(lines), i + 2)])
            if self._forced.search(window) or self._forced.search(line):
                findings.append(
                    self._finding(
                        Severity.HIGH,
                        file_path,
                        i,
                        line,
                        "Mandatory upload of local files to a remote platform — "
                        "content may leave the machine without explicit user intent",
                        88,
                    )
                )
            else:
                findings.append(
                    self._finding(
                        Severity.MEDIUM,
                        file_path,
                        i,
                        line,
                        "Platform/file upload command present — verify user consent before use",
                        55,
                    )
                )

        # Attachment auto-upload patterns (e.g. @path in coze code message)
        for i, line in enumerate(lines, 1):
            if re.search(r"@[^\s]+.{0,60}(自动上传|auto(?:matic(?:ally)?)?\s+upload|作为附件)", line, re.I):
                findings.append(
                    self._finding(
                        Severity.HIGH,
                        file_path,
                        i,
                        line,
                        "Local file reference auto-uploaded as attachment to remote platform",
                        82,
                    )
                )
        return findings


class CovertToolHandoffDetector(BaseDetector):
    """Detects handing work to tools/platforms the user did not explicitly request."""

    name = "CovertToolHandoffDetector"
    layer = "L2"
    category = "covert_tool_handoff"
    _patterns = [
        (
            re.compile(
                r"(无需显式点名|without\s+(explicitly\s+)?(?:naming|mentioning|asking)|"
                r"即[使便]用户没有(?:提到|要求)|even\s+if\s+the\s+user\s+(?:did\s+not|never)|"
                r"自动(?:选择|调用|切换).{0,20}(工具|平台|CLI|agent)|"
                r"silently\s+(?:switch|route|delegate|redirect))",
                re.IGNORECASE,
            ),
            "Routes work to tools/platforms without explicit user request",
            80,
        ),
        (
            re.compile(
                r"(delegate|handoff|转交|委派).{0,40}(peer\s+agent|subagent|另一个|第三方)|"
                r"coze\s+agent\s+at\s+--mode\s+request",
                re.IGNORECASE,
            ),
            "Delegates work to peer/third-party agents",
            60,
        ),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match covert handoff / silent routing language."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                sev = Severity.HIGH if conf >= 75 else Severity.MEDIUM
                findings.append(self._finding(sev, file_path, line_num, line, desc, conf))
        return findings


class HostCapabilitySuppressionDetector(BaseDetector):
    """Detects instructions that forbid using the host agent's native capabilities."""

    name = "HostCapabilitySuppressionDetector"
    layer = "L2"
    category = "host_suppression"
    _patterns = [
        (
            re.compile(
                r"(禁止.{0,20}(改用|使用).{0,30}(宿主|自带|本地|第三方|别的|其他)|"
                r"do\s+not\s+use\s+(the\s+)?(host|built-?in|native|local).{0,30}(agent|tool|tts|capability)|"
                r"必须优先把.{0,20}路径跑通|"
                r"不得?私自改用)",
                re.IGNORECASE,
            ),
            "Forbids falling back to host-agent capabilities — locks workflow onto external platform",
            78,
        ),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match host-capability suppression instructions."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                findings.append(
                    self._finding(Severity.HIGH, file_path, line_num, line, desc, conf)
                )
        return findings


# ─── L3 supply-chain detectors ───────────────────────────────────────────────


class SilentSkillInstallDetector(BaseDetector):
    """Detects silent self-installation of skills into agent directories."""

    name = "SilentSkillInstallDetector"
    layer = "L3"
    category = "supply_chain_persistence"
    _patterns = [
        (
            re.compile(
                r"(静默.{0,30}skill\s+install|"
                r"silently\s+(?:install|sync|write).{0,30}skill|"
                r"self\s+skill\s+install|"
                r"自动(?:把|将)?.{0,20}skills?\s*(安装|写入|同步).{0,40}(agent|cursor|claude|本机)|"
                r"把自带\s*skills?\s*安装到|"
                r"skill\.mode\s*=\s*auto|"
                r"npx\s+skills\s+add.{0,40}(-y|--yes|--all))",
                re.IGNORECASE,
            ),
            "Silently installs or syncs skills into local AI agents — supply-chain persistence risk",
            90,
        ),
        (
            re.compile(
                r"(自动升级|auto(?:matic)?\s+upgrade|后台静默安装|"
                r"upgrade\.mode\s*=\s*auto)",
                re.IGNORECASE,
            ),
            "Silent auto-upgrade of CLI/skills may change behavior without user review",
            55,
        ),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match silent skill install and auto-upgrade patterns."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                sev = Severity.CRITICAL if conf >= 85 else Severity.MEDIUM
                findings.append(self._finding(sev, file_path, line_num, line, desc, conf))
        return findings


class SkillPathWriteDetector(BaseDetector):
    """Detects writes into agent skill directories from scripts."""

    name = "SkillPathWriteDetector"
    layer = "L3"
    category = "supply_chain_persistence"
    _patterns = [
        (
            re.compile(
                r"(\.cursor/skills|\.claude/skills|\.agents/skills|\.codex/skills|"
                r"\.openclaw/.*/skills)",
                re.IGNORECASE,
            ),
            "References agent skill install directories — verify it does not write without consent",
            50,
        ),
        (
            re.compile(
                r"(cp|copy|writeFile|mkdir|os\.makedirs).{0,80}"
                r"(\.cursor/skills|\.claude/skills|\.agents/skills)",
                re.IGNORECASE,
            ),
            "Writes into agent skill directories — possible unauthorized skill injection",
            85,
        ),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match skill-directory write or reference patterns."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                sev = Severity.HIGH if conf >= 80 else Severity.LOW
                findings.append(self._finding(sev, file_path, line_num, line, desc, conf))
        return findings


# ─── Scanner orchestration ───────────────────────────────────────────────────


@dataclass
class ScanResult:
    """Aggregated scan output across all skills."""

    skills_scanned: int = 0
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    skill_roots: list[str] = field(default_factory=list)

    def counts_by_severity(self) -> dict[str, int]:
        """Count findings per severity level."""
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def max_severity(self) -> Optional[Severity]:
        """Return the highest severity present, or None if clean."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)


class SkillScanner:
    """Runs all detector layers against discovered or targeted skills."""

    def __init__(self, ioc_db: Optional[IOCDatabase] = None) -> None:
        db = ioc_db or IOCDatabase()
        self.detectors: list[BaseDetector] = [
            # L1
            Base64Detector(),
            DownloadExecDetector(),
            IOCMatchDetector(db),
            ObfuscationDetector(),
            ExfiltrationDetector(),
            CredentialTheftDetector(),
            PersistenceDetector(),
            PostInstallHookDetector(),
            HiddenCharDetector(),
            EntropyDetector(),
            SocialEngineeringDetector(),
            NetworkCallDetector(),
            PrivilegeEscalationDetector(),
            PromptInjectionDetector(),
            # L2
            PlatformDiversionDetector(),
            ForcedUploadDetector(),
            CovertToolHandoffDetector(),
            HostCapabilitySuppressionDetector(),
            # L3
            SilentSkillInstallDetector(),
            SkillPathWriteDetector(),
        ]

    def scan_skills(self, skills: list[dict]) -> ScanResult:
        """Scan a list of skill records and aggregate findings."""
        result = ScanResult()
        result.skills_scanned = len(skills)
        roots = sorted({s.get("source_root", "") for s in skills if s.get("source_root")})
        result.skill_roots = [r for r in roots if r]

        for skill in skills:
            name = skill["name"]
            for path in skill["files"]:
                result.files_scanned += 1
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                rel = str(path)
                for detector in self.detectors:
                    for finding in detector.scan_file(content, rel):
                        finding.skill_name = name
                        result.findings.append(finding)
        return result


# ─── Reporting ───────────────────────────────────────────────────────────────


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def filter_findings(
    findings: Iterable[Finding], min_severity: Severity
) -> list[Finding]:
    """Keep findings at or above the requested severity."""
    return [f for f in findings if f.severity >= min_severity]


def print_report(result: ScanResult, use_color: bool = True) -> None:
    """Print a human-readable audit report to stdout."""
    colors = {
        Severity.CRITICAL: "\033[91m" if use_color else "",
        Severity.HIGH: "\033[91m" if use_color else "",
        Severity.MEDIUM: "\033[93m" if use_color else "",
        Severity.LOW: "\033[94m" if use_color else "",
    }
    reset = "\033[0m" if use_color else ""
    counts = result.counts_by_severity()

    print("=" * 70)
    print("  SKILL SECURITY SCAN REPORT")
    print(f"  Skills: {result.skills_scanned}  Files: {result.files_scanned}")
    if result.skill_roots:
        print("  Roots:")
        for root in result.skill_roots:
            print(f"    - {root}")
    print("=" * 70)
    print(
        f"  CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  "
        f"MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}"
    )
    print()

    if not result.findings:
        print("  [CLEAN] No security issues detected.")
        print()
        return

    by_skill: dict[str, list[Finding]] = {}
    for f in sorted(result.findings, key=lambda x: (-int(x.severity), x.skill_name, x.file_path)):
        by_skill.setdefault(f.skill_name or "(unknown)", []).append(f)

    for skill_name, findings in by_skill.items():
        print("-" * 70)
        print(f"  Skill: {skill_name}  ({len(findings)} finding(s))")
        for f in findings:
            c = colors.get(f.severity, "")
            print(f"    {c}[{f.severity}]{reset} [{f.layer}] {f.detector}")
            print(f"      Category: {f.category}")
            print(f"      File: {f.file_path}:{f.line_number}")
            print(f"      {f.description}")
            print(f"      Confidence: {f.confidence}%")
            if f.line_content:
                print(f"      > {f.line_content}")
            print()


def exit_code_for(result: ScanResult) -> int:
    """Map max severity to process exit code."""
    m = result.max_severity()
    if m is None:
        return 0
    if m >= Severity.CRITICAL:
        return 3
    if m >= Severity.HIGH:
        return 2
    return 1


def parse_severity(value: str) -> Severity:
    """Parse a severity name into a Severity enum."""
    try:
        return Severity[value.upper()]
    except KeyError as e:
        raise argparse.ArgumentTypeError(
            f"Invalid severity '{value}'. Use low|medium|high|critical."
        ) from e


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    p = argparse.ArgumentParser(
        description="Comprehensive security scanner for AI agent skills (L1 malware, "
        "L2 behavioral diversion, L3 supply chain)."
    )
    p.add_argument(
        "--path",
        help="Scan a single skill directory instead of auto-discovering installs",
    )
    p.add_argument(
        "--project",
        default=".",
        help="Project root used to discover project-local skills (default: cwd)",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text report")
    p.add_argument(
        "--severity",
        type=parse_severity,
        default=Severity.LOW,
        help="Minimum severity to report (default: low)",
    )
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument(
        "--ioc-db",
        help="Path to an alternate IOC JSON database",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint: discover or target skills, scan, and report."""
    args = build_arg_parser().parse_args(argv)
    discovery = SkillDiscovery()
    if args.path:
        skills = discovery.discover_single(args.path)
    else:
        skills = discovery.discover(project_root=Path(args.project).resolve())

    if not skills:
        print("[WARN] No skills found to scan.", file=sys.stderr)
        return 0

    ioc = IOCDatabase(args.ioc_db) if args.ioc_db else IOCDatabase()
    scanner = SkillScanner(ioc)
    result = scanner.scan_skills(skills)
    result.findings = filter_findings(result.findings, args.severity)

    if args.json:
        payload = {
            "skills_scanned": result.skills_scanned,
            "files_scanned": result.files_scanned,
            "skill_roots": result.skill_roots,
            "severity_counts": result.counts_by_severity(),
            "findings": [f.to_dict() for f in result.findings],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_report(result, use_color=not args.no_color and sys.stdout.isatty())

    return exit_code_for(result)


if __name__ == "__main__":
    sys.exit(main())
