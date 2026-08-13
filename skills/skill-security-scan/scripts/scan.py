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
import io
import json
import math
import os
import re
import shlex
import sys
from contextlib import redirect_stdout
from dataclasses import asdict, dataclass, field
from datetime import datetime
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
    skill_path: str = ""

    def to_dict(self) -> dict:
        """Serialize the finding for JSON output."""
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d


# Hit-line only; surrounding context is omitted to keep reports short.
EVIDENCE_CONTEXT_BEFORE = 0
EVIDENCE_CONTEXT_AFTER = 0
EVIDENCE_MAX_LINE_CHARS = 220
# Max distinct excerpts shown per risk-summary category.
EVIDENCE_SUMMARY_LIMIT = 3
DEFAULT_MD_REPORT_NAME = "skill-security-scan-report.md"
SCAN_TIME_FORMAT = "%Y-%m-%d %H:%M"


def format_scan_time(when: Optional[datetime] = None) -> str:
    """Return a local scan timestamp for report headings."""
    return (when or datetime.now()).strftime(SCAN_TIME_FORMAT)


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
SELF_SKILL_NAMES = {"skill-security-scan"}


def is_self_scanner_skill(skill_dir: Path, skill_name: str = "") -> bool:
    """Return True when this directory is the scanner's own skill package."""
    name = skill_name or skill_dir.name
    if name in SELF_SKILL_NAMES:
        return True
    scan_py = skill_dir / "scripts" / "scan.py"
    if not scan_py.is_file():
        return False
    try:
        head = scan_py.read_text(encoding="utf-8", errors="replace")[:500]
    except OSError:
        return False
    return SCANNER_SELF_MARKER in head


def skill_content_fingerprint(
    skill_dir: Path, files: list[Path]
) -> tuple[str, dict[Path, str]]:
    """Hash skill file contents (relative paths + bytes) and return decoded text.

    Used to skip re-scanning identical copies installed under multiple agent roots.
    """
    digest = hashlib.sha256()
    contents: dict[Path, str] = {}
    for path in sorted(files, key=lambda p: str(p)):
        try:
            rel = str(path.resolve().relative_to(skill_dir.resolve()))
        except ValueError:
            rel = path.name
        try:
            data = path.read_bytes()
        except OSError:
            continue
        digest.update(rel.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
        contents[path] = data.decode("utf-8", errors="replace")
    return digest.hexdigest(), contents


class SkillDiscovery:
    """Finds skill directories across Cursor, Claude, Codex, Trae, OpenClaw, and agents."""

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
            # Trae / Trae CN (skills CLI: ~/.trae/skills, ~/.trae-cn/skills)
            home / ".trae" / "skills",
            home / ".trae-cn" / "skills",
        ]

        if project_root is None:
            project_root = Path.cwd()
        search_roots.extend(
            [
                project_root / ".cursor" / "skills",
                project_root / ".claude" / "skills",
                project_root / ".agents" / "skills",
                project_root / ".trae" / "skills",
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
        """Walk search roots and return unique skill directories.

        Symlinked installs are collapsed to the resolved directory so scan
        roots and finding file paths stay aligned. Extra install paths are
        kept on ``aliases``.
        """
        skills: list[dict] = []
        seen: dict[Path, dict] = {}
        for root in roots:
            if not root.is_dir():
                continue
            for child in sorted(root.iterdir()):
                if not child.is_dir():
                    continue
                resolved = child.resolve()
                if is_self_scanner_skill(resolved, child.name):
                    continue
                if resolved in seen:
                    existing = seen[resolved]
                    if child.is_symlink():
                        alias = str(child)
                        if alias not in existing["aliases"]:
                            existing["aliases"].append(alias)
                    continue
                record = {
                    "name": child.name,
                    "path": resolved,
                    "files": self._collect_files(resolved),
                    "source_root": str(resolved.parent),
                    "aliases": [],
                }
                if child.is_symlink():
                    record["aliases"].append(str(child))
                seen[resolved] = record
                skills.append(record)
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
            line_content=line.strip()[:EVIDENCE_MAX_LINE_CHARS],
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
        """Match covert-handoff candidate language; the skill reviews destination."""
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


class RemoteWorkflowExfiltrationDetector(BaseDetector):
    """Detects shipping local files or coding tasks into a remote platform workflow."""

    name = "RemoteWorkflowExfiltrationDetector"
    layer = "L2"
    category = "remote_workflow_exfiltration"
    _auto_attach = re.compile(
        r"(@[^\s]+.{0,80}(自动上传|作为附件)|"
        r"引用本地文件.{0,40}(自动上传|附件)|"
        r"(message\s+send|session\s+message).{0,80}@[^\s]+|"
        r"对比\s+@|@[\w./-]+\s+和\s+@)",
        re.IGNORECASE,
    )
    _remote_task = re.compile(
        r"((coze|acme|bolt|replit)\s+code\s+message\s+send|"
        r"(coze|acme)\s+session\s+message|"
        r"发送需求\s*`?message`?|"
        r"把.{0,20}(需求|代码|文件|上下文).{0,20}(发到|发送到|同步到).{0,20}(云|平台|远端|远程))",
        re.IGNORECASE,
    )
    _deploy = re.compile(
        r"((coze|acme)\s+code\s+deploy|部署上线|deploy\s+to\s+production)",
        re.IGNORECASE,
    )

    def scan_file(self, content: str, file_path: str) -> list[Finding]:
        """Flag remote message/file workflows that exfiltrate local context."""
        findings: list[Finding] = []
        lines = content.splitlines()
        remote_hits: list[tuple[int, str]] = []
        attach_hits: list[tuple[int, str]] = []
        deploy_hits: list[tuple[int, str]] = []
        for i, line in enumerate(lines, 1):
            if self._auto_attach.search(line):
                attach_hits.append((i, line))
            if self._remote_task.search(line):
                remote_hits.append((i, line))
            if self._deploy.search(line):
                deploy_hits.append((i, line))

        for i, line in attach_hits[:5]:
            findings.append(
                self._finding(
                    Severity.HIGH,
                    file_path,
                    i,
                    line,
                    "Local file paths are auto-attached/uploaded into a remote platform message — "
                    "source code or secrets may leave the machine",
                    86,
                )
            )
        if remote_hits and attach_hits:
            i, line = remote_hits[0]
            findings.append(
                self._finding(
                    Severity.HIGH,
                    file_path,
                    i,
                    line,
                    "Remote workflow accepts local file attachments — combined code/context exfiltration risk",
                    84,
                )
            )
        elif remote_hits:
            i, line = remote_hits[0]
            findings.append(
                self._finding(
                    Severity.MEDIUM,
                    file_path,
                    i,
                    line,
                    "Sends user tasks/messages into a remote coding or session workflow",
                    58,
                )
            )
        if deploy_hits:
            i, line = deploy_hits[0]
            findings.append(
                self._finding(
                    Severity.MEDIUM,
                    file_path,
                    i,
                    line,
                    "Instructs deployment onto a third-party platform — confirm user intent",
                    50,
                )
            )
        return findings


class ThirdPartyAuthHandoffDetector(BaseDetector):
    """Detects skills that push the agent into third-party OAuth/login flows."""

    name = "ThirdPartyAuthHandoffDetector"
    layer = "L2"
    category = "third_party_auth"
    _oauth = re.compile(
        r"((coze|acme|bolt)\s+auth\s+login|"
        r"Authentication successful\.?\s*Credentials saved|"
        r"user_code=|"
        r"设备码.{0,20}授权|"
        r"coze auth login)",
        re.IGNORECASE,
    )
    _background = re.compile(
        r"(nohup|后台执行.{0,20}(login|auth|授权)|detached)",
        re.IGNORECASE,
    )

    def scan_file(self, content: str, file_path: str) -> list[Finding]:
        """Flag OAuth/login handoff, especially when run detached in the background."""
        findings: list[Finding] = []
        lines = content.splitlines()
        auth_lines: list[tuple[int, str]] = []
        for i, line in enumerate(lines, 1):
            if self._oauth.search(line):
                auth_lines.append((i, line))
        high: list[Finding] = []
        medium: list[Finding] = []
        for i, line in auth_lines:
            window = "\n".join(lines[max(0, i - 5) : min(len(lines), i + 12)])
            if self._background.search(window):
                high.append(
                    self._finding(
                        Severity.HIGH,
                        file_path,
                        i,
                        line,
                        "Background/detached third-party OAuth login — may bind host agent to an external account "
                        "without a clear interactive consent path",
                        80,
                    )
                )
            else:
                medium.append(
                    self._finding(
                        Severity.MEDIUM,
                        file_path,
                        i,
                        line,
                        "Third-party CLI OAuth/login required — verify the user intends to authorize that platform",
                        55,
                    )
                )
        findings.extend(high[:4])
        if not high and medium:
            findings.append(medium[0])
        elif medium and high:
            # Keep a single medium only if it adds a distinct non-background auth mention
            pass
        return findings


class OutputDrivenCommandDetector(BaseDetector):
    """Detects instructions to execute commands suggested by CLI/tool output."""

    name = "OutputDrivenCommandDetector"
    layer = "L3"
    category = "output_driven_execution"
    _patterns = [
        (
            re.compile(
                r"(_notice\.command|执行其\s*`?command`?\s*字段|"
                r"完成当前任务之余执行.{0,30}(command|修复命令)|"
                r"run\s+the\s+(suggested|emitted|notice)\s+command|"
                r"execute.{0,40}_notice)",
                re.IGNORECASE,
            ),
            "Instructs the agent to execute commands emitted by CLI/tool output — "
            "remote output can drive local side effects (confused deputy)",
            88,
        ),
        (
            re.compile(
                r"(skill\.mode\s*=\s*auto|静默自动修复|"
                r"自动(?:同步|修复).{0,30}skill)",
                re.IGNORECASE,
            ),
            "Auto-repairs/syncs skills from tool notices without explicit user approval",
            70,
        ),
    ]

    def scan_line(self, line: str, line_num: int, file_path: str) -> list[Finding]:
        """Match output-driven or auto-repair command execution patterns."""
        findings = []
        for pat, desc, conf in self._patterns:
            if pat.search(line):
                sev = Severity.HIGH if conf >= 80 else Severity.MEDIUM
                findings.append(self._finding(sev, file_path, line_num, line, desc, conf))
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
                r"\.trae(?:-cn)?/skills|"
                r"\.openclaw/.*/skills)",
                re.IGNORECASE,
            ),
            "References agent skill install directories — verify it does not write without consent",
            50,
        ),
        (
            re.compile(
                r"(cp|copy|writeFile|mkdir|os\.makedirs).{0,80}"
                r"(\.cursor/skills|\.claude/skills|\.agents/skills|\.trae(?:-cn)?/skills)",
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
class DuplicateCopy:
    """A skill that matches an already-scanned copy by content hash."""

    name: str
    scanned_path: str
    copy_path: str

    def to_dict(self) -> dict:
        """Serialize the duplicate-copy record for JSON output."""
        return {
            "name": self.name,
            "scanned_path": self.scanned_path,
            "copy_path": self.copy_path,
        }


@dataclass
class SymlinkRoot:
    """A search root that only reached skills through a symlink."""

    path: str
    real_path: str

    def to_dict(self) -> dict:
        """Serialize the symlink-root record for JSON output."""
        return {"path": self.path, "real_path": self.real_path}


@dataclass
class ScanResult:
    """Aggregated scan output across all skills."""

    skills_scanned: int = 0
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    skill_roots: list[str] = field(default_factory=list)
    symlink_roots: list[SymlinkRoot] = field(default_factory=list)
    skill_paths: dict[str, str] = field(default_factory=dict)
    skipped_self: list[str] = field(default_factory=list)
    duplicate_copies: list[DuplicateCopy] = field(default_factory=list)
    scanned_at: str = ""

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
            RemoteWorkflowExfiltrationDetector(),
            ThirdPartyAuthHandoffDetector(),
            # L3
            SilentSkillInstallDetector(),
            SkillPathWriteDetector(),
            OutputDrivenCommandDetector(),
        ]

    def scan_skills(self, skills: list[dict]) -> ScanResult:
        """Scan skill records, skipping this scanner and identical copies."""
        result = ScanResult(scanned_at=format_scan_time())
        seen_hashes: dict[str, tuple[str, str]] = {}
        scanned_roots: set[str] = set()
        symlink_roots: dict[str, str] = {}

        for skill in skills:
            name = skill["name"]
            skill_dir = Path(skill.get("path") or "")
            try:
                skill_dir = skill_dir.resolve() if skill_dir else skill_dir
            except OSError:
                pass
            skill_path = str(skill_dir) if skill_dir else ""
            if skill_dir and is_self_scanner_skill(skill_dir, name):
                result.skipped_self.append(skill_path or name)
                continue
            files = list(skill.get("files") or [])
            fingerprint, contents = skill_content_fingerprint(skill_dir, files)
            if fingerprint and fingerprint in seen_hashes:
                first_name, first_path = seen_hashes[fingerprint]
                result.duplicate_copies.append(
                    DuplicateCopy(
                        name=name or first_name,
                        scanned_path=first_path,
                        copy_path=skill_path,
                    )
                )
                continue
            if fingerprint:
                seen_hashes[fingerprint] = (name, skill_path)
            if skill_path:
                result.skill_paths.setdefault(name, skill_path)
                scanned_roots.add(str(skill_dir.parent))
            for alias in skill.get("aliases") or []:
                if alias and alias != skill_path:
                    result.duplicate_copies.append(
                        DuplicateCopy(
                            name=name,
                            scanned_path=skill_path,
                            copy_path=alias,
                        )
                    )
                    alias_root = str(Path(alias).parent)
                    real_root = str(skill_dir.parent) if skill_dir else ""
                    if not alias_root or not real_root:
                        continue
                    try:
                        same_root = Path(alias_root).resolve() == Path(real_root).resolve()
                    except OSError:
                        same_root = alias_root == real_root
                    if not same_root:
                        symlink_roots[alias_root] = real_root
            result.skills_scanned += 1
            for path in files:
                content = contents.get(path)
                if content is None:
                    try:
                        content = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                result.files_scanned += 1
                rel = str(path)
                for detector in self.detectors:
                    for finding in detector.scan_file(content, rel):
                        finding.skill_name = name
                        finding.skill_path = skill_path
                        finding.line_content = build_evidence_excerpt(
                            content,
                            finding.line_number,
                            file_label=Path(rel).name,
                        ) or finding.line_content
                        result.findings.append(finding)
        result.skill_roots = sorted(scanned_roots)
        result.symlink_roots = [
            SymlinkRoot(path=path, real_path=real_path)
            for path, real_path in sorted(symlink_roots.items())
            if path not in scanned_roots
        ]
        return result


# ─── Reporting ───────────────────────────────────────────────────────────────


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}

CATEGORY_RISK_TITLES = {
    "remote_code_execution": "Remote code execution via download-and-run",
    "threat_intelligence": "Known malicious indicator (IOC) match",
    "obfuscation": "Obfuscated or encoded payload patterns",
    "data_exfiltration": "Sensitive data collection/upload patterns",
    "credential_theft": "Credential or secret access patterns",
    "persistence": "Persistence / auto-start mechanisms",
    "supply_chain": "Install-hook / supply-chain code execution",
    "prompt_injection": "Prompt-injection / jailbreak language",
    "social_engineering": "Social-engineering naming or framing",
    "network_access": "Unexpected network access primitives",
    "privilege_escalation": "Privilege escalation patterns",
    "platform_diversion": "Silent diversion of workflows to a third-party platform",
    "forced_exfiltration": "Mandatory upload of local content to a remote platform",
    "covert_tool_handoff": "Routing work to tools/platforms without explicit user request",
    "host_suppression": "Blocking fallback to the host agent's own capabilities",
    "remote_workflow_exfiltration": "Sending local files/tasks into a remote platform workflow",
    "third_party_auth": "Third-party account authorization / OAuth handoff",
    "supply_chain_persistence": "Silent skill install or persistence into agent directories",
    "output_driven_execution": "Executing commands suggested by tool/CLI output",
    "generic": "Suspicious skill behavior",
}

CATEGORY_RISK_TITLES_ZH = {
    "remote_code_execution": "通过「下载并执行」实现远程代码执行",
    "threat_intelligence": "命中已知恶意指标（IOC）",
    "obfuscation": "存在混淆或编码载荷特征",
    "data_exfiltration": "存在敏感数据收集/上传特征",
    "credential_theft": "存在凭据或密钥访问特征",
    "persistence": "存在持久化/开机自启类机制",
    "supply_chain": "安装钩子等供应链代码执行风险",
    "prompt_injection": "存在提示注入/越狱类文案",
    "social_engineering": "存在社工式命名或话术包装",
    "network_access": "出现非预期的网络访问能力",
    "privilege_escalation": "存在提权相关操作",
    "platform_diversion": "将正常工作流静默导流到第三方平台",
    "forced_exfiltration": "强制把本地内容上传到远端平台",
    "covert_tool_handoff": "在用户未明确点名时把工作交给外部工具/平台",
    "host_suppression": "禁止回退到宿主 Agent 自身能力",
    "remote_workflow_exfiltration": "把本地文件/任务送入远端平台工作流",
    "third_party_auth": "引导进行第三方账号授权/OAuth",
    "supply_chain_persistence": "静默安装 skill 或写入 agent 目录形成持久化",
    "output_driven_execution": "按 CLI/工具输出中的建议命令执行（输出驱动）",
    "generic": "存在可疑 skill 行为",
}

CATEGORY_TYPE_LABELS = {
    "remote_code_execution": "Remote code execution",
    "threat_intelligence": "Malicious indicator",
    "obfuscation": "Obfuscation / encoding",
    "data_exfiltration": "Data exfiltration",
    "credential_theft": "Credential theft",
    "persistence": "Persistence",
    "supply_chain": "Supply-chain hook",
    "prompt_injection": "Prompt injection",
    "social_engineering": "Social engineering",
    "network_access": "Network access",
    "privilege_escalation": "Privilege escalation",
    "platform_diversion": "Platform diversion",
    "forced_exfiltration": "Forced upload",
    "covert_tool_handoff": "Covert handoff",
    "host_suppression": "Host suppression",
    "remote_workflow_exfiltration": "Remote workflow",
    "third_party_auth": "Third-party auth",
    "supply_chain_persistence": "Supply-chain persistence",
    "output_driven_execution": "Output-driven execution",
    "generic": "Suspicious behavior",
}

CATEGORY_TYPE_LABELS_ZH = {
    "remote_code_execution": "远程代码执行",
    "threat_intelligence": "恶意指标",
    "obfuscation": "混淆/编码",
    "data_exfiltration": "数据外传",
    "credential_theft": "凭据窃取",
    "persistence": "持久化",
    "supply_chain": "供应链钩子",
    "prompt_injection": "提示注入",
    "social_engineering": "社会工程",
    "network_access": "网络访问",
    "privilege_escalation": "权限提升",
    "platform_diversion": "平台导流",
    "forced_exfiltration": "强制上传",
    "covert_tool_handoff": "隐蔽交接",
    "host_suppression": "宿主压制",
    "remote_workflow_exfiltration": "远端工作流",
    "third_party_auth": "第三方授权",
    "supply_chain_persistence": "供应链持久化",
    "output_driven_execution": "输出驱动执行",
    "generic": "可疑行为",
}

EXPLANATION_MAX_CHARS = 180
_COMMAND_IN_TICKS = re.compile(r"`([^`]+)`")
_URL_RE = re.compile(r"https?://[^\s)\"'`<>]+")
_AT_FILE_RE = re.compile(r"@[\w./\\-]+")

UI_TEXT = {
    "en": {
        "report_title": "Skill Security Scan Report",
        "overview": "Scan overview",
        "findings_section": "Findings",
        "skills": "Skills scanned",
        "files": "Files scanned",
        "roots": "Scan roots",
        "clean": "No security issues detected.",
        "remediation": "Remediation plan",
        "skill": "Skill",
        "risk_type": "Risk type",
        "explanation": "Note",
        "source": "Source",
        "source_excerpt": "Excerpt",
        "scanned_at": "Scan time",
        "severity_counts": "Severity totals",
        "none": "(none)",
        "act_now": "act immediately",
        "act_soon": "act soon",
        "review": "review",
        "duplicates": "Other install locations (symlink or same content, not re-scanned)",
        "symlink_note": "symlink →",
        "duplicate_of": "same as",
        "skipped_self": "Skipped this scanner's own skill",
        "md_written": "Report written to",
        "md_failed": "Could not write markdown report; showing stdout only",
        "severity": {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        },
    },
    "zh": {
        "report_title": "Skill 安全扫描报告",
        "overview": "总体检查情况",
        "findings_section": "风险项",
        "skills": "Skill 数",
        "files": "文件数",
        "roots": "扫描根目录",
        "clean": "未发现安全问题。",
        "remediation": "处置方案",
        "skill": "Skill",
        "risk_type": "风险类型",
        "explanation": "说明",
        "source": "出处",
        "source_excerpt": "原文摘录",
        "scanned_at": "检查时间",
        "severity_counts": "风险级别统计",
        "none": "（无）",
        "act_now": "建议立即处理",
        "act_soon": "建议尽快处理",
        "review": "建议复核",
        "duplicates": "其它安装位置（符号链接或内容相同，未再扫描）",
        "symlink_note": "符号链接 →",
        "duplicate_of": "同于",
        "skipped_self": "已跳过本扫描器自身 skill",
        "md_written": "报告已写入",
        "md_failed": "无法写入 Markdown 报告，仅输出到终端",
        "severity": {
            "CRITICAL": "严重",
            "HIGH": "高",
            "MEDIUM": "中",
            "LOW": "低",
        },
    },
}


def normalize_lang(lang: Optional[str]) -> str:
    """Normalize a language code to `en` or `zh`."""
    if not lang:
        return "en"
    value = lang.strip().lower().replace("_", "-")
    if value in {"zh", "zh-cn", "zh-hans", "cn", "chinese"}:
        return "zh"
    return "en"


def ui(lang: str) -> dict:
    """Return UI string table for the selected language."""
    return UI_TEXT[normalize_lang(lang)]


def category_title(category: str, lang: str = "en") -> str:
    """Return the localized risk title for a finding category."""
    lang = normalize_lang(lang)
    if lang == "zh":
        return CATEGORY_RISK_TITLES_ZH.get(
            category, CATEGORY_RISK_TITLES.get(category, category)
        )
    return CATEGORY_RISK_TITLES.get(category, category)


def category_type_label(category: str, layer: str = "", lang: str = "en") -> str:
    """Return a short risk-type label, distinct from the H4 risk title."""
    lang = normalize_lang(lang)
    if lang == "zh":
        name = CATEGORY_TYPE_LABELS_ZH.get(
            category, CATEGORY_TYPE_LABELS.get(category, category)
        )
    else:
        name = CATEGORY_TYPE_LABELS.get(category, category)
    if layer:
        return f"{layer} · {name}"
    return name


def extract_effect_facts(items: list[Finding]) -> dict[str, object]:
    """Pull commands, hosts, and flags from hit lines to describe impact."""
    text = "\n".join(
        finding.line_content for finding in items if finding.line_content
    )
    commands: list[str] = []
    seen: set[str] = set()
    for raw in _COMMAND_IN_TICKS.findall(text):
        cmd = re.sub(r"\s+", " ", raw).strip()
        if cmd and cmd not in seen and len(cmd) < 80:
            seen.add(cmd)
            commands.append(cmd)
    for match in re.finditer(
        r"(?:curl|wget)\s+[^\n]+?(?:\|\s*(?:bash|sh|zsh))?", text, re.I
    ):
        cmd = re.sub(r"\s+", " ", match.group(0)).strip()
        if cmd not in seen:
            seen.add(cmd)
            commands.append(cmd)
    hosts: list[str] = []
    for url in _URL_RE.findall(text):
        host = re.sub(r"^https?://", "", url).split("/")[0]
        if host and host not in hosts:
            hosts.append(host)
    cli_names: list[str] = []
    for cmd in commands:
        token = cmd.split()[0] if cmd.split() else ""
        if token and token not in {"curl", "wget", "bash", "sh", "zsh"} and token not in cli_names:
            cli_names.append(token)
    return {
        "text": text,
        "commands": commands[:3],
        "hosts": hosts[:2],
        "cli_names": cli_names[:2],
        "has_notice": "_notice" in text,
        "has_at_file": bool(_AT_FILE_RE.search(text)),
        "has_pipe_shell": bool(re.search(r"\|\s*(?:bash|sh|zsh|powershell)", text, re.I)),
        "has_regex_exec": bool(re.search(r"\.exec\s*\(", text)),
        "has_oauth": bool(re.search(r"oauth|auth login", text, re.I)),
    }


def _join_code(values: list[str]) -> str:
    """Join extracted tokens as inline code for an effect sentence."""
    return "、".join(f"`{item}`" for item in values)


def format_risk_effect(
    skill_name: str, category: str, facts: dict[str, object], lang: str
) -> str:
    """Turn extracted facts into an impact sentence, not a recopied excerpt."""
    zh = lang == "zh"
    name = f"`{skill_name or '(unknown)'}`"
    commands = list(facts.get("commands") or [])
    hosts = list(facts.get("hosts") or [])
    clis = list(facts.get("cli_names") or [])
    cmd = _join_code(commands[:2]) if commands else ""
    host = hosts[0] if hosts else ""
    cli = _join_code(clis[:2]) if clis else ""
    tool = cli or cmd or (f"`{host}`" if host else "")

    if category == "remote_code_execution":
        if zh:
            if host and facts.get("has_pipe_shell"):
                return (
                    f"{name} 会从 `{host}` 下载内容并立刻在本机 shell 执行，"
                    f"效果是把这台机器的控制权交给远端脚本。"
                )
            if cmd:
                return (
                    f"{name} 会把 {cmd} 接到本机执行；"
                    f"一旦跑起来，来路不明的代码就拥有当前用户权限。"
                )
            return f"{name} 会下载并执行远端代码，本机进程会被外部脚本接管。"
        if host and facts.get("has_pipe_shell"):
            return (
                f"{name} downloads from `{host}` and pipes it to a local shell, "
                f"giving a remote script control of this machine."
            )
        if cmd:
            return (
                f"{name} would run {cmd} locally; "
                f"untrusted code then executes with the current user's privileges."
            )
        return f"{name} downloads and runs remote code on this machine."

    if category == "supply_chain_persistence":
        if zh:
            extra = f"（{cmd}）" if cmd else ""
            notice = (
                "CLI 输出里的 `_notice.command` 还会催促再跑安装/升级，形成反复写入。"
                if facts.get("has_notice")
                else ""
            )
            return (
                f"{name} 一旦按原文执行{extra}，会把该 CLI 自带的 skills "
                f"写入本机 Agent 目录；之后即使用户不再打开这个 skill，"
                f"这些拷贝仍可能被自动加载。{notice}"
            )
        extra = f" ({cmd})" if cmd else ""
        notice = (
            " `_notice.command` in CLI output can also re-trigger install/upgrade."
            if facts.get("has_notice")
            else ""
        )
        return (
            f"{name} would write the CLI's bundled skills into local agent "
            f"directories{extra}; those copies can keep loading after this "
            f"skill is no longer used.{notice}"
        )

    if category == "forced_exfiltration":
        if zh:
            via = f"通过 {cmd} " if cmd else ""
            return (
                f"{name} 会{via}把本地文件传到远端平台；"
                f"用户界面上可能只看到「已生成/已发送」，实际副本已经离开本机。"
            )
        via = f" via {cmd}" if cmd else ""
        return (
            f"{name} uploads local files to a remote platform{via}; "
            f"the user may only see “generated/sent” while a copy has left the machine."
        )

    if category == "remote_workflow_exfiltration":
        if zh:
            attach = "用 `@文件路径` 自动附带本地文件，" if facts.get("has_at_file") else ""
            via = f"经 {cmd} " if cmd else ""
            return (
                f"{name} 会{via}{attach}把本地任务送进远端会话/工作流，"
                f"文件内容会离开本机进入对方平台。"
            )
        attach = "auto-attaches local `@path` files and " if facts.get("has_at_file") else ""
        via = f" via {cmd}" if cmd else ""
        return (
            f"{name}{via} {attach}sends local work into a remote session, "
            f"so file contents leave this machine."
        ).replace("  ", " ")

    if category == "platform_diversion":
        if zh:
            dest = tool or "第三方 CLI"
            return (
                f"{name} 会在用户只是说「开发/改代码/做产品」时把任务转给{dest}，"
                f"当前 Agent 不再自己做完，工作流被切到外部平台。"
            )
        dest = tool or "a third-party CLI"
        return (
            f"{name} hijacks ordinary coding/product requests onto {dest}, "
            f"so the host agent no longer finishes the work itself."
        )

    if category == "covert_tool_handoff":
        dest = tool or ("外部工具" if zh else "an external tool")
        if zh:
            return (
                f"{name} 会在用户没有点名{dest}时就把工作交出去；"
                f"用户以为还在当前 Agent 里处理，实际已换到另一条工具链。"
            )
        return (
            f"{name} hands work to {dest} without the user naming it, "
            f"so the task leaves the host agent’s own path."
        )

    if category == "host_suppression":
        if zh:
            dest = tool or "指定的外部 CLI"
            return (
                f"{name} 禁止回退到宿主 Agent 自己的能力，必须把{dest}路径跑通；"
                f"用户很难退出这条导流，一旦 CLI 失败任务也会被卡住。"
            )
        dest = tool or "the vendor CLI"
        return (
            f"{name} forbids falling back to the host agent, forcing {dest}; "
            f"the user cannot easily leave that path if the CLI fails."
        )

    if category == "output_driven_execution":
        if zh:
            example = f"例如 {cmd}，" if cmd and "_notice" not in cmd else ""
            return (
                f"{name} 会把 CLI 输出里的建议命令（`_notice.command` 等）"
                f"当成必须补做的步骤，{example}等于让远端输出直接改本机环境。"
            )
        example = f" such as {cmd}" if cmd else ""
        return (
            f"{name} treats suggested commands in CLI output "
            f"(`_notice.command`) as required follow-up{example}, "
            f"so remote output can change this machine."
        )

    if category == "third_party_auth":
        if zh:
            via = f"{cmd} " if cmd else ""
            return (
                f"{name} 会拉起 {via}第三方登录/OAuth；"
                f"授权可能在后台完成，本机因此留下对方账号的 token。"
            )
        via = f"{cmd} " if cmd else ""
        return (
            f"{name} starts {via}third-party login/OAuth; "
            f"the grant may finish in the background and leave a local token."
        )

    if category == "obfuscation":
        if facts.get("has_regex_exec"):
            if zh:
                return (
                    f"{name} 命中的是脚本里的正则解析（`.exec`），"
                    f"更像在拆 HTTP/Markdown，不一定是隐藏载荷；需要对照上下文判断。"
                )
            return (
                f"{name} matched regex `.exec` parsing (HTTP/Markdown-style), "
                f"which is not necessarily a hidden payload — review the surrounding code."
            )
        if zh:
            return (
                f"{name} 出现编码/混淆写法，可能用来藏命令或地址；"
                f"直接阅读原文不容易看出真正会执行什么。"
            )
        return (
            f"{name} uses encoding/obfuscation that can hide commands or hosts; "
            f"the real action is easy to miss when reading the source."
        )

    if category == "threat_intelligence":
        if zh:
            via = f"`{host}` " if host else (f"{cmd} " if cmd else "")
            return f"{name} 命中已知恶意指标 {via}，按原文连接或下载即可能接入攻击方基础设施。"
        via = f"`{host}` " if host else (f"{cmd} " if cmd else "")
        return (
            f"{name} matches a known-bad indicator {via}; "
            f"following the source can reach attacker infrastructure."
        )

    if category in {"data_exfiltration", "credential_theft"}:
        if zh:
            via = f"用 {cmd} " if cmd else ""
            what = "凭据/密钥" if category == "credential_theft" else "敏感文件或目录"
            return f"{name} 会{via}读取或外传{what}，相关秘密可能离开本机。"
        via = f" via {cmd}" if cmd else ""
        what = "credentials/secrets" if category == "credential_theft" else "sensitive files"
        return f"{name} reads or sends {what}{via}, so secrets may leave this machine."

    if category == "prompt_injection":
        if zh:
            return (
                f"{name} 用越狱/覆盖系统规则的话术改变 Agent 行为，"
                f"后续工具调用可能不再遵守原来的安全边界。"
            )
        return (
            f"{name} uses jailbreak/override language that can make the agent "
            f"ignore its original safety constraints."
        )

    if zh:
        via = f"（涉及 {tool}）" if tool else ""
        return f"{name} 按原文执行后会产生超出表面描述的副作用{via}，需要结合出处判断影响范围。"
    via = f" involving {tool}" if tool else ""
    return (
        f"{name} has side effects beyond the surface wording{via}; "
        f"check the source to see what actually changes."
    )


def risk_explanation(
    skill_name: str, items: list[Finding], lang: str = "en"
) -> str:
    """Explain the practical effect of the hits, without recopying the excerpt."""
    lang = normalize_lang(lang)
    shown = unique_findings_by_location(items)
    if not shown:
        return ""
    category = shown[0].category
    note = format_risk_effect(skill_name, category, extract_effect_facts(shown), lang)
    if len(note) > EXPLANATION_MAX_CHARS * 2:
        note = note[: EXPLANATION_MAX_CHARS * 2 - 1] + "…"
    return note


def severity_name(severity: Severity, lang: str = "en") -> str:
    """Return a localized severity name."""
    return ui(lang)["severity"][str(severity)]


@dataclass
class RiskSummary:
    """Deduped risk statement for a skill/category pair."""

    severity: Severity
    layer: str
    category: str
    skill_name: str
    statement: str
    source_excerpt: str
    count: int
    detectors: list[str] = field(default_factory=list)
    file_refs: list[str] = field(default_factory=list)
    risk_type: str = ""
    explanation: str = ""

    def to_dict(self) -> dict:
        """Serialize the risk summary for JSON output."""
        return {
            "severity": str(self.severity),
            "layer": self.layer,
            "category": self.category,
            "skill_name": self.skill_name,
            "statement": self.statement,
            "risk_type": self.risk_type,
            "explanation": self.explanation,
            "source_excerpt": self.source_excerpt,
            "file_refs": self.file_refs,
            "count": self.count,
            "detectors": self.detectors,
        }


@dataclass
class RemediationStep:
    """One numbered remediation step, optionally with executable commands."""

    title: str
    commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize the remediation step for JSON output."""
        return {"title": self.title, "commands": self.commands}


@dataclass
class RemediationItem:
    """Actionable remediation for one skill (or a global follow-up)."""

    skill_name: str
    skill_path: str
    severity: Severity
    categories: list[str]
    steps: list[RemediationStep]

    def to_dict(self) -> dict:
        """Serialize the remediation item for JSON output."""
        return {
            "skill_name": self.skill_name,
            "skill_path": self.skill_path,
            "severity": str(self.severity),
            "categories": self.categories,
            "steps": [s.to_dict() for s in self.steps],
        }


# Categories that imply credential / secret exposure risk.
_CREDENTIAL_CATEGORIES = frozenset(
    {
        "credential_theft",
        "data_exfiltration",
        "forced_exfiltration",
        "remote_workflow_exfiltration",
    }
)

# Categories that imply third-party account / token handoff.
_AUTH_CATEGORIES = frozenset({"third_party_auth"})

# Categories that imply CLI auto-reinstall / persistence.
_PERSISTENCE_CATEGORIES = frozenset(
    {
        "supply_chain_persistence",
        "supply_chain",
        "persistence",
    }
)

# Categories that imply diversion / host lock-in.
_DIVERSION_CATEGORIES = frozenset(
    {
        "platform_diversion",
        "covert_tool_handoff",
        "host_suppression",
        "output_driven_execution",
    }
)

# Categories that warrant immediate quarantine when CRITICAL/HIGH.
_QUARANTINE_CATEGORIES = frozenset(
    {
        "remote_code_execution",
        "threat_intelligence",
        "credential_theft",
        "data_exfiltration",
        "forced_exfiltration",
        "remote_workflow_exfiltration",
        "supply_chain_persistence",
        "platform_diversion",
        "covert_tool_handoff",
        "host_suppression",
        "third_party_auth",
        "output_driven_execution",
        "privilege_escalation",
    }
)


def _remediation_steps_for(
    categories: set[str],
    severity: Severity,
    skill_path: str,
    lang: str,
) -> list[RemediationStep]:
    """Build numbered remediation steps for a skill's categories."""
    zh = lang == "zh"
    steps: list[RemediationStep] = []
    quarantine_cmds = _quarantine_commands(skill_path)

    if categories & _QUARANTINE_CATEGORIES or severity >= Severity.HIGH:
        title = "隔离该 skill" if zh else "Quarantine this skill"
        if not quarantine_cmds:
            title = (
                "将该 skill 移出 Agent 加载路径（路径未知，请手动隔离）"
                if zh
                else "Move this skill out of agent load paths (path unknown — quarantine manually)"
            )
        steps.append(RemediationStep(title=title, commands=quarantine_cmds))

    if categories & _CREDENTIAL_CATEGORIES:
        steps.append(
            RemediationStep(
                title=(
                    "若可能已上传敏感内容，轮换密钥/token"
                    if zh
                    else "If sensitive content may have been uploaded, rotate keys/tokens"
                )
            )
        )

    if categories & _AUTH_CATEGORIES:
        steps.append(
            RemediationStep(
                title=(
                    "检查并撤销相关第三方 CLI / OAuth 授权与本地 token"
                    if zh
                    else "Review and revoke related third-party CLI / OAuth grants and local tokens"
                )
            )
        )

    if categories & _DIVERSION_CATEGORIES:
        steps.append(
            RemediationStep(
                title=(
                    "改用宿主 Agent 原生工作流；删除会宽触发并导流的 skill"
                    if zh
                    else "Prefer host-native workflows; remove broad-trigger diversion skills"
                )
            )
        )

    if categories & _PERSISTENCE_CATEGORIES:
        steps.append(
            RemediationStep(
                title=(
                    "检查该 CLI 是否会静默重装 skill，必要时卸载该 CLI"
                    if zh
                    else "Check whether the CLI silently reinstalls skills; uninstall it if needed"
                )
            )
        )

    if "remote_code_execution" in categories or "threat_intelligence" in categories:
        steps.append(
            RemediationStep(
                title=(
                    "复查近期 shell / Agent 历史，确认是否已执行可疑命令"
                    if zh
                    else "Review recent shell / agent history for suspicious commands"
                )
            )
        )

    if "output_driven_execution" in categories:
        steps.append(
            RemediationStep(
                title=(
                    "不要盲目执行 CLI/工具输出中的建议命令"
                    if zh
                    else "Do not blindly run commands suggested by tool/CLI output"
                )
            )
        )

    if not steps:
        steps.append(
            RemediationStep(
                title=(
                    "人工复核该 skill 的触发范围与行为后再决定是否保留"
                    if zh
                    else "Manually review this skill's triggers/behavior before keeping it"
                )
            )
        )
    return steps


def _quarantine_commands(skill_path: str) -> list[str]:
    """Return shell commands to quarantine a skill directory when the path is known."""
    if not skill_path:
        return []
    quoted = shlex.quote(skill_path)
    return [
        "mkdir -p ~/quarantine/skills",
        f"mv {quoted} ~/quarantine/skills/",
    ]


def _rescan_command(lang: str) -> str:
    """Return a re-scan command pointing at this scanner script when possible."""
    script = Path(__file__).resolve()
    base = f"python3 {shlex.quote(str(script))} --severity high --no-color"
    if lang == "zh":
        return f"{base} --lang zh"
    return base


def build_remediation_plan(
    findings: Iterable[Finding], lang: str = "en"
) -> list[RemediationItem]:
    """Build per-skill remediation items plus a global follow-up when needed."""
    lang = normalize_lang(lang)
    findings_list = list(findings)
    if not findings_list:
        return []

    grouped: dict[tuple[str, str], list[Finding]] = {}
    for f in findings_list:
        key = (f.skill_name or "(unknown)", f.skill_path or "")
        grouped.setdefault(key, []).append(f)

    items: list[RemediationItem] = []
    for (skill_name, skill_path), items_f in grouped.items():
        top = max(f.severity for f in items_f)
        if top < Severity.HIGH:
            continue
        categories = sorted({f.category for f in items_f})
        steps = _remediation_steps_for(set(categories), top, skill_path, lang)
        items.append(
            RemediationItem(
                skill_name=skill_name,
                skill_path=skill_path,
                severity=top,
                categories=categories,
                steps=steps,
            )
        )

    items.sort(key=lambda i: (-int(i.severity), i.skill_name, i.skill_path))

    zh = lang == "zh"
    global_steps: list[RemediationStep] = [
        RemediationStep(
            title="隔离后复扫确认 HIGH+ 告警消失" if zh else "Re-scan after cleanup to confirm HIGH+ is clear",
            commands=[_rescan_command(lang)],
        ),
        RemediationStep(
            title=(
                "将 skill 名称、来源包/URL 与扫描 JSON 报给团队或安全联系人"
                if zh
                else "Report skill name, source package/URL, and scanner JSON to your team/security contact"
            )
        ),
        RemediationStep(
            title=(
                "若来自市场/注册表，向运营方举报该 skill"
                if zh
                else "If it came from a marketplace/registry, report it to the operator"
            )
        ),
    ]
    if any(f.severity < Severity.HIGH for f in findings_list) and not items:
        global_steps.insert(
            0,
            RemediationStep(
                title=(
                    "当前主要为中/低风险：人工复核描述与触发范围；必要时再隔离"
                    if zh
                    else "Findings are mostly MEDIUM/LOW: review scope/triggers; quarantine if still untrusted"
                )
            ),
        )
    items.append(
        RemediationItem(
            skill_name="*" if not zh else "（全局）",
            skill_path="",
            severity=max(f.severity for f in findings_list),
            categories=[],
            steps=global_steps,
        )
    )
    return items


def filter_findings(
    findings: Iterable[Finding], min_severity: Severity
) -> list[Finding]:
    """Keep findings at or above the requested severity."""
    return [f for f in findings if f.severity >= min_severity]


def build_evidence_excerpt(
    content: str,
    line_number: int,
    *,
    before: int = EVIDENCE_CONTEXT_BEFORE,
    after: int = EVIDENCE_CONTEXT_AFTER,
    file_label: str = "",
) -> str:
    """Return only the hit line text (no line-number or filename prefix)."""
    del file_label
    lines = content.splitlines()
    if not lines:
        return ""
    if line_number <= 0:
        idx = 0
    else:
        idx = min(max(line_number, 1), len(lines)) - 1
    start_i = max(0, idx - before)
    end_i = min(len(lines), idx + after + 1)
    parts: list[str] = []
    for i in range(start_i, end_i):
        raw = lines[i].rstrip("\n")
        if len(raw) > EVIDENCE_MAX_LINE_CHARS:
            raw = raw[: EVIDENCE_MAX_LINE_CHARS - 1] + "…"
        parts.append(raw)
    return "\n".join(parts)


def collect_excerpt_hits(
    items: list[Finding], limit: int = EVIDENCE_SUMMARY_LIMIT
) -> list[Finding]:
    """Pick up to ``limit`` distinct hit lines, highest severity first."""
    ranked = sorted(
        items,
        key=lambda x: (-int(x.severity), -x.confidence, x.file_path, x.line_number),
    )
    hits: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for f in ranked:
        if not f.line_content:
            continue
        key = (f.file_path, f.line_number)
        if key in seen:
            continue
        seen.add(key)
        hits.append(f)
        if len(hits) >= limit:
            break
    return hits


def collect_source_excerpts(
    items: list[Finding], limit: int = EVIDENCE_SUMMARY_LIMIT
) -> str:
    """Merge up to ``limit`` distinct hit-line excerpts (raw line text only)."""
    return "\n".join(f.line_content.strip() for f in collect_excerpt_hits(items, limit))


def markdown_fence(text: str, info: str = "md") -> str:
    """Wrap ``text`` in a CommonMark fence longer than any backtick run inside it."""
    longest = 0
    run = 0
    for ch in text:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{info}\n{text.rstrip()}\n{ticks}"


def markdown_file_link(file_path: str, line_number: int = 0) -> str:
    """Return a markdown link that jumps to ``file_path`` at ``line_number``."""
    raw = (file_path or "").strip()
    if not raw:
        return ""
    path = Path(raw).expanduser()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if not resolved.is_absolute():
        resolved = Path.cwd() / resolved
    label = f"{resolved}:{line_number}" if line_number > 0 else str(resolved)
    try:
        uri = resolved.as_uri()
    except ValueError:
        uri = str(resolved)
    if line_number > 0:
        uri = f"{uri}#L{line_number}"
    return f"[{label}]({uri})"


def group_findings_for_report(
    findings: Iterable[Finding],
) -> dict[Severity, list[tuple[str, str, list[Finding]]]]:
    """Group findings by severity, then by skill and risk category."""
    buckets: dict[tuple[Severity, str, str], list[Finding]] = {}
    for finding in findings:
        key = (
            finding.severity,
            finding.skill_name or "(unknown)",
            finding.category,
        )
        buckets.setdefault(key, []).append(finding)

    grouped: dict[Severity, list[tuple[str, str, list[Finding]]]] = {
        severity: [] for severity in SEVERITY_ORDER
    }
    for (severity, skill_name, category), items in sorted(
        buckets.items(),
        key=lambda kv: (-int(kv[0][0]), kv[0][1], kv[0][2]),
    ):
        items_sorted = sorted(items, key=lambda x: (x.file_path, x.line_number))
        grouped[severity].append((skill_name, category, items_sorted))
    return grouped


def urgency_phrase(severity: Severity, lang: str = "en") -> str:
    """Return a short urgency hint for remediation headers."""
    text_ui = ui(lang)
    if severity >= Severity.CRITICAL:
        return text_ui["act_now"]
    if severity >= Severity.HIGH:
        return text_ui["act_soon"]
    return text_ui["review"]


def remediation_header(
    item: RemediationItem, *, use_emoji: bool = True, lang: str = "en"
) -> str:
    """Format a remediation skill header like ``🔴 name（严重 — 建议立即处理）``."""
    lang = normalize_lang(lang)
    sev = severity_name(item.severity, lang)
    urgency = urgency_phrase(item.severity, lang)
    emoji = f"{SEVERITY_EMOJI.get(item.severity, '⚪')} " if use_emoji else ""
    if lang == "zh":
        return f"{emoji}{item.skill_name}（{sev} — {urgency}）"
    return f"{emoji}{item.skill_name} ({sev} — {urgency})"


def print_remediation_steps(steps: list[RemediationStep]) -> None:
    """Print numbered remediation steps; wrap shell commands in bash fences."""
    for i, step in enumerate(steps, 1):
        print(f"{i}. {step.title}")
        print()
        if step.commands:
            print(markdown_fence("\n".join(step.commands), "bash"))
            print()


def build_risk_summaries(
    findings: Iterable[Finding], lang: str = "en"
) -> list[RiskSummary]:
    """Collapse findings into per-skill risk statements for the summary section."""
    lang = normalize_lang(lang)
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        key = (f.skill_name or "(unknown)", f.category)
        grouped.setdefault(key, []).append(f)

    summaries: list[RiskSummary] = []
    for (skill_name, category), items in grouped.items():
        top = max(items, key=lambda x: (int(x.severity), x.confidence))
        if lang == "zh":
            statement = category_title(category, "zh")
        else:
            statement = top.description or category_title(category, "en")
        hits = collect_excerpt_hits(items)
        excerpt = "\n".join(f.line_content.strip() for f in hits)
        file_refs = [
            f"{f.file_path}:{f.line_number}" if f.line_number > 0 else f.file_path
            for f in hits
        ]
        detectors = sorted({i.detector for i in items})
        summaries.append(
            RiskSummary(
                severity=top.severity,
                layer=top.layer,
                category=category,
                skill_name=skill_name,
                statement=statement,
                source_excerpt=excerpt,
                count=len(items),
                detectors=detectors,
                file_refs=file_refs,
                risk_type=category_type_label(category, top.layer, lang),
                explanation=risk_explanation(skill_name, items, lang),
            )
        )

    summaries.sort(key=lambda s: (-int(s.severity), s.skill_name, s.category))
    return summaries


def print_overview(
    result: ScanResult, *, use_emoji: bool = True, lang: str = "en"
) -> None:
    """Print the scan-overview section (counts, roots, skips, duplicates)."""
    lang = normalize_lang(lang)
    text = ui(lang)
    scanned_at = result.scanned_at or format_scan_time()
    counts = result.counts_by_severity()
    print(f"## {text['overview']}")
    print()
    sep = "：" if lang == "zh" else ": "
    print(f"- **{text['scanned_at']}**{sep}{scanned_at}")
    print(f"- **{text['skills']}**{sep}{result.skills_scanned}")
    print(f"- **{text['files']}**{sep}{result.files_scanned}")
    count_bits: list[str] = []
    for severity in SEVERITY_ORDER:
        name = severity_name(severity, lang)
        mark = f"{SEVERITY_EMOJI[severity]} " if use_emoji else ""
        count_bits.append(f"{mark}{name} {counts[severity.name]}")
    print(f"- **{text['severity_counts']}**{sep}{' · '.join(count_bits)}")
    if result.skill_roots or result.symlink_roots:
        print(f"- **{text['roots']}**{sep}")
        for root in result.skill_roots:
            print(f"  - `{root}`")
        for link in result.symlink_roots:
            note = text["symlink_note"]
            if lang == "zh":
                print(f"  - `{link.path}`（{note} `{link.real_path}`）")
            else:
                print(f"  - `{link.path}` ({note} `{link.real_path}`)")
    if result.skipped_self:
        print(f"- **{text['skipped_self']}**{sep}")
        for path in result.skipped_self:
            print(f"  - `{path}`")
    if result.duplicate_copies:
        print(f"- **{text['duplicates']}**{sep}")
        for dup in result.duplicate_copies:
            print(
                f"  - `{dup.name}`: `{dup.copy_path}` "
                f"({text['duplicate_of']} `{dup.scanned_path}`)"
            )
    print()


def unique_findings_by_location(items: list[Finding]) -> list[Finding]:
    """Keep the first finding for each file:line so source links are not repeated."""
    seen: set[tuple[str, int]] = set()
    unique: list[Finding] = []
    for finding in items:
        key = (finding.file_path, finding.line_number)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def print_finding_fields(
    skill_name: str,
    category: str,
    items: list[Finding],
    *,
    lang: str = "en",
) -> None:
    """Print skill, short risk type, content-based note, sources, and excerpts."""
    text = ui(lang)
    sep = "：" if lang == "zh" else ": "
    shown = unique_findings_by_location(items)
    layer = shown[0].layer if shown else ""
    print(f"- **{text['skill']}**{sep}`{skill_name}`")
    print(
        f"- **{text['risk_type']}**{sep}"
        f"{category_type_label(category, layer, lang)}"
    )
    note = risk_explanation(skill_name, shown, lang)
    if note:
        print(f"- **{text['explanation']}**{sep}{note}")
    if len(shown) == 1:
        finding = shown[0]
        print(
            f"- **{text['source']}**{sep}"
            f"{markdown_file_link(finding.file_path, finding.line_number)}"
        )
    else:
        print(f"- **{text['source']}**{sep}")
        for finding in shown:
            print(
                f"  - {markdown_file_link(finding.file_path, finding.line_number)}"
            )
    excerpts = "\n".join(
        finding.line_content.strip()
        for finding in shown
        if finding.line_content and finding.line_content.strip()
    )
    if excerpts:
        print(f"- **{text['source_excerpt']}**{sep}")
        print()
        print(markdown_fence(excerpts, "md"))
    print()


def print_findings_section(
    findings: list[Finding],
    *,
    summary_only: bool = False,
    use_emoji: bool = True,
    lang: str = "en",
) -> None:
    """Print findings grouped by severity heading, then risk-item heading."""
    lang = normalize_lang(lang)
    text = ui(lang)
    print(f"## {text['findings_section']}")
    print()
    if not findings:
        print(text["clean"])
        print()
        return

    grouped = group_findings_for_report(findings)
    for severity in SEVERITY_ORDER:
        groups = grouped.get(severity) or []
        if not groups:
            continue
        sev_name = severity_name(severity, lang)
        heading = f"{SEVERITY_EMOJI[severity]} {sev_name}" if use_emoji else sev_name
        print(f"### {heading}")
        print()
        for skill_name, category, items in groups:
            shown = items if not summary_only else collect_excerpt_hits(items)
            title = category_title(category, lang)
            print(f"#### {title}")
            print()
            print_finding_fields(skill_name, category, shown, lang=lang)


def print_remediation(
    items: list[RemediationItem],
    use_emoji: bool = True,
    lang: str = "en",
) -> None:
    """Print the remediation plan as H2/H3 markdown with fenced commands."""
    lang = normalize_lang(lang)
    text = ui(lang)
    if not items:
        return

    print(f"## {text['remediation']}")
    print()
    for item in items:
        print(f"### {remediation_header(item, use_emoji=use_emoji, lang=lang)}")
        print()
        print_remediation_steps(item.steps)


def print_report(
    result: ScanResult,
    use_color: bool = True,
    summary_only: bool = False,
    use_emoji: bool = True,
    lang: str = "en",
) -> None:
    """Print the markdown audit report (headings, findings, remediation)."""
    del use_color
    lang = normalize_lang(lang)
    text = ui(lang)
    scanned_at = result.scanned_at or format_scan_time()
    print(f"# {text['report_title']} · {scanned_at}")
    print()
    print_overview(result, use_emoji=use_emoji, lang=lang)
    print_findings_section(
        result.findings,
        summary_only=summary_only,
        use_emoji=use_emoji,
        lang=lang,
    )
    if result.findings:
        print_remediation(
            build_remediation_plan(result.findings, lang=lang),
            use_emoji=use_emoji,
            lang=lang,
        )


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


def render_report_text(
    result: ScanResult,
    *,
    summary_only: bool = False,
    use_emoji: bool = True,
    lang: str = "en",
) -> str:
    """Render the human-readable report as plain text (no ANSI colors)."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_report(
            result,
            use_color=False,
            summary_only=summary_only,
            use_emoji=use_emoji,
            lang=lang,
        )
    return buf.getvalue()


def default_md_report_path() -> Path:
    """Return the default markdown report path in the current working directory."""
    return Path.cwd() / DEFAULT_MD_REPORT_NAME


def write_markdown_report(path: Path, body: str) -> Optional[Path]:
    """Write ``body`` to ``path``. Return the path on success, else None."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path.resolve()
    except OSError:
        return None


def should_print_stdout_report(args: argparse.Namespace, md_path: Optional[Path]) -> bool:
    """Return whether the full markdown report should also go to stdout.

    Agent/tool captures are not a TTY and often truncate long stdout. When a
    report file was written, skip the duplicate dump unless the user asked
    to print it.
    """
    if getattr(args, "quiet", False):
        return False
    if getattr(args, "force_print", False):
        return True
    if md_path is not None and not sys.stdout.isatty():
        return False
    return True


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
        "--summary-only",
        action="store_true",
        help="Limit excerpts per risk item (ignored with --json)",
    )
    p.add_argument(
        "--severity",
        type=parse_severity,
        default=Severity.LOW,
        help="Minimum severity to report (default: low)",
    )
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument(
        "--no-emoji",
        action="store_true",
        help="Disable emoji markers in the text report",
    )
    p.add_argument(
        "--lang",
        choices=["en", "zh"],
        default="en",
        help="Report language: en (default) or zh",
    )
    p.add_argument(
        "--md",
        metavar="PATH",
        help=(
            "Write the text report to this markdown file "
            f"(default: ./{DEFAULT_MD_REPORT_NAME})"
        ),
    )
    p.add_argument(
        "--no-md",
        action="store_true",
        help="Do not write a markdown report file",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print the full report to stdout (file / stderr path only)",
    )
    p.add_argument(
        "--print",
        dest="force_print",
        action="store_true",
        help="Always print the full report to stdout, even when a markdown file was written",
    )
    p.add_argument(
        "--ioc-db",
        help="Path to an alternate IOC JSON database",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint: discover or target skills, scan, and report."""
    args = build_arg_parser().parse_args(argv)
    lang = normalize_lang(args.lang)
    discovery = SkillDiscovery()
    if args.path:
        skills = discovery.discover_single(args.path)
    else:
        skills = discovery.discover(project_root=Path(args.project).resolve())

    if not skills:
        warn = (
            "[警告] 未找到可扫描的 skill。"
            if lang == "zh"
            else "[WARN] No skills found to scan."
        )
        print(warn, file=sys.stderr)
        return 0

    ioc = IOCDatabase(args.ioc_db) if args.ioc_db else IOCDatabase()
    scanner = SkillScanner(ioc)
    result = scanner.scan_skills(skills)
    result.findings = filter_findings(result.findings, args.severity)
    summaries = build_risk_summaries(result.findings, lang=lang)
    remediation = build_remediation_plan(result.findings, lang=lang)
    text = ui(lang)
    md_path: Optional[Path] = None
    if not args.no_md:
        dest = Path(args.md).expanduser() if args.md else default_md_report_path()
        body = render_report_text(
            result,
            summary_only=args.summary_only,
            use_emoji=not args.no_emoji,
            lang=lang,
        )
        md_path = write_markdown_report(dest, body)
        if md_path is None:
            print(f"{text['md_failed']}: {dest}", file=sys.stderr)
        else:
            print(f"{text['md_written']}: {md_path}", file=sys.stderr)

    if args.json:
        payload = {
            "skills_scanned": result.skills_scanned,
            "files_scanned": result.files_scanned,
            "skill_roots": result.skill_roots,
            "symlink_roots": [s.to_dict() for s in result.symlink_roots],
            "skill_paths": result.skill_paths,
            "skipped_self": result.skipped_self,
            "duplicate_copies": [d.to_dict() for d in result.duplicate_copies],
            "lang": lang,
            "scanned_at": result.scanned_at,
            "report_md": str(md_path) if md_path else None,
            "severity_counts": result.counts_by_severity(),
            "risk_summaries": [s.to_dict() for s in summaries],
            "remediation": [r.to_dict() for r in remediation],
            "findings": [f.to_dict() for f in result.findings],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif should_print_stdout_report(args, md_path):
        print_report(
            result,
            use_color=not args.no_color and sys.stdout.isatty(),
            summary_only=args.summary_only,
            use_emoji=not args.no_emoji,
            lang=lang,
        )

    return exit_code_for(result)


if __name__ == "__main__":
    sys.exit(main())
