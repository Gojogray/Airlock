"""
Airlock :: Local Guard
======================
Sub-20ms deterministic rule engine with:
  - Pre-loaded regex/signature blocks
  - Local secret tokenisation (Vault)
  - Canary key detector
  - Hash-chained audit log
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LEARNED_RULES_FILE = Path(__file__).parent / "learned_rules.json"
AUDIT_LOG_FILE = Path(__file__).parent / "audit.jsonl"

# Canary secret planted in the environment (never a real credential)
CANARY_KEY = "CANARY_KEY_PROD_8841"

# ---------------------------------------------------------------------------
# Built-in deterministic block patterns
# ---------------------------------------------------------------------------

BUILTIN_BLOCK_RULES: list[dict] = [
    {
        "id": "EXFIL_CURL_SH",
        "pattern": r"curl.*\|.*sh",
        "reason": "Pipe-to-shell exfiltration via curl",
    },
    {
        "id": "EXFIL_WGET_SH",
        "pattern": r"wget.*\|.*sh",
        "reason": "Pipe-to-shell exfiltration via wget",
    },
    {
        "id": "SSH_KEY_READ",
        "pattern": r"cat\s+.*\.ssh[/\\]id_",
        "reason": "Attempt to read SSH private key",
    },
    {
        "id": "ENV_FILE_READ",
        "pattern": r"cat\s+.*\.env(\s|$|\")",
        "reason": "Attempt to read .env secrets file",
    },
    {
        "id": "DESTRUCTIVE_RM",
        "pattern": r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+/",
        "reason": "Recursive force-delete from filesystem root",
    },
    {
        "id": "FORK_BOMB",
        "pattern": r":\(\){.*:\|:&};:",
        "reason": "Fork bomb detected",
    },
    {
        "id": "EXFIL_NC",
        "pattern": r"\bnc\b.*-[a-zA-Z]*e\b",
        "reason": "Netcat reverse-shell (-e) exfiltration",
    },
    {
        "id": "DD_DEV_ZERO",
        "pattern": r"dd\s+.*of=/dev/(s|h|v|xv)d",
        "reason": "Direct disk overwrite via dd",
    },
    {
        "id": "HISTORY_READ",
        "pattern": r"cat\s+.*bash_history|cat\s+.*zsh_history",
        "reason": "Attempt to read shell command history",
    },
    {
        "id": "SHADOW_READ",
        "pattern": r"cat\s+/etc/shadow",
        "reason": "Attempt to read /etc/shadow credentials",
    },
    {
        "id": "CRON_INJECT",
        "pattern": r"crontab.*\|.*curl|echo.*cron.*curl",
        "reason": "Cron-based persistence/exfiltration injection",
    },
    {
        "id": "PYTHON_EXEC_DECODE",
        "pattern": r"python[23]?\s+-c\s+['\"].*b64.*exec",
        "reason": "Python base64 exec obfuscation",
    },
]

# ---------------------------------------------------------------------------
# Secret patterns for local vault tokenisation
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[dict] = [
    {"id": "GOOGLE_API_KEY",   "pattern": r"AIza[0-9A-Za-z\-_]{35}"},
    {"id": "GITHUB_PAT",       "pattern": r"ghp_[0-9A-Za-z]{36}"},
    {"id": "GITHUB_OAUTH",     "pattern": r"gho_[0-9A-Za-z]{36}"},
    {"id": "AWS_ACCESS_KEY",   "pattern": r"AKIA[0-9A-Z]{16}"},
    {"id": "AWS_SECRET_KEY",   "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"},
    {"id": "STRIPE_SECRET",    "pattern": r"sk_live_[0-9A-Za-z]{24,}"},
    {"id": "STRIPE_RESTRICTED", "pattern": r"rk_live_[0-9A-Za-z]{24,}"},
    {"id": "SLACK_TOKEN",      "pattern": r"xox[baprs]-[0-9A-Za-z\-]{10,}"},
    {"id": "HEROKU_API",       "pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"},
    {"id": "PRIVATE_KEY_BLOCK","pattern": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"},
    {"id": "GENERIC_SECRET",   "pattern": r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9!@#$%^&*()_+\-=]{12,})['\"]?"},
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class GuardResult:
    decision: str                      # ALLOW | LOCAL_BLOCK | ESCALATE | CANARY_BLOCK
    reason: str
    latency_ms: float
    original_cmd: str
    sanitized_cmd: str
    matched_rule_id: Optional[str] = None
    vault_tokens: dict = field(default_factory=dict)
    canary_triggered: bool = False


@dataclass
class AuditEntry:
    timestamp: str
    command: str
    decision: str
    reason: str
    latency_ms: float
    matched_rule_id: Optional[str]
    canary_triggered: bool
    prev_hash: str
    entry_hash: str = ""


# ---------------------------------------------------------------------------
# Local Guard
# ---------------------------------------------------------------------------

class LocalGuard:
    """Deterministic local security gate."""

    def __init__(self) -> None:
        self._compiled_builtin: list[tuple[dict, re.Pattern]] = []
        self._compiled_learned: list[tuple[dict, re.Pattern]] = []
        self._prev_hash: str = "GENESIS"
        self._vault_counter: int = 0

        self._load_builtin_rules()
        self._load_learned_rules()

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_builtin_rules(self) -> None:
        self._compiled_builtin = []
        for rule in BUILTIN_BLOCK_RULES:
            try:
                compiled = re.compile(rule["pattern"], re.IGNORECASE)
                self._compiled_builtin.append((rule, compiled))
            except re.error as exc:
                print(f"[LocalGuard] Bad builtin regex {rule['id']}: {exc}")

    def _load_learned_rules(self) -> None:
        self._compiled_learned = []
        if not LEARNED_RULES_FILE.exists():
            return
        try:
            rules = json.loads(LEARNED_RULES_FILE.read_text())
            for rule in rules:
                try:
                    compiled = re.compile(rule["pattern"], re.IGNORECASE)
                    self._compiled_learned.append((rule, compiled))
                except re.error as exc:
                    print(f"[LocalGuard] Bad learned regex {rule['id']}: {exc}")
        except (json.JSONDecodeError, OSError):
            pass

    def add_learned_rule(self, rule_id: str, pattern: str, reason: str) -> bool:
        """Dynamically register a cloud-derived rule into the local engine."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return False

        new_rule = {"id": rule_id, "pattern": pattern, "reason": reason, "source": "cloud"}

        # Persist
        existing: list = []
        if LEARNED_RULES_FILE.exists():
            try:
                existing = json.loads(LEARNED_RULES_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                existing = []

        # Deduplicate by id
        existing = [r for r in existing if r.get("id") != rule_id]
        existing.append(new_rule)
        LEARNED_RULES_FILE.write_text(json.dumps(existing, indent=2))

        # Hot-reload into memory
        self._compiled_learned.append((new_rule, compiled))
        return True

    def reload_learned_rules(self) -> None:
        self._load_learned_rules()

    # ------------------------------------------------------------------
    # Vault / Secret Tokenisation
    # ------------------------------------------------------------------

    def _tokenise_secrets(self, cmd: str) -> tuple[str, dict[str, str]]:
        """Replace sensitive tokens with vault placeholders."""
        tokens: dict[str, str] = {}
        sanitized = cmd

        for sp in SECRET_PATTERNS:
            try:
                pattern = re.compile(sp["pattern"])
            except re.error:
                continue
            matches = list(pattern.finditer(sanitized))
            for match in reversed(matches):  # reverse so offsets stay valid
                self._vault_counter += 1
                vault_key = f"⟦SECRET_VAULT_{self._vault_counter}⟧"
                secret_val = match.group(0)
                tokens[vault_key] = f"[{sp['id']}]"
                sanitized = sanitized[: match.start()] + vault_key + sanitized[match.end():]

        return sanitized, tokens

    # ------------------------------------------------------------------
    # Canary detection
    # ------------------------------------------------------------------

    def _check_canary(self, cmd: str) -> bool:
        return CANARY_KEY in cmd

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(self, cmd: str) -> GuardResult:
        t0 = time.perf_counter()

        # 1. Canary check (highest priority)
        if self._check_canary(cmd):
            latency = (time.perf_counter() - t0) * 1000
            sanitized, vault = self._tokenise_secrets(cmd)
            result = GuardResult(
                decision="CANARY_BLOCK",
                reason=f"Canary key '{CANARY_KEY}' referenced — emergency local block",
                latency_ms=round(latency, 2),
                original_cmd=cmd,
                sanitized_cmd=sanitized,
                matched_rule_id="CANARY_DETECTOR",
                vault_tokens=vault,
                canary_triggered=True,
            )
            self._write_audit(result)
            return result

        # 2. Sanitise secrets before any further processing
        sanitized_cmd, vault_tokens = self._tokenise_secrets(cmd)

        # 3. Check learned (cloud-pushed) rules first so the flywheel benefits are visible
        for rule, compiled in self._compiled_learned:
            if compiled.search(cmd):
                latency = (time.perf_counter() - t0) * 1000
                result = GuardResult(
                    decision="LOCAL_BLOCK",
                    reason=f"[LEARNED] {rule['reason']}",
                    latency_ms=round(latency, 2),
                    original_cmd=cmd,
                    sanitized_cmd=sanitized_cmd,
                    matched_rule_id=rule["id"],
                    vault_tokens=vault_tokens,
                )
                self._write_audit(result)
                return result

        # 4. Check builtin rules
        for rule, compiled in self._compiled_builtin:
            if compiled.search(cmd):
                latency = (time.perf_counter() - t0) * 1000
                result = GuardResult(
                    decision="LOCAL_BLOCK",
                    reason=rule["reason"],
                    latency_ms=round(latency, 2),
                    original_cmd=cmd,
                    sanitized_cmd=sanitized_cmd,
                    matched_rule_id=rule["id"],
                    vault_tokens=vault_tokens,
                )
                self._write_audit(result)
                return result

        # 5. Heuristic: escalate if ambiguous signals found
        escalate_signals = [
            r"base64\s+-d",
            r"eval\s+\$\(",
            r"\bexec\b.*\$\(",
            r"python[23]?\s+-c",
            r"perl\s+-e",
            r"ruby\s+-e",
            r"curl\s+.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",    # raw IP curl
            r"wget\s+.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
            r"curl.*raw\.githubusercontent",
            r"wget.*raw\.githubusercontent",
            r"mkfifo",
            r"/dev/tcp/",
            r"openssl\s+enc",
        ]
        for sig in escalate_signals:
            if re.search(sig, cmd, re.IGNORECASE):
                latency = (time.perf_counter() - t0) * 1000
                result = GuardResult(
                    decision="ESCALATE",
                    reason=f"Ambiguous signal matched: `{sig}` — escalating to cloud",
                    latency_ms=round(latency, 2),
                    original_cmd=cmd,
                    sanitized_cmd=sanitized_cmd,
                    matched_rule_id=None,
                    vault_tokens=vault_tokens,
                )
                self._write_audit(result)
                return result

        # 6. ALLOW
        latency = (time.perf_counter() - t0) * 1000
        result = GuardResult(
            decision="ALLOW",
            reason="Passed all local checks",
            latency_ms=round(latency, 2),
            original_cmd=cmd,
            sanitized_cmd=sanitized_cmd,
            matched_rule_id=None,
            vault_tokens=vault_tokens,
        )
        self._write_audit(result)
        return result

    # ------------------------------------------------------------------
    # Hash-chained audit log
    # ------------------------------------------------------------------

    def _write_audit(self, result: GuardResult) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            command=result.original_cmd,
            decision=result.decision,
            reason=result.reason,
            latency_ms=result.latency_ms,
            matched_rule_id=result.matched_rule_id,
            canary_triggered=result.canary_triggered,
            prev_hash=self._prev_hash,
        )
        entry_dict = asdict(entry)
        # Compute hash over the entry (excluding the entry_hash field)
        entry_dict_no_hash = {k: v for k, v in entry_dict.items() if k != "entry_hash"}
        raw = json.dumps(entry_dict_no_hash, sort_keys=True).encode()
        entry.entry_hash = hashlib.sha256(raw).hexdigest()
        entry_dict["entry_hash"] = entry.entry_hash
        self._prev_hash = entry.entry_hash

        try:
            with AUDIT_LOG_FILE.open("a") as f:
                f.write(json.dumps(entry_dict) + "\n")
        except OSError:
            pass
