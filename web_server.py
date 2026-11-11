"""
Airlock :: Interactive Web Dashboard Server
===========================================
FastAPI-powered lightweight server exposing the Airlock hybrid firewall engine
and real-time ShieldAgent-style visual telemetry dashboard.

Run with:
    python web_server.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from local_guard import (
    LocalGuard,
    AUDIT_LOG_FILE,
    LEARNED_RULES_FILE,
    BUILTIN_BLOCK_RULES,
    SECRET_PATTERNS,
    CANARY_KEY,
)
from cloud_judge import CloudJudge

# ---------------------------------------------------------------------------
# App initialization
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="Airlock Interactive Dashboard",
    description="Zero-latency hybrid security firewall for autonomous coding agents",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared singletons
guard = LocalGuard()
judge = CloudJudge()


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

class EvaluateRequest(BaseModel):
    command: str
    context: Optional[str] = ""


class AddRuleRequest(BaseModel):
    rule_id: str
    pattern: str
    reason: str


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _load_audit_records() -> list[dict]:
    """Load audit records from disk with integrity checks."""
    if not AUDIT_LOG_FILE.exists():
        return []
    records = []
    with AUDIT_LOG_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                # Verify sha256
                stored_hash = rec.get("entry_hash", "")
                rec_copy = {k: v for k, v in rec.items() if k != "entry_hash"}
                raw = json.dumps(rec_copy, sort_keys=True).encode()
                computed_hash = hashlib.sha256(raw).hexdigest()
                rec["hash_valid"] = (stored_hash == computed_hash)
                records.append(rec)
            except Exception:
                pass
    return records


def _get_system_status() -> dict:
    """Return live system telemetry."""
    learned_count = 0
    if LEARNED_RULES_FILE.exists():
        try:
            learned_count = len(json.loads(LEARNED_RULES_FILE.read_text(encoding="utf-8")))
        except Exception:
            learned_count = 0

    has_key = bool(os.environ.get("GEMINI_API_KEY"))
    cloud_status = "READY (Gemini 2.0 Flash)" if has_key else "READY (Offline Heuristic)"

    audit_records = _load_audit_records()
    total_valid = sum(1 for r in audit_records if r.get("hash_valid", False))
    integrity_ok = (total_valid == len(audit_records)) if audit_records else True

    return {
        "local_edge": "ONLINE",
        "cloud_bridge": cloud_status,
        "model": "gemini-2.0-flash",
        "has_gemini_key": has_key,
        "rules_builtin": len(BUILTIN_BLOCK_RULES),
        "rules_learned": learned_count,
        "rules_total": len(BUILTIN_BLOCK_RULES) + learned_count,
        "secrets_patterns_count": len(SECRET_PATTERNS),
        "canary_key": CANARY_KEY,
        "audit_total_records": len(audit_records),
        "audit_integrity_verified": integrity_ok,
    }


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="templates/index.html not found")
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


@app.get("/api/status")
async def get_status():
    return _get_system_status()


@app.get("/api/rules")
async def get_rules():
    """Return all active rules with metadata."""
    learned = []
    if LEARNED_RULES_FILE.exists():
        try:
            learned = json.loads(LEARNED_RULES_FILE.read_text(encoding="utf-8"))
        except Exception:
            learned = []

    builtin = [
        {
            "id": r["id"],
            "pattern": r["pattern"],
            "reason": r["reason"],
            "source": "builtin",
            "tier": "edge",
        }
        for r in BUILTIN_BLOCK_RULES
    ]

    for r in learned:
        r["tier"] = "learned_flywheel"

    return {
        "builtin_rules": builtin,
        "learned_rules": learned,
        "total_rules": len(builtin) + len(learned),
    }


@app.get("/api/audit")
async def get_audit(limit: int = 50):
    records = _load_audit_records()
    # Most recent first
    records.reverse()
    return {
        "records": records[:limit],
        "total": len(records),
        "integrity_verified": all(r.get("hash_valid", False) for r in records),
    }


@app.post("/api/reset-rules")
async def reset_rules():
    """Wipe learned rules to reset flywheel state."""
    if LEARNED_RULES_FILE.exists():
        try:
            LEARNED_RULES_FILE.unlink()
        except OSError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
    guard.reload_learned_rules()
    return {"status": "ok", "message": "Learned rules cleared. Flywheel reset.", "rules_total": len(BUILTIN_BLOCK_RULES)}


@app.post("/api/clear-audit")
async def clear_audit():
    """Clear audit log."""
    if AUDIT_LOG_FILE.exists():
        try:
            AUDIT_LOG_FILE.unlink()
        except OSError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
    return {"status": "ok", "message": "Audit log reset."}


@app.post("/api/evaluate")
async def evaluate_command(req: EvaluateRequest):
    """
    Core hybrid evaluation pipeline:
    1. Local deterministic guard evaluates command (<1ms)
    2. Canary checks and secret tokenization
    3. If ESCALATE: sanitize and ship to Gemini Flash
    4. If malicious: push compiled regex rule back to edge engine (Flywheel)
    5. Return full dual-stream decision & packet inspection data
    """
    cmd = req.command.strip()
    if not cmd:
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    context = req.context or ""
    t_start = time.perf_counter()

    # Step 1: Local edge evaluation
    result = guard.evaluate(cmd)

    cloud_verdict: Optional[dict] = None
    cloud_escalated = (result.decision == "ESCALATE")
    flywheel_rule_added = False
    new_rule_details = None
    outbound_egress = None

    if cloud_escalated:
        # Construct exact simulated egress payload dispatched across the network
        outbound_payload = {
            "target": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
            "masked_command": result.sanitized_cmd,
            "context": context or "Untrusted agent execution context",
            "vault_tokens_count": len(result.vault_tokens),
            "vault_tokens_map": result.vault_tokens,
            "raw_secrets_exposed": False,
            "provenance_check": "INDIRECT_INJECTION_SCAN",
        }
        outbound_egress = {
            "dispatched": True,
            "destination": "Gemini 2.0 Flash (Cloud Reasoning Tier)",
            "bytes_sent": len(json.dumps(outbound_payload)),
            "sanitized_payload_preview": result.sanitized_cmd,
            "vault_tokens_used": result.vault_tokens,
            "full_egress_packet": outbound_payload,
        }

        # Step 2: Cloud Judge reasoning
        cloud_verdict = judge.judge(result.sanitized_cmd, context=context)

        # Step 3: Self-learning flywheel: push rule back to local engine
        new_rule_pattern = cloud_verdict.get("new_local_rule")
        if new_rule_pattern and cloud_verdict.get("verdict") == "BLOCK":
            rule_id = f"CLOUD_LEARNED_{abs(hash(new_rule_pattern)) % 100000:05d}"
            rule_reason = cloud_verdict.get("reason", "Cloud-derived prompt injection rule")
            success = guard.add_learned_rule(rule_id, new_rule_pattern, rule_reason)
            if success:
                flywheel_rule_added = True
                new_rule_details = {
                    "id": rule_id,
                    "pattern": new_rule_pattern,
                    "reason": rule_reason,
                    "source": "Gemini 2.0 Flash Synthesis",
                }
    else:
        # Zero network egress
        outbound_egress = {
            "dispatched": False,
            "destination": "NONE (Processed 100% On-Edge)",
            "bytes_sent": 0,
            "sanitized_payload_preview": "[ZERO BYTES TRANSMITTED TO CLOUD]",
            "vault_tokens_used": result.vault_tokens,
            "full_egress_packet": {
                "status": "LOCAL_EXECUTION_ONLY",
                "network_egress": "0 bytes",
                "privacy_guarantee": "All inspection occurred within local process memory.",
            },
        }

    total_time_ms = round((time.perf_counter() - t_start) * 1000, 2)

    # Determine final compound verdict
    if result.decision == "CANARY_BLOCK":
        final_verdict = "CANARY_BLOCK"
    elif cloud_escalated and cloud_verdict:
        final_verdict = "CLOUD_BLOCK" if cloud_verdict.get("verdict") == "BLOCK" else "CLOUD_ALLOW"
    else:
        final_verdict = "LOCAL_ALLOW" if result.decision == "ALLOW" else "LOCAL_BLOCK"

    # Fetch newest audit entry for response
    records = _load_audit_records()
    latest_audit = records[-1] if records else None

    # Count updated rules
    learned_count = 0
    if LEARNED_RULES_FILE.exists():
        try:
            learned_count = len(json.loads(LEARNED_RULES_FILE.read_text(encoding="utf-8")))
        except Exception:
            learned_count = 0

    return {
        "final_verdict": final_verdict,
        "local_decision": result.decision,
        "local_latency_ms": result.latency_ms,
        "total_latency_ms": total_time_ms,
        "original_cmd": result.original_cmd,
        "sanitized_cmd": result.sanitized_cmd,
        "matched_rule_id": result.matched_rule_id,
        "reason": result.reason,
        "canary_triggered": result.canary_triggered,
        "vault_tokens": result.vault_tokens,
        "cloud_escalated": cloud_escalated,
        "cloud_verdict": cloud_verdict,
        "flywheel_rule_added": flywheel_rule_added,
        "new_rule_details": new_rule_details,
        "outbound_egress": outbound_egress,
        "latest_audit": latest_audit,
        "active_rules_count": len(BUILTIN_BLOCK_RULES) + learned_count,
    }


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------

def run_server(host: str = "0.0.0.0", port: int = 8080):
    banner = f"""
====================================================================
🛡️   AIRLOCK INTERACTIVE WEB DASHBOARD
====================================================================
  Status:  Running on http://localhost:{port} (all interfaces {host}:{port})
  Engine:  LocalGuard (deterministic) + CloudJudge (Gemini Flash)
  Audit:   Cryptographic SHA-256 Hash Chained ({AUDIT_LOG_FILE.name})
  Target:  Devpost Demo & Live Interactive Evaluation
====================================================================
"""
    print(banner)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    host = os.environ.get("HOST", "0.0.0.0")
    run_server(host=host, port=port)
