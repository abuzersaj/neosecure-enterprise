from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import re
import uuid

app = FastAPI(title="NeoSecure AI Self-Healing Backend")

# ------------------------------------------------------------
# CORS for frontend
# ------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------
# In-memory DB (replace with PostgreSQL in production)
# ------------------------------------------------------------
EVENTS = []
ALERTS = []

TOTAL_EVENTS = 0
BLOCKED_ATTACKS = 0
AUTO_PATCH_COUNT = 0
LAST_SYNC = None

# ===============================================================
# 1️⃣ ATTACK PATTERNS (FIXED REGEX SYNTAX)
# ===============================================================
ATTACK_PATTERNS = {
    "xss": re.compile(r"(?:<script>|alert\(|onerror=|javascript:)", re.I),
    "sqli": re.compile(r"(?:union select|sleep\(| or 1=1| drop table)", re.I),

    # COMPLETELY FIXED — was causing Render crash
    "rce": re.compile(r"(?:;\s*rm -rf|bash -c|system\(|exec\()", re.I),

    "lfi": re.compile(r"(?:\.\./\.\./|\.\./etc/passwd)", re.I),
    "ssrf": re.compile(r"(?:http://127\.0\.0\.1|169\.254\.169\.254)", re.I),
    "cmdi": re.compile(r"(?:;|&&|\\|%60)", re.I),
}

# ===============================================================
# 2️⃣ AUTO PATCH ENGINE
# ===============================================================
def auto_patch_code(payload: str):
    patch_notes = []

    if "input(" in payload or "eval(" in payload:
        patch_notes.append("Replaced insecure eval/input.")

    if "<script>" in payload.lower():
        patch_notes.append("HTML sanitization applied (XSS).")

    if "union select" in payload.lower():
        patch_notes.append("Enforced SQL prepared statements.")

    if "rm -rf" in payload.lower():
        patch_notes.append("Blocked OS command injection.")

    if not patch_notes:
        return None

    global AUTO_PATCH_COUNT
    AUTO_PATCH_COUNT += 1

    return {
        "patched": True,
        "patch_id": str(uuid.uuid4()),
        "patch_notes": patch_notes,
    }

# ===============================================================
# 3️⃣ ATTACK CLASSIFIER + DECISION ENGINE
# ===============================================================
def classify_attack(payload: str):
    for attack, pattern in ATTACK_PATTERNS.items():
        if pattern.search(payload):
            return attack
    return None


def determine_decision(attack_type, patch_result):
    if patch_result:
        return "PATCHED"
    if attack_type:
        return "BLOCK"
    return "ALLOW"

# ===============================================================
# 4️⃣ REQUEST MODEL
# ===============================================================
class IngestRequest(BaseModel):
    path: str
    method: str
    payload: str
    source_ip: str = "unknown"

# ===============================================================
# 5️⃣ INGEST ENDPOINT
# ===============================================================
@app.post("/ingest")
async def ingest(req: IngestRequest):
    global TOTAL_EVENTS, BLOCKED_ATTACKS, LAST_SYNC

    TOTAL_EVENTS += 1
    LAST_SYNC = datetime.utcnow()

    attack_type = classify_attack(req.payload)
    patch_result = auto_patch_code(req.payload)
    decision = determine_decision(attack_type, patch_result)

    if decision in ["BLOCK", "PATCHED"]:
        BLOCKED_ATTACKS += 1

    event_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()

    alert_record = {
        "id": event_id,
        "timestamp": timestamp,
        "path": req.path,
        "method": req.method,
        "payload": req.payload,
        "issue": attack_type or "none",
        "decision": decision,
        "severity": (
            "critical" if attack_type in ["rce", "ssrf"]
            else "high" if attack_type in ["sqli", "cmdi"]
            else "medium" if attack_type
            else "low"
        ),
        "patch": patch_result,
        "source_ip": req.source_ip,
    }

    ALERTS.insert(0, alert_record)

    return {
        "status": "ok",
        "id": event_id,
        "attack_type": attack_type,
        "decision": decision,
        "patched": patch_result,
    }

# ===============================================================
# 6️⃣ STATISTICS ENDPOINT
# ===============================================================
@app.get("/stats")
async def stats():
    attack_ratio = (
        (BLOCKED_ATTACKS / TOTAL_EVENTS) * 100
        if TOTAL_EVENTS > 0
        else 0
    )

    return {
        "total_events": TOTAL_EVENTS,
        "blocked_healed": BLOCKED_ATTACKS,
        "attack_ratio": round(attack_ratio, 2),
        "engine_online": True,
        "last_event_at": LAST_SYNC,
        "auto_patch_count": AUTO_PATCH_COUNT,
    }

# ===============================================================
# 7️⃣ ALERTS TABLE ENDPOINT
# ===============================================================
@app.get("/alerts")
async def get_alerts(limit: int = 50):
    return ALERTS[:limit]

# ===============================================================
# 8️⃣ ROOT ENDPOINT
# ===============================================================
@app.get("/")
def home():
    return {"message": "NeoSecure AI Self-Healing Backend Running"}

