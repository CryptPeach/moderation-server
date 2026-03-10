
import io, os, hashlib, datetime, asyncio, uuid
from contextlib import asynccontextmanager

import httpx
import imagehash
import magic
from PIL import Image
from nudenet import NudeDetector

from fastapi import FastAPI, File, UploadFile, HTTPException, Header, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from supabase import create_client, Client

# ── ENV ───────────────────────────────────────────────────────────────────────
SUPABASE_URL     = os.environ["SUPABASE_URL"]
SUPABASE_KEY     = os.environ["SUPABASE_SERVICE_KEY"]
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
ADMIN_SECRET     = os.environ.get("ADMIN_SECRET", "change-me")

# ── Clients ───────────────────────────────────────────────────────────────────
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
detector         = NudeDetector()
limiter          = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app):
    yield

app = FastAPI(title="Moderation Server", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Constants ─────────────────────────────────────────────────────────────────
VIOLATION_THRESHOLD = 3       # auto-ban after N NSFW uploads
PHASH_THRESHOLD     = 10      # hamming distance for near-duplicate images
MAX_FILE_SIZE       = 5 * 1024 * 1024
ALLOWED_MIME_TYPES  = {"image/jpeg", "image/png", "image/webp", "image/gif"}
UNSAFE_LABELS       = {
    "EXPOSED_BREAST_F", "EXPOSED_GENITALIA_F", "EXPOSED_GENITALIA_M",
    "EXPOSED_BUTTOCKS", "EXPOSED_ANUS",
}
AUTO_REPORT_THRESHOLD = 5     # auto-ban after N unique reporters

# ── Async job store ───────────────────────────────────────────────────────────
job_store: dict = {}

def now_ms() -> int:
    """Current time as Unix milliseconds (matches your bigint timestamps)."""
    return int(datetime.datetime.utcnow().timestamp() * 1000)


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════════════════════
# SUPABASE HELPERS — mapped to YOUR schema
# ══════════════════════════════════════════════════════════════════════════════

# ── Ban helpers ───────────────────────────────────────────────────────────────

def db_is_banned(user_id: str) -> bool:
    """Check users.is_banned — the authoritative ban flag."""
    r = supabase.table("users").select("is_banned").eq("user_id", user_id).single().execute()
    return r.data.get("is_banned", False) if r.data else False

def db_ban_user(user_id: str, reason: str):
    """
    Ban a user:
      - users.is_banned = true
      - user_private.ban_reason = reason  (your trg_sync_ban trigger keeps them in sync)
    """
    supabase.table("users").update({"is_banned": True}).eq("user_id", user_id).execute()
    supabase.table("user_private").update({
        "ban_reason": reason,
        "ban_until":  None,          # NULL = permanent
    }).eq("user_id", user_id).execute()
    db_audit(user_id, "ban", reason)
    asyncio.create_task(telegram_alert(f"🔨 *User Banned*\nUser: `{user_id}`\nReason: {reason}"))

def db_unban_user(user_id: str):
    supabase.table("users").update({"is_banned": False}).eq("user_id", user_id).execute()
    supabase.table("user_private").update({"ban_reason": None, "ban_until": None}).eq("user_id", user_id).execute()
    db_audit(user_id, "unban", "Admin unban")

# ── Violation counter (uses user_private.report_count as violation proxy) ────

def db_record_violation(user_id: str) -> int:
    """
    Increments user_private.report_count.
    Auto-bans when VIOLATION_THRESHOLD is reached.
    Returns new count.
    """
    r = supabase.table("user_private").select("report_count").eq("user_id", user_id).single().execute()
    count = (r.data.get("report_count") or 0) + 1
    supabase.table("user_private").update({"report_count": count}).eq("user_id", user_id).execute()
    if count >= VIOLATION_THRESHOLD and not db_is_banned(user_id):
        db_ban_user(user_id, f"Auto-banned: {count} NSFW violations")
    return count

# ── Image hash cache (new table — see schema_addon.sql) ──────────────────────

def db_hash_lookup(key: str):
    r = supabase.table("hash_cache").select("*").eq("hash_key", key).execute()
    return r.data[0] if r.data else None

def db_hash_store(md5_key: str, phash_key: str, safe: bool, confidence: float):
    rec = {"safe": safe, "confidence": confidence, "hits": 1, "cached_at": now_ms()}
    supabase.table("hash_cache").upsert({**rec, "hash_key": md5_key}).execute()
    supabase.table("hash_cache").upsert({**rec, "hash_key": phash_key}).execute()

def db_hash_bump(key: str):
    r = supabase.table("hash_cache").select("hits").eq("hash_key", key).execute()
    if r.data:
        supabase.table("hash_cache").update({
            "hits": r.data[0]["hits"] + 1,
            "last_seen": now_ms(),
        }).eq("hash_key", key).execute()

def db_find_similar_phash(new_phash: str):
    r = supabase.table("hash_cache").select("*").like("hash_key", "phash:%").execute()
    for row in r.data:
        try:
            a = imagehash.hex_to_hash(new_phash.replace("phash:", ""))
            b = imagehash.hex_to_hash(row["hash_key"].replace("phash:", ""))
            if (a - b) <= PHASH_THRESHOLD:
                return row
        except Exception:
            continue
    return None

# ── Audit log (new table) ─────────────────────────────────────────────────────

def db_audit(user_id: str, action: str, detail: str = ""):
    supabase.table("audit_log").insert({
        "user_id":   user_id,
        "action":    action,
        "detail":    detail,
        "timestamp": now_ms(),
    }).execute()

# ── Reports — mapped to YOUR reports table ────────────────────────────────────

def db_insert_report(reporter_id: str, reported_user_id: str, reason: str, description: str = ""):
    supabase.table("reports").insert({
        "reporter_id":      reporter_id,
        "reported_user_id": reported_user_id,
        "reason":           reason,
        "description":      description,
        "status":           "pending",
        "timestamp":        now_ms(),
    }).execute()

def db_count_unique_reporters(reported_user_id: str) -> int:
    r = supabase.table("reports").select("reporter_id").eq("reported_user_id", reported_user_id).execute()
    return len({row["reporter_id"] for row in r.data})

# ── Blocks — mapped to YOUR blocks table ─────────────────────────────────────

def db_block(blocker_id: str, blocked_id: str, reason: str = ""):
    supabase.table("blocks").upsert({
        "blocker_id": blocker_id,
        "blocked_id": blocked_id,
        "reason":     reason,
        "created_at": now_ms(),
    }).execute()

def db_unblock(blocker_id: str, blocked_id: str):
    supabase.table("blocks").delete() \
        .eq("blocker_id", blocker_id) \
        .eq("blocked_id", blocked_id) \
        .execute()

def db_get_blocked(blocker_id: str) -> list:
    r = supabase.table("blocks").select("blocked_id, reason, created_at") \
        .eq("blocker_id", blocker_id).execute()
    return r.data


# ══════════════════════════════════════════════════════════════════════════════
# TELEGRAM
# ══════════════════════════════════════════════════════════════════════════════

async def telegram_alert(msg: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        async with httpx.AsyncClient() as c:
            await c.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=5,
            )
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# FILE VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_image(contents: bytes) -> Image.Image:
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(413, "File too large — max 5 MB")
    real_mime = magic.from_buffer(contents, mime=True)
    if real_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(415, f"Unsupported type: {real_mime}")
    try:
        return Image.open(io.BytesIO(contents)).convert("RGB")
    except Exception:
        raise HTTPException(400, "Corrupt or unreadable image")


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN GUARD
# ══════════════════════════════════════════════════════════════════════════════

def require_admin(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(401, "Unauthorized")


# ══════════════════════════════════════════════════════════════════════════════
# DETECT — ASYNC (recommended)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/detect/async")
@limiter.limit("10/minute")
async def detect_async(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    x_user_id: str = Header(default="anonymous"),
):
    if db_is_banned(x_user_id):
        raise HTTPException(403, "User is banned")

    contents = await file.read()
    img      = validate_image(contents)
    job_id   = str(uuid.uuid4())
    job_store[job_id] = {"status": "processing", "result": None}

    background_tasks.add_task(_run_detection, job_id, contents, img, x_user_id)
    db_audit(x_user_id, "detect_submitted", f"job={job_id}")
    return {"job_id": job_id, "status": "processing"}


async def _run_detection(job_id: str, contents: bytes, img: Image.Image, user_id: str):
    md5_key   = "md5:"   + hashlib.md5(contents).hexdigest()
    phash_key = "phash:" + str(imagehash.phash(img))

    # 1. Exact cache hit
    cached = db_hash_lookup(md5_key)
    if cached:
        db_hash_bump(md5_key)
        if not cached["safe"]:
            db_record_violation(user_id)
        job_store[job_id] = {"status": "done", "result": {
            "safe":        cached["safe"],
            "confidence":  cached["confidence"],
            "source":      "cache_exact",
            "user_banned": db_is_banned(user_id),
        }}
        return

    # 2. Near-duplicate cache hit
    similar = db_find_similar_phash(phash_key)
    if similar:
        db_hash_bump(similar["hash_key"])
        if not similar["safe"]:
            db_record_violation(user_id)
        job_store[job_id] = {"status": "done", "result": {
            "safe":        similar["safe"],
            "confidence":  similar["confidence"],
            "source":      "cache_similar",
            "user_banned": db_is_banned(user_id),
        }}
        return

    # 3. Fresh NudeNet scan
    img_path = f"/tmp/{user_id}_{job_id}.jpg"
    img.save(img_path)
    detections  = detector.detect(img_path)
    os.remove(img_path)

    unsafe_hits = [d for d in detections if d["class"] in UNSAFE_LABELS]
    confidence  = max((d["score"] for d in unsafe_hits), default=0.0)
    is_safe     = len(unsafe_hits) == 0 or confidence < 0.5

    db_hash_store(md5_key, phash_key, is_safe, round(confidence, 4))

    violations = 0
    if not is_safe:
        violations = db_record_violation(user_id)
        await telegram_alert(
            f"🚨 *NSFW Detected*\nUser: `{user_id}`\n"
            f"Confidence: {confidence:.0%}\nViolations: {violations}/{VIOLATION_THRESHOLD}"
        )

    job_store[job_id] = {"status": "done", "result": {
        "safe":        is_safe,
        "confidence":  round(confidence, 4),
        "violations":  violations,
        "source":      "nudenet",
        "user_banned": db_is_banned(user_id),
    }}
    db_audit(user_id, "detect_complete", f"safe={is_safe} conf={confidence:.2f}")


@app.get("/detect/result/{job_id}")
async def detect_result(job_id: str):
    job = job_store.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


# ══════════════════════════════════════════════════════════════════════════════
# DETECT — SYNC
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/detect")
@limiter.limit("10/minute")
async def detect_sync(
    request: Request,
    file: UploadFile = File(...),
    x_user_id: str = Header(default="anonymous"),
):
    if db_is_banned(x_user_id):
        raise HTTPException(403, "User is banned")

    contents  = await file.read()
    img       = validate_image(contents)
    md5_key   = "md5:"   + hashlib.md5(contents).hexdigest()
    phash_key = "phash:" + str(imagehash.phash(img))

    cached = db_hash_lookup(md5_key)
    if cached:
        db_hash_bump(md5_key)
        if not cached["safe"]: db_record_violation(x_user_id)
        return {**cached, "source": "cache_exact", "user_banned": db_is_banned(x_user_id)}

    similar = db_find_similar_phash(phash_key)
    if similar:
        db_hash_bump(similar["hash_key"])
        if not similar["safe"]: db_record_violation(x_user_id)
        return {**similar, "source": "cache_similar", "user_banned": db_is_banned(x_user_id)}

    img_path = f"/tmp/{x_user_id}_sync.jpg"
    img.save(img_path)
    detections  = detector.detect(img_path)
    os.remove(img_path)

    unsafe_hits = [d for d in detections if d["class"] in UNSAFE_LABELS]
    confidence  = max((d["score"] for d in unsafe_hits), default=0.0)
    is_safe     = len(unsafe_hits) == 0 or confidence < 0.5

    db_hash_store(md5_key, phash_key, is_safe, round(confidence, 4))

    violations = 0
    if not is_safe:
        violations = db_record_violation(x_user_id)
        await telegram_alert(
            f"🚨 *NSFW*\nUser: `{x_user_id}`\nConf: {confidence:.0%}\nViolations: {violations}/{VIOLATION_THRESHOLD}"
        )

    db_audit(x_user_id, "detect", f"safe={is_safe}")
    return {
        "safe":        is_safe,
        "confidence":  round(confidence, 4),
        "violations":  violations,
        "source":      "nudenet",
        "user_banned": db_is_banned(x_user_id),
    }


# ══════════════════════════════════════════════════════════════════════════════
# REPORT — uses your reports table exactly
# ══════════════════════════════════════════════════════════════════════════════

class ReportRequest(BaseModel):
    reporter_id:      str
    reported_user_id: str           # matches your column name
    reason:           str           # required in your schema
    description:      str = ""      # optional in your schema

@app.post("/report")
@limiter.limit("5/minute")
async def report_user(request: Request, req: ReportRequest):
    if db_is_banned(req.reporter_id):
        raise HTTPException(403, "Banned users cannot submit reports")

    # Prevent duplicate reports from same user
    existing = supabase.table("reports") \
        .select("report_id") \
        .eq("reporter_id", req.reporter_id) \
        .eq("reported_user_id", req.reported_user_id) \
        .execute()
    if existing.data:
        raise HTTPException(409, "You already reported this user")

    db_insert_report(req.reporter_id, req.reported_user_id, req.reason, req.description)
    db_audit(req.reporter_id, "report", f"reported={req.reported_user_id} reason={req.reason}")

    # Increment report_count in user_private
    r = supabase.table("user_private").select("report_count").eq("user_id", req.reported_user_id).single().execute()
    new_count = (r.data.get("report_count") or 0) + 1
    supabase.table("user_private").update({"report_count": new_count}).eq("user_id", req.reported_user_id).execute()

    # Auto-ban if too many unique reporters
    unique_reporters = db_count_unique_reporters(req.reported_user_id)
    reported_banned  = False
    if unique_reporters >= AUTO_REPORT_THRESHOLD and not db_is_banned(req.reported_user_id):
        db_ban_user(req.reported_user_id, f"Auto-banned: {unique_reporters} reports")
        reported_banned = True
        await telegram_alert(
            f"🚨 *Auto-Ban via Reports*\nUser: `{req.reported_user_id}`\nReporters: {unique_reporters}"
        )

    return {
        "success":         True,
        "total_reporters": unique_reporters,
        "reported_banned": reported_banned,
    }


# ══════════════════════════════════════════════════════════════════════════════
# BLOCK — uses your blocks table exactly
# ══════════════════════════════════════════════════════════════════════════════

class BlockRequest(BaseModel):
    blocker_id: str      # matches your column name
    blocked_id: str      # matches your column name
    reason:     str = ""

@app.post("/block")
async def block_user(req: BlockRequest):
    if req.blocker_id == req.blocked_id:
        raise HTTPException(400, "Cannot block yourself")   # mirrors your no_self_block constraint
    db_block(req.blocker_id, req.blocked_id, req.reason)
    db_audit(req.blocker_id, "block", f"blocked={req.blocked_id}")
    return {"success": True}

@app.delete("/block")
async def unblock_user(req: BlockRequest):
    db_unblock(req.blocker_id, req.blocked_id)
    db_audit(req.blocker_id, "unblock", f"unblocked={req.blocked_id}")
    return {"success": True}

@app.get("/block/{blocker_id}")
async def get_blocked(blocker_id: str):
    return {"blocked_users": db_get_blocked(blocker_id)}


# ══════════════════════════════════════════════════════════════════════════════
# APPEAL — uses new appeals table (schema_addon.sql)
# ══════════════════════════════════════════════════════════════════════════════

class AppealRequest(BaseModel):
    user_id: str
    message: str

@app.post("/appeal")
@limiter.limit("2/hour")
async def submit_appeal(request: Request, req: AppealRequest):
    existing = supabase.table("appeals") \
        .select("id") \
        .eq("user_id", req.user_id) \
        .eq("status", "pending") \
        .execute()
    if existing.data:
        raise HTTPException(429, "You already have a pending appeal")

    supabase.table("appeals").insert({
        "user_id":      req.user_id,
        "message":      req.message,
        "status":       "pending",
        "submitted_at": now_ms(),
    }).execute()
    db_audit(req.user_id, "appeal_submitted", req.message[:100])
    await telegram_alert(f"📋 *New Appeal*\nUser: `{req.user_id}`\n{req.message[:200]}")
    return {"success": True, "message": "Appeal submitted. We'll review within 48 hours."}


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/admin/stats")
async def admin_stats(admin_secret: str = Header(...)):
    require_admin(admin_secret)

    # Count from YOUR tables
    banned   = supabase.table("users").select("user_id", count="exact").eq("is_banned", True).execute()
    reports  = supabase.table("reports").select("report_id", count="exact").eq("status", "pending").execute()
    appeals  = supabase.table("appeals").select("id", count="exact").eq("status", "pending").execute()
    cache    = supabase.table("hash_cache").select("hits").execute()

    return {
        "active_bans":      banned.count,
        "pending_reports":  reports.count,
        "pending_appeals":  appeals.count,
        "cache_entries":    len(cache.data),
        "total_cache_hits": sum(r["hits"] for r in cache.data),
    }


@app.get("/admin/reports")
async def admin_reports(admin_secret: str = Header(...)):
    require_admin(admin_secret)
    # Join with users to get names
    r = supabase.table("reports") \
        .select("*, reporter:reporter_id(name, main_photo_url), reported:reported_user_id(name, main_photo_url)") \
        .eq("status", "pending") \
        .order("timestamp", desc=True) \
        .execute()
    return r.data

@app.patch("/admin/reports/{report_id}")
async def review_report(report_id: int, action: str = "reviewed", admin_secret: str = Header(...)):
    require_admin(admin_secret)
    # action: "reviewed" | "actioned" | "dismissed"
    supabase.table("reports").update({"status": action}).eq("report_id", report_id).execute()
    return {"success": True}


@app.get("/admin/banned")
async def admin_banned(admin_secret: str = Header(...)):
    require_admin(admin_secret)
    # Join users + user_private to show ban reason
    r = supabase.table("users") \
        .select("user_id, name, main_photo_url, user_private(ban_reason, report_count)") \
        .eq("is_banned", True) \
        .is_("deleted_at", None) \
        .order("updated_at", desc=True) \
        .execute()
    return r.data

@app.post("/admin/ban/{user_id}")
async def manual_ban(user_id: str, reason: str = "Manual ban", admin_secret: str = Header(...)):
    require_admin(admin_secret)
    db_ban_user(user_id, reason)
    return {"success": True}

@app.delete("/admin/ban/{user_id}")
async def unban(user_id: str, admin_secret: str = Header(...)):
    require_admin(admin_secret)
    db_unban_user(user_id)
    return {"success": True}


@app.get("/admin/appeals")
async def admin_appeals(admin_secret: str = Header(...)):
    require_admin(admin_secret)
    r = supabase.table("appeals") \
        .select("*") \
        .eq("status", "pending") \
        .order("submitted_at", desc=True) \
        .execute()
    return r.data

@app.patch("/admin/appeals/{appeal_id}")
async def resolve_appeal(appeal_id: str, action: str, admin_secret: str = Header(...)):
    require_admin(admin_secret)
    if action not in ("approve", "deny"):
        raise HTTPException(400, "action must be 'approve' or 'deny'")

    appeal = supabase.table("appeals").select("*").eq("id", appeal_id).execute()
    if not appeal.data:
        raise HTTPException(404, "Appeal not found")

    user_id = appeal.data[0]["user_id"]
    supabase.table("appeals").update({
        "status":      "approved" if action == "approve" else "denied",
        "resolved_at": now_ms(),
    }).eq("id", appeal_id).execute()

    if action == "approve":
        db_unban_user(user_id)
        await telegram_alert(f"✅ *Appeal Approved*\nUser `{user_id}` unbanned")
    else:
        db_audit(user_id, "appeal_denied")
        await telegram_alert(f"❌ *Appeal Denied*\nUser `{user_id}`")

    return {"success": True}


@app.get("/admin/audit")
async def admin_audit(admin_secret: str = Header(...), limit: int = 100):
    require_admin(admin_secret)
    r = supabase.table("audit_log") \
        .select("*") \
        .order("timestamp", desc=True) \
        .limit(limit) \
        .execute()
    return r.data


@app.delete("/admin/cache")
async def clear_cache(admin_secret: str = Header(...)):
    require_admin(admin_secret)
    supabase.table("hash_cache").delete().neq("hash_key", "").execute()
    return {"success": True}


@app.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard():
    with open("dashboard.html") as f:
        return f.read()
