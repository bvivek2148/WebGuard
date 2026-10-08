import os
import sys
import math
import time
import json
import asyncio
import urllib.parse
from collections import deque, defaultdict
from contextlib import asynccontextmanager
from typing import Dict, List, Set, Optional

# Ensure stdout handles UTF-8 and ANSI escape codes on Windows
if os.name == 'nt':
    os.system('')
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import database

import joblib
import httpx
import numpy as np
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ============================================================================
# 1. Global State & Configurations
# ============================================================================

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.joblib")
RF_MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.joblib")

vectorizer = None
rf_model = None

# Default System Settings
settings = {
    "waf_mode": "blocking",  # "blocking" or "detection"
    "target_url": "http://localhost:8080",
    "blocking_threshold": 0.80,
    "rate_limit_rpm": 100
}

# In-Memory Security Fast-Paths
blacklisted_ips: Set[str] = set()
blacklist_records: List[dict] = []
request_logs: List[dict] = []
rate_limit_tracker: Dict[str, deque] = defaultdict(deque)
connected_websockets: List[WebSocket] = []

ATTACK_LABELS = {
    0: "None",
    1: "SQL Injection",
    2: "Cross-Site Scripting",
    3: "Path Traversal",
    4: "Server-Side Request Forgery",
    5: "NoSQL Injection",
    6: "Remote Code Execution"
}

# ============================================================================
# 2. Shannon Entropy & ML Utility Functions
# ============================================================================

def calculate_shannon_entropy(payload: str) -> float:
    """Calculates byte variance entropy (0.0 to 8.0) to flag obfuscated/encrypted payloads."""
    if not payload:
        return 0.0
    payload_bytes = payload.encode("utf-8")
    length = len(payload_bytes)
    freq = defaultdict(int)
    for b in payload_bytes:
        freq[b] += 1
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 2)

def check_rate_limit(client_ip: str, limit_rpm: int = 100) -> bool:
    """Sliding-window rate limiter (returns True if rate limit is exceeded)."""
    now = time.time()
    timestamps = rate_limit_tracker[client_ip]
    while timestamps and timestamps[0] < now - 60:
        timestamps.popleft()
    if len(timestamps) >= limit_rpm:
        return True
    timestamps.append(now)
    return False

import re

OWASP_PATTERNS = [
    (re.compile(r"('|\")?\s*(or|and)\s+('?\w+'?|\d+)\s*=\s*('?\w+'?|\d+)", re.IGNORECASE), "SQL Injection"),
    (re.compile(r"union[\s\+]+all[\s\+]+select|union[\s\+]+select", re.IGNORECASE), "SQL Injection"),
    (re.compile(r";[\s\+]*(drop|insert|delete|update|exec|alter)[\s\+]+", re.IGNORECASE), "SQL Injection"),
    (re.compile(r"(--|#|/\*)", re.IGNORECASE), "SQL Injection"),
    (re.compile(r"<script[^>]*>|<svg[^>]*onload|<img[^>]*onerror|javascript:", re.IGNORECASE), "Cross-Site Scripting"),
    (re.compile(r"\.\./|\.\.\\|/etc/passwd|win\.ini|/WEB-INF/", re.IGNORECASE), "Path Traversal"),
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|(gopher|dict|file)://", re.IGNORECASE), "Server-Side Request Forgery"),
    (re.compile(r"\$(gt|ne|where|regex|nin|exists)\b", re.IGNORECASE), "NoSQL Injection"),
    (re.compile(r"\$\{jndi:(ldap|rmi|dns|nis):|;\s*(system|exec|passthru|shell_exec|curl|wget)\b", re.IGNORECASE), "Remote Code Execution"),
]

def load_ml_models() -> bool:
    """Loads trained Random Forest model and TF-IDF vectorizer, auto-training if missing."""
    global vectorizer, rf_model
    if vectorizer is not None and rf_model is not None:
        return True
    if os.path.exists(VECTORIZER_PATH) and os.path.exists(RF_MODEL_PATH):
        try:
            vectorizer = joblib.load(VECTORIZER_PATH)
            rf_model = joblib.load(RF_MODEL_PATH)
            print("✅ Loaded Random Forest Model & TF-IDF Vectorizer from disk.")
            return True
        except Exception as e:
            print(f"❌ Failed loading model artifacts: {e}")
            return False
    else:
        print("⚠️ Model artifacts missing. Auto-training Random Forest model now...")
        try:
            import train_model
            train_model.train_model()
            vectorizer = joblib.load(VECTORIZER_PATH)
            rf_model = joblib.load(RF_MODEL_PATH)
            print("✅ Successfully trained and loaded Random Forest model & vectorizer.")
            return True
        except Exception as e:
            print(f"❌ Auto-training failed: {e}")
            return False

def evaluate_payload_ml(query_str: str, body_str: str, path: str) -> dict:
    """Combines OWASP regex signatures and Random Forest ML classification."""
    decoded_path = urllib.parse.unquote_plus(path)
    decoded_query = urllib.parse.unquote_plus(query_str)
    decoded_body = urllib.parse.unquote_plus(body_str)
    eval_text = f"{decoded_path} {decoded_query} {decoded_body}".strip()
    raw_text = f"{path} {query_str} {body_str}".strip()

    # 1. OWASP Signature Fast-Path Check
    for pattern, attack_cat in OWASP_PATTERNS:
        if pattern.search(eval_text) or pattern.search(raw_text):
            return {
                "attack_type": attack_cat,
                "confidence": 0.99,
                "is_attack": True,
                "detection_engine": "OWASP Signature Engine"
            }

    # 2. Random Forest ML Inference
    if (vectorizer is None or rf_model is None) and not load_ml_models():
        return {"attack_type": "None", "confidence": 0.0, "is_attack": False, "detection_engine": "None"}

    if not eval_text:
        return {"attack_type": "None", "confidence": 0.0, "is_attack": False, "detection_engine": "None"}

    try:
        sample_text = eval_text[:10000]
        X_vec = vectorizer.transform([sample_text])
        probabilities = rf_model.predict_proba(X_vec)[0]
        predicted_class = int(np.argmax(probabilities))
        confidence = float(probabilities[predicted_class])

        attack_label = ATTACK_LABELS.get(predicted_class, "None")
        is_attack = (predicted_class != 0) and (confidence >= settings["blocking_threshold"])

        return {
            "attack_type": attack_label,
            "confidence": round(confidence, 4),
            "is_attack": is_attack,
            "detection_engine": "Random Forest ML Classifier"
        }
    except Exception as e:
        print(f"⚠️ ML Evaluation Error: {e}")
        return {"attack_type": "None", "confidence": 0.0, "is_attack": False, "detection_engine": "Error"}

async def broadcast_event(event_data: dict):
    """Pushes live JSON telemetry event to connected React WebSocket clients."""
    disconnected = []
    for ws in connected_websockets:
        try:
            await ws.send_json(event_data)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        if ws in connected_websockets:
            connected_websockets.remove(ws)

# ============================================================================
# 3. Lifespan Startup & Shutdown Management
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("🛡️ Initializing WebGuard AI WAF Proxy Backend (FastAPI)")
    print("=" * 60)

    database.init_db()
    db_settings = database.load_settings()
    if db_settings:
        settings.update(db_settings)
    persisted_bl = database.load_blacklist()
    for b in persisted_bl:
        blacklisted_ips.add(b["client_ip"])
    blacklist_records.extend(persisted_bl)

    if load_ml_models():
        print("🛡️ WebGuard Defense Engines Active & Armed.")
    else:
        print("⚠️ Warning: Machine learning model could not be armed.")

    yield
    print("🛑 Shutting down WebGuard Backend.")

app = FastAPI(
    title="WebGuard AI WAF & Threat Intel Server",
    description="Real-time Web Application Firewall powered by FastAPI, SQLite, WebSockets, and Scikit-Learn.",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["Health"])
@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "service": "WebGuard AI WAF & Reverse Proxy",
        "status": "operational",
        "version": "2.0.0",
        "waf_mode": settings["waf_mode"],
        "target_url": settings["target_url"],
        "ml_model_loaded": rf_model is not None,
        "db_status": "connected (SQLite WAL)",
        "active_websockets": len(connected_websockets),
        "blacklisted_ips_count": len(blacklisted_ips),
        "endpoints": {
            "proxy": "/proxy/{path}",
            "health": "/api/health",
            "settings": "/api/settings",
            "logs": "/api/logs",
            "blacklist": "/api/blacklist",
            "auth": "/api/auth/login",
            "audit_scan": "/api/audit/scan",
            "websocket": "/ws/events",
            "docs": "/docs"
        }
    }

# ============================================================================
# 4. Reverse Proxy & WAF Interceptor Engine
# ============================================================================

@app.api_route("/proxy{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def waf_reverse_proxy(request: Request, path: str = ""):
    client_ip = request.client.host if request.client else "127.0.0.1"
    start_time = time.time()

    # 1. Fast-Path IP Blacklist Check
    if client_ip in blacklisted_ips:
        log_entry = create_log_entry(request, client_ip, "Blocked (Blacklisted IP)", "Blacklisted IP", 1.0, True, 0.0)
        asyncio.create_task(broadcast_event({"event_type": "request_blocked", "log": log_entry}))
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "Access Denied by WebGuard WAF", "reason": "Client IP is Blacklisted", "client_ip": client_ip}
        )

    # 2. Sliding Window Rate Limit Check
    if check_rate_limit(client_ip, settings["rate_limit_rpm"]):
        reason = "Rate Limit Exceeded"
        blacklisted_ips.add(client_ip)
        blacklist_records.append({"client_ip": client_ip, "reason": reason, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")})
        database.add_blacklist_ip(client_ip, reason)
        log_entry = create_log_entry(request, client_ip, "Blocked (Rate Limit)", "Rate Limit Exceeded", 0.99, True, 0.0)
        asyncio.create_task(broadcast_event({"event_type": "request_blocked", "log": log_entry}))
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"error": "Too Many Requests", "reason": "Rate Limit Exceeded. IP auto-blacklisted.", "client_ip": client_ip}
        )

    # 3. Extract & Assemble Payload for ML Inspection
    query_str = str(request.query_params)
    body_str = ""
    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        pass

    full_payload = f"PATH:{path} QUERY:{query_str} BODY:{body_str} UA:{request.headers.get('user-agent', '')}"
    entropy = calculate_shannon_entropy(full_payload)
    ml_result = evaluate_payload_ml(query_str, body_str, path)

    # 4. Handle Attack Detection Logic
    is_blocked = False
    if ml_result["is_attack"]:
        if settings["waf_mode"] == "blocking":
            is_blocked = True
            reason = f"Random Forest Flagged: {ml_result['attack_type']} ({int(ml_result['confidence']*100)}% confidence)"
            blacklisted_ips.add(client_ip)
            blacklist_records.append({
                "client_ip": client_ip,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
            })
            database.add_blacklist_ip(client_ip, reason)
            log_entry = create_log_entry(request, client_ip, full_payload, ml_result["attack_type"], ml_result["confidence"], True, entropy)
            asyncio.create_task(broadcast_event({"event_type": "request_blocked", "log": log_entry}))
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Forbidden by WebGuard WAF",
                    "attack_type": ml_result["attack_type"],
                    "confidence": ml_result["confidence"],
                    "client_ip": client_ip,
                    "action": "Blocked & IP Blacklisted"
                }
            )

    # 5. Forward Clean Traffic to Target Backend URL
    target_backend = settings["target_url"].rstrip("/")
    target_path = path if (not path or path.startswith("/")) else f"/{path}"
    destination_url = f"{target_backend}{target_path}"
    if request.url.query:
        destination_url += f"?{request.url.query}"

    forward_headers = dict(request.headers)
    forward_headers["x-forwarded-for"] = client_ip
    forward_headers["x-forwarded-proto"] = request.url.scheme
    forward_headers.pop("host", None)

    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=destination_url,
                headers=forward_headers,
                content=await request.body()
            )
            latency_ms = round((time.time() - start_time) * 1000, 2)
            log_entry = create_log_entry(request, client_ip, full_payload, ml_result["attack_type"], ml_result["confidence"], is_blocked, entropy, latency_ms)
            asyncio.create_task(broadcast_event({"event_type": "request_allowed", "log": log_entry}))

            # Inject Hardening Security Headers into Response
            response_headers = dict(resp.headers)
            response_headers["X-Protected-By"] = "WebGuard-AI-WAF"
            response_headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline';"
            response_headers["X-Frame-Options"] = "SAMEORIGIN"
            response_headers["X-Content-Type-Options"] = "nosniff"

            return Response(content=resp.content, status_code=resp.status_code, headers=response_headers)

        except httpx.RequestError as e:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"error": "Bad Gateway", "message": f"WebGuard WAF cannot reach target website at {settings['target_url']}: {e}"}
            )

def create_log_entry(request: Request, client_ip: str, payload: str, attack_type: str, confidence: float, is_blocked: bool, entropy: float, latency: float = 0.0) -> dict:
    entry = {
        "id": f"log-{int(time.time()*1000)}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_ip": client_ip,
        "method": request.method,
        "path": request.url.path,
        "payload": payload[:300],
        "attack_type": attack_type,
        "confidence": confidence,
        "is_blocked": is_blocked,
        "entropy": entropy,
        "latency_ms": latency
    }
    request_logs.append(entry)
    if len(request_logs) > 500:
        request_logs.pop(0)
    database.insert_request_log(entry)
    return entry

# ============================================================================
# 5. Real-Time WebSockets Telemetry
# ============================================================================

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)

# ============================================================================
# 6. REST API Models & Controls
# ============================================================================

class SettingsUpdate(BaseModel):
    waf_mode: Optional[str] = None
    target_url: Optional[str] = None
    blocking_threshold: Optional[float] = None
    rate_limit_rpm: Optional[int] = None

class UnblockRequest(BaseModel):
    client_ip: str

class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

class AuditScanRequest(BaseModel):
    target_url: str

@app.post("/api/auth/login")
def login(body: LoginRequest):
    uname = (body.username or body.email or "").strip()
    # 1. Master SuperAdmin verification
    if (uname.lower() in ["admin@webguard.project", "admin", "admin@webguard.internal"] and body.password in ["WebGuard@Major_Project_B38", "admin123"]):
        token = f"token-admin-b38-{int(time.time()*1000)}"
        return {
            "status": "success",
            "token": token,
            "user": {
                "id": 1,
                "username": "admin@webguard.project",
                "email": "admin@webguard.project",
                "role": "SuperAdmin (Full Access)",
                "isSuperAdmin": True,
                "permissions": ["all", "waf_control", "audit", "rules", "soc_lead", "admin_vault"]
            }
        }

    # 2. Check if user exists in database
    db_user = database.authenticate_user(uname, body.password)
    if db_user:
        token = f"token-{db_user['username']}-{int(time.time()*1000)}"
        return {
            "status": "success",
            "token": token,
            "user": {
                **db_user,
                "email": f"{db_user['username']}@webguard.project" if "@" not in db_user['username'] else db_user['username'],
                "isSuperAdmin": "SuperAdmin" in db_user.get("role", ""),
                "permissions": ["all"] if "SuperAdmin" in db_user.get("role", "") else ["overview", "traffic", "audit", "sandbox"]
            }
        }

    # 3. Allow open onboarding for any credentials as Guest / Analyst
    token = f"token-guest-{int(time.time()*1000)}"
    return {
        "status": "success",
        "token": token,
        "user": {
            "id": int(time.time()),
            "username": uname if uname else "Guest User",
            "email": uname if "@" in uname else f"{uname}@user.local",
            "role": "Guest / Analyst (Limited View)",
            "isSuperAdmin": False,
            "permissions": ["overview", "traffic", "audit", "sandbox"]
        }
    }

@app.get("/api/settings")
def get_settings():
    return settings

@app.api_route("/api/settings", methods=["POST", "PUT"])
def update_settings(body: SettingsUpdate):
    if body.waf_mode and body.waf_mode in ["blocking", "detection", "off"]:
        settings["waf_mode"] = body.waf_mode
        database.save_setting("waf_mode", body.waf_mode)
    if body.target_url:
        val = body.target_url.strip()
        if val.startswith("http://") or val.startswith("https://"):
            settings["target_url"] = val
            database.save_setting("target_url", val)
    if body.blocking_threshold is not None and 0.0 <= body.blocking_threshold <= 1.0:
        settings["blocking_threshold"] = body.blocking_threshold
        database.save_setting("blocking_threshold", body.blocking_threshold)
    if body.rate_limit_rpm is not None and body.rate_limit_rpm > 0:
        settings["rate_limit_rpm"] = body.rate_limit_rpm
        database.save_setting("rate_limit_rpm", body.rate_limit_rpm)
    return {"status": "success", "settings": settings}

@app.get("/api/logs")
def get_logs():
    db_logs = database.get_recent_logs(100)
    return {"logs": db_logs if db_logs else request_logs[-100:]}

@app.get("/api/blacklist")
def get_blacklist():
    db_blacklist = database.load_blacklist()
    return {"blacklist": db_blacklist if db_blacklist else blacklist_records}

@app.post("/api/blacklist/unblock")
def unblock_ip(body: UnblockRequest):
    if body.client_ip in blacklisted_ips:
        blacklisted_ips.remove(body.client_ip)
    global blacklist_records
    blacklist_records = [r for r in blacklist_records if r["client_ip"] != body.client_ip]
    database.remove_blacklist_ip(body.client_ip)
    return {"status": "success", "unblocked": body.client_ip}

# ============================================================================
# 7. Live Vulnerability Auditor Endpoint (Before & After Scan Engine)
# ============================================================================

@app.post("/api/audit/scan")
async def scan_url_vulnerabilities(body: AuditScanRequest):
    target = body.target_url.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    findings = []
    radar = {"sqli": 10, "xss": 10, "cmdi": 10, "rateLimit": 10, "headers": 10, "csrf": 10}

    async with httpx.AsyncClient(timeout=4.0, verify=False) as client:
        try:
            resp = await client.get(target)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check Security Headers
            if "content-security-policy" not in headers:
                findings.append({"id": "v-101", "name": "Missing Content-Security-Policy (CSP)", "severity": "High", "category": "headers", "desc": "No CSP header detected. Increases vulnerability to XSS attacks."})
                radar["xss"] += 25
                radar["headers"] += 30

            if "strict-transport-security" not in headers and target.startswith("https"):
                findings.append({"id": "v-102", "name": "Missing HSTS Header", "severity": "Medium", "category": "headers", "desc": "HTTP Strict Transport Security header is missing."})
                radar["headers"] += 20

            if "x-frame-options" not in headers:
                findings.append({"id": "v-103", "name": "Missing Clickjacking Protection (X-Frame-Options)", "severity": "Medium", "category": "headers", "desc": "Site can be embedded in malicious iframes."})
                radar["csrf"] += 20

            if headers.get("access-control-allow-origin") == "*":
                findings.append({"id": "v-104", "name": "Wildcard CORS Configuration", "severity": "High", "category": "csrf", "desc": "Access-Control-Allow-Origin is set to wildcard (*)."})
                radar["csrf"] += 35

            is_shielded = "x-protected-by" in headers or "WebGuard" in headers.get("server", "")

        except Exception as e:
            findings.append({"id": "v-999", "name": "Target Connection Timeout / Unreachable", "severity": "Critical", "category": "headers", "desc": f"Unable to establish HTTP handshake with target: {e}"})
            is_shielded = False

    # Calculate overall security posture score
    max_penalty = sum(radar.values()) - 60
    posture_score = max(5, 100 - max_penalty)
    if is_shielded:
        posture_score = 98
        radar = {"sqli": 5, "xss": 5, "cmdi": 5, "rateLimit": 5, "headers": 5, "csrf": 5}

    return {
        "target_url": target,
        "is_shielded_by_webguard": is_shielded,
        "posture_score": posture_score,
        "radar_scores": radar,
        "findings": findings,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }

# ============================================================================
# 8. Google Gemini AI Generative Copilot & Remediation Engine
# ============================================================================

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AQ.Ab8RN6LBzyLlgqKFTdCyyx91ndzjZ8GXLTntCX7gQsY2zanjbw")

class CopilotChatRequest(BaseModel):
    message: str
    context: Optional[dict] = None

class CopilotExplainRequest(BaseModel):
    payload: str
    attack_type: str
    path: str
    method: str = "GET"

@app.post("/api/copilot/chat")
async def copilot_chat(body: CopilotChatRequest):
    """Answers security questions and SOC queries using Google Gemini 2.5 Flash."""
    context_str = ""
    if body.context:
        context_str = f"\nRelevant Threat Context: {json.dumps(body.context)}"

    prompt = f"""You are WebGuard AI Copilot, an elite cybersecurity and SOC defense specialist.
Provide clear, actionable, professional cybersecurity guidance. Keep explanations crisp, practical, and provide code or configuration snippets when relevant.
{context_str}

User Question: {body.message}
"""
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
        try:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                reply_text = data["candidates"][0]["content"]["parts"][0]["text"]
                return {"status": "success", "reply": reply_text, "model": "gemini-2.5-flash"}
            else:
                return {"status": "error", "reply": f"Gemini API error ({resp.status_code}): {resp.text[:200]}"}
        except Exception as e:
            return {"status": "error", "reply": f"Failed to connect to Gemini AI: {type(e).__name__} {e}"}

@app.post("/api/copilot/explain")
async def copilot_explain(body: CopilotExplainRequest):
    """Generates full incident triage with Gemini AI: Threat Summary, Root Cause, Code Patch, and Custom WAF Rule."""
    prompt = f"""Analyze this intercepted cyber attack detected by WebGuard AI WAF:
- Attack Type: {body.attack_type}
- HTTP Method: {body.method}
- Target Path: {body.path}
- Malicious Payload: {body.payload}

Provide a structured, executive-level triage report in markdown. Keep each section concise (2-3 sentences each):
1. **Threat Summary**: What is the attacker attempting to achieve?
2. **Technical Impact**: What systems would be compromised if not blocked?
3. **Recommended Code Remediation**: Brief code snippet (Python or JS) showing proper input sanitization or parameterization.
4. **Custom WAF Defense Rule**: A regex or ModSecurity rule to block variations.
"""
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "maxOutputTokens": 700,
            "temperature": 0.2
        }
    }

    async with httpx.AsyncClient(timeout=httpx.Timeout(45.0, connect=10.0)) as client:
        try:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                analysis = data["candidates"][0]["content"]["parts"][0]["text"]
                return {"status": "success", "analysis": analysis, "model": "gemini-2.5-flash"}
            else:
                return {"status": "error", "analysis": f"Gemini API error ({resp.status_code}): {resp.text[:200]}"}
        except Exception as e:
            return {"status": "error", "analysis": f"Failed to reach Gemini AI: {type(e).__name__} {e}"}

if __name__ == "__main__":
    import uvicorn
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True, reload_dirs=[backend_dir], app_dir=backend_dir)
