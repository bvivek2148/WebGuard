import os
import sys
import math
import time
import json
import asyncio
from collections import deque, defaultdict
from contextlib import asynccontextmanager
from typing import Dict, List, Set, Optional

# Ensure stdout handles UTF-8 on Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

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

ATTACK_LABELS = {0: "None", 1: "SQL Injection", 2: "Cross-Site Scripting", 3: "Path Traversal"}

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
    (re.compile(r"('|\")\s*(or|and)\s*('|\"|\d|\w)\s*=\s*('|\"|\d|\w)", re.IGNORECASE), "SQL Injection"),
    (re.compile(r"union\s+all\s+select|union\s+select", re.IGNORECASE), "SQL Injection"),
    (re.compile(r";\s*(drop|insert|delete|update|exec|alter)\s+", re.IGNORECASE), "SQL Injection"),
    (re.compile(r"(--|#|/\*)\s*", re.IGNORECASE), "SQL Injection"),
    (re.compile(r"<script[^>]*>|<svg[^>]*onload|<img[^>]*onerror|javascript:", re.IGNORECASE), "Cross-Site Scripting"),
    (re.compile(r"\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|win\.ini", re.IGNORECASE), "Path Traversal"),
]

def evaluate_payload_ml(query_str: str, body_str: str, path: str) -> dict:
    """Combines OWASP regex signatures and Random Forest ML classification."""
    eval_text = f"{path} {query_str} {body_str}".strip()

    # 1. OWASP Signature Fast-Path Check
    for pattern, attack_cat in OWASP_PATTERNS:
        if pattern.search(eval_text):
            return {
                "attack_type": attack_cat,
                "confidence": 0.99,
                "is_attack": True,
                "detection_engine": "OWASP Signature Engine"
            }

    # 2. Random Forest ML Inference
    if not vectorizer or not rf_model or not eval_text:
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
    global vectorizer, rf_model
    print("=" * 60)
    print("🛡️ Initializing WebGuard AI WAF Proxy Backend (FastAPI)")
    print("=" * 60)

    if os.path.exists(VECTORIZER_PATH) and os.path.exists(RF_MODEL_PATH):
        try:
            vectorizer = joblib.load(VECTORIZER_PATH)
            rf_model = joblib.load(RF_MODEL_PATH)
            print("✅ Loaded Random Forest Model & TF-IDF Vectorizer from disk.")
        except Exception as e:
            print(f"❌ Failed loading model artifacts: {e}")
    else:
        print("⚠️ Model files not found! Run 'python train_model.py' to generate artifacts.")

    yield
    print("🛑 Shutting down WebGuard Backend.")

app = FastAPI(title="WebGuard AI WAF & Threat Intel Server", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
        blacklisted_ips.add(client_ip)
        blacklist_records.append({"client_ip": client_ip, "reason": "Rate Limit Exceeded", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")})
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
            blacklisted_ips.add(client_ip)
            blacklist_records.append({
                "client_ip": client_ip,
                "reason": f"Random Forest Flagged: {ml_result['attack_type']} ({int(ml_result['confidence']*100)}% confidence)",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
            })
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
    destination_url = f"{target_backend}{path}"
    if request.url.query:
        destination_url += f"?{request.url.query}"

    forward_headers = dict(request.headers)
    forward_headers["x-forwarded-for"] = client_ip
    forward_headers["x-forwarded-proto"] = request.url.scheme
    forward_headers.pop("host", None)

    async with httpx.AsyncClient(timeout=5.0) as client:
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

class AuditScanRequest(BaseModel):
    target_url: str

@app.get("/api/settings")
def get_settings():
    return settings

@app.post("/api/settings")
def update_settings(body: SettingsUpdate):
    if body.waf_mode:
        settings["waf_mode"] = body.waf_mode
    if body.target_url:
        settings["target_url"] = body.target_url
    if body.blocking_threshold is not None:
        settings["blocking_threshold"] = body.blocking_threshold
    if body.rate_limit_rpm is not None:
        settings["rate_limit_rpm"] = body.rate_limit_rpm
    return {"status": "success", "settings": settings}

@app.get("/api/logs")
def get_logs():
    return {"logs": request_logs[-100:]}

@app.get("/api/blacklist")
def get_blacklist():
    return {"blacklist": blacklist_records}

@app.post("/api/blacklist/unblock")
def unblock_ip(body: UnblockRequest):
    if body.client_ip in blacklisted_ips:
        blacklisted_ips.remove(body.client_ip)
    global blacklist_records
    blacklist_records = [r for r in blacklist_records if r["client_ip"] != body.client_ip]
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
