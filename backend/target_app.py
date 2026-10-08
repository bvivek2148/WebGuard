import sys
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
import uvicorn

# Ensure stdout handles UTF-8 on Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

app = FastAPI(title="Apex CyberStore & Target Web Application (Protected by WebGuard)")

PRODUCTS_DB = [
    {
        "id": 101,
        "name": "Apex Titan Security Key Pro",
        "category": "tokens",
        "price": 69.99,
        "rating": 4.9,
        "stock": 42,
        "description": "FIDO2 / WebAuthn hardware authenticator with NFC & biometrics."
    },
    {
        "id": 102,
        "name": "Apex CyberGuard WAF Appliance X900",
        "category": "hardware",
        "price": 1899.00,
        "rating": 4.8,
        "stock": 12,
        "description": "Rack-mount high-throughput hardware firewall with AI ML threat classification."
    },
    {
        "id": 103,
        "name": "CloudShield SOC Managed Defense",
        "category": "cloud",
        "price": 499.00,
        "rating": 4.7,
        "stock": 999,
        "description": "24/7 AI-augmented SIEM & automated threat triage with incident response."
    },
    {
        "id": 104,
        "name": "Apex Encrypted NVMe SSD 2TB",
        "category": "hardware",
        "price": 249.99,
        "rating": 4.9,
        "stock": 28,
        "description": "Self-encrypting hardware drive with AES-XTS 256-bit crypto controller."
    }
]

ORDERS_DB = {
    "1001": {
        "order_id": "1001",
        "customer_name": "Alex Mercer",
        "email": "alex.mercer@apex-corp.internal",
        "card_last4": "4111",
        "total": 139.98,
        "items": ["2x Apex Titan Security Key Pro"],
        "confidential": False
    },
    "1002": {
        "order_id": "1002",
        "customer_name": "Victoria Sterling (CFO)",
        "email": "v.sterling@apex-finance.internal",
        "card_last4": "9821 [AMEX BLACK VIP]",
        "total": 14890.00,
        "items": ["5x Apex CyberGuard WAF Appliance X900"],
        "confidential": True
    },
    "1003": {
        "order_id": "1003",
        "customer_name": "Dr. Jonathan Hayes (Director)",
        "email": "j.hayes@classified-soc.gov",
        "card_last4": "5542 [GOV PROCUREMENT]",
        "total": 3990.00,
        "items": ["10x Apex Encrypted NVMe SSD 2TB"],
        "confidential": True
    }
}

REVIEWS_DB = [
    {
        "id": "rev-1",
        "author": "Elena Rostova",
        "product_id": 101,
        "rating": 5,
        "comment": "Flawless FIDO2 integration. Zero auth friction across 400 keys."
    }
]

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    headers_dict = dict(request.headers)
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Apex CyberStore - Protected by WebGuard AI WAF</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1120; color: #f8fafc; padding: 40px; }}
            .card {{ background: #1e293b; border-radius: 16px; padding: 28px; border: 1px solid #334155; max-width: 860px; margin: 0 auto; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
            .status {{ display: inline-flex; align-items: center; gap: 6px; background: #10b98120; color: #34d399; padding: 6px 14px; border-radius: 9999px; font-weight: 700; font-size: 13px; border: 1px solid #10b98140; }}
            pre {{ background: #070d18; padding: 16px; border-radius: 10px; font-size: 12px; overflow-x: auto; color: #38bdf8; border: 1px solid #1e293b; }}
            .endpoint-list {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-top: 20px; }}
            .endpoint {{ background: #0f172a; padding: 12px; border-radius: 8px; border: 1px solid #334155; font-size: 12px; }}
            .endpoint span {{ color: #38bdf8; font-weight: bold; font-family: monospace; }}
        </style>
    </head>
    <body>
        <div class="card">
            <span class="status">🛡️ Protected by WebGuard WAF Proxy</span>
            <h1>⚡ Apex CyberStore Enterprise Application</h1>
            <p>Welcome! If you are seeing this page, your HTTP request successfully passed the <strong>WebGuard AI Web Application Firewall</strong>.</p>
            
            <h3>Available Multi-Page Target Endpoints:</h3>
            <div class="endpoint-list">
                <div class="endpoint"><span>GET /api/products</span> — Product catalog & specs</div>
                <div class="endpoint"><span>GET /api/products/search?q=...</span> — Search & query filter</div>
                <div class="endpoint"><span>GET /api/orders/&#123;id&#125;</span> — Customer order lookup (IDOR)</div>
                <div class="endpoint"><span>POST /api/products/&#123;id&#125;/reviews</span> — Customer reviews (Stored XSS)</div>
                <div class="endpoint"><span>POST /api/diagnostics/ping</span> — Network ping tool (CMDi)</div>
                <div class="endpoint"><span>GET /api/reports/download?file=...</span> — Report downloader (Path Traversal)</div>
                <div class="endpoint"><span>POST /api/webhooks/verify</span> — Webhook inspector (SSRF)</div>
                <div class="endpoint"><span>GET /admin</span> — Restricted admin console</div>
            </div>

            <h3 style="margin-top:24px;">Forwarded Request Headers:</h3>
            <pre>{headers_dict}</pre>
        </div>
    </body>
    </html>
    """

@app.get("/api/products")
async def get_products():
    return {
        "status": "success",
        "count": len(PRODUCTS_DB),
        "data": PRODUCTS_DB
    }

@app.get("/api/products/search")
async def search_products(q: str = ""):
    results = [p for p in PRODUCTS_DB if q.lower() in p["name"].lower() or q.lower() in p["description"].lower()]
    return {
        "status": "success",
        "query": q,
        "count": len(results),
        "data": results
    }

@app.get("/api/orders/{order_id}")
async def get_order(order_id: str):
    order = ORDERS_DB.get(order_id)
    if not order:
        return JSONResponse(status_code=404, content={"status": "error", "message": "Order not found"})
    return {
        "status": "success",
        "data": order
    }

@app.post("/api/products/{product_id}/reviews")
async def add_review(product_id: int, request: Request):
    data = await request.form()
    new_rev = {
        "id": f"rev-{len(REVIEWS_DB) + 1}",
        "author": data.get("author", "Anonymous"),
        "product_id": product_id,
        "rating": int(data.get("rating", 5)),
        "comment": data.get("comment", "")
    }
    REVIEWS_DB.append(new_rev)
    return {
        "status": "success",
        "message": "Review added to product",
        "data": new_rev
    }

@app.post("/api/diagnostics/ping")
async def ping_diagnostic(request: Request):
    data = await request.form()
    host = data.get("host", "127.0.0.1")
    return {
        "status": "success",
        "host": host,
        "result": f"PING {host} (56 data bytes)\n64 bytes from {host}: icmp_seq=1 ttl=118 time=12.4 ms"
    }

@app.get("/api/reports/download")
async def download_report(file: str = "report.log"):
    return {
        "status": "success",
        "filename": file,
        "content": f"[Apex System Log: {file}]\nSystem running normal.\nAll security controls active."
    }

@app.post("/api/webhooks/verify")
async def verify_webhook(request: Request):
    data = await request.form()
    url = data.get("url", "")
    return {
        "status": "success",
        "target": url,
        "response_code": 200,
        "message": "Webhook ping delivered successfully."
    }

@app.get("/admin")
async def admin_portal():
    return {
        "status": "success",
        "portal": "Apex Restricted Executive Admin",
        "users_count": 3,
        "secrets_vault": "unlocked"
    }

if __name__ == "__main__":
    print("🚀 Starting Apex CyberStore Target Application on http://localhost:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080)
