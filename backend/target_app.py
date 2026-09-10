import sys
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
import uvicorn

# Ensure stdout handles UTF-8 on Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

app = FastAPI(title="Target Web Application (Backend Protected by WebGuard)")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    headers_dict = dict(request.headers)
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Target Application - Protected by WebGuard</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }}
            .card {{ background: #1e293b; border-radius: 12px; padding: 24px; border: 1px solid #334155; max-width: 800px; margin: 0 auto; }}
            .status {{ display: inline-block; background: #10b98120; color: #34d399; padding: 6px 12px; border-radius: 9999px; font-weight: 600; font-size: 14px; border: 1px solid #10b98140; }}
            pre {{ background: #0f172a; padding: 16px; border-radius: 8px; font-size: 12px; overflow-x: auto; color: #38bdf8; }}
        </style>
    </head>
    <body>
        <div class="card">
            <span class="status">🛡️ Protected by WebGuard WAF Proxy</span>
            <h1>Target Backend Application</h1>
            <p>Welcome! If you are seeing this page, your HTTP request successfully passed the <strong>WebGuard AI Web Application Firewall</strong>.</p>
            <h3>Forwarded Request Headers:</h3>
            <pre>{headers_dict}</pre>
        </div>
    </body>
    </html>
    """

@app.get("/api/products")
async def get_products():
    return {
        "status": "success",
        "data": [
            {"id": 101, "name": "CyberSec Pro Laptop", "price": 1499.99},
            {"id": 102, "name": "WebGuard Shield Router", "price": 299.00},
            {"id": 103, "name": "Hardware Security Token", "price": 49.99}
        ]
    }

@app.get("/api/user/profile")
async def get_profile(request: Request):
    return {
        "user_id": "usr_9843a",
        "username": "security_admin",
        "email": "admin@webguard.internal",
        "role": "Administrator",
        "shielded_by": "WebGuard AI WAF"
    }

if __name__ == "__main__":
    print("🚀 Starting Target Application on http://localhost:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080)
