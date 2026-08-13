# 🛡️ API Sentinel

> **Runtime API Security Platform** — Real-time BOLA detection, Shadow API discovery, and live inventory tracking.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-0.111+-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLite-aiosqlite-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

---

## 📖 Table of Contents

- [What is API Sentinel?](#-what-is-api-sentinel)
- [Real-World Problem](#-real-world-problem)
- [How It Works](#-how-it-works)
- [Architecture](#-architecture)
- [Detection Signals](#-detection-signals)
- [Prerequisites](#-prerequisites)
- [Quick Start (Local)](#-quick-start-local)
- [Quick Start (Docker)](#-quick-start-docker)
- [Demo Scenarios](#-demo-scenarios)
- [API Endpoints](#-api-endpoints
- [Configuration](#-configuration
- [Running Tests](#-running-tests
- [Project Structure](#-project-structure
- [Tech Stack](#-tech-stack

---

## 🎯 What is API Sentinel?

API Sentinel is an **application-layer security platform** that intercepts, analyses, and scores every HTTP request in real time. Unlike WAFs or API gateways that rely on signatures, Sentinel uses a **multi-signal risk scoring engine** to detect:

| Threat | OWASP Category | Response |
|--------|---------------|----------|
| **BOLA / IDOR** — users accessing objects they don't own | API1:2023 | Block (HTTP 403) |
| **Shadow APIs** — undocumented endpoints in live traffic | API9:2023 | Alert + Inventory |
| **Enumeration Attacks** — scanning many IDs rapidly | API1:2023 | Alert |
| **Deprecated Routes** — legacy endpoints still active | API9:2023 | Alert |

---

## 🔥 Real-World Problem

Modern REST APIs expose hundreds of endpoints handling sensitive data. Three critical threats are responsible for the majority of API breaches:

1. **BOLA (Broken Object Level Authorization)**: A user changes `/api/orders/101` → `/api/orders/202` and reads someone else's data. This is the **#1 API vulnerability** (affected Uber, T-Mobile, Venmo).

2. **Shadow APIs**: Forgotten or experimental endpoints (`/api/admin/debug`) that bypass all security controls because they were never documented.

3. **Deprecated Routes**: Legacy API versions (`/v1/`, `/legacy/`) that remain active in production, often lacking modern security patches.

---

## ⚙️ How It Works

```
Incoming HTTP Request
        │
        ▼
┌─────────────────────────────────┐
│       SentinelMiddleware         │  ← Intercepts EVERY request
│  • Extract identity (JWT/Header) │
│  • Normalize route template      │
│  • Build ApiEvent object         │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│       Detection Engine           │
│                                 │
│  ┌──────────────┐  ┌──────────┐ │
│  │ BOLADetector │  │ ShadowAPI│ │
│  │ • ownership  │  │ Detector │ │
│  │ • enumeration│  │ • OAS diff│ │
│  └──────────────┘  └──────────┘ │
│                                 │
│  Risk Score = max(bola, shadow) │
│  Decision: ALLOW / ALERT / BLOCK│
└────────────────┬────────────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
  EventStore          AlertStore
  (SQLite)            (SQLite)
                          │
                          ▼ SSE Push
                   Live Dashboard
```

**Score ≥ 60** with `enforcement_mode=True` → **HTTP 403 BLOCKED**  
**Score < 60** with signals → **ALERT** (logged + streamed to dashboard)  
**No signals** → **ALLOW**

---

## 🏗️ Architecture

```
API SENTINAL/
├── backend/
│   ├── main.py                  # App entry point, lifespan wiring
│   ├── config.py                # Settings (env vars / .env)
│   ├── middleware.py            # SentinelMiddleware — intercepts every request
│   ├── engine.py                # BOLA + Shadow API detection engine
│   ├── inventory.py             # OAS contract loader + live inventory
│   ├── ownership.py             # Object ownership map
│   ├── store.py                 # Async SQLite stores (Event/Alert/Inventory)
│   ├── event_bus.py             # In-process async pub/sub
│   ├── models.py                # Pydantic schemas + SQLAlchemy ORM models
│   ├── openapi_contract.yaml    # Declared API contract (OAS 3.0)
│   ├── requirements.txt         # Python dependencies
│   ├── data/
│   │   └── ownership_seed.json  # Initial ownership mappings
│   ├── routers/
│   │   ├── dashboard.py         # /api/v1/* dashboard + SSE endpoints
│   │   └── sandbox.py           # Vulnerable sandbox API for demos
│   └── tests/
│       └── test_engine.py       # pytest unit/integration tests
├── frontend/
│   └── index.html               # Glassmorphism real-time dashboard
├── ebpf/                        # eBPF kernel sensor (Rust, optional)
├── infra/k8s/                   # Kubernetes manifests
└── docker-compose.yml           # Full-stack orchestration
```

---

## 📊 Detection Signals

| Signal | Weight | Detector | Trigger |
|--------|--------|----------|---------|
| `ownership_mismatch` | **50 pts** | BOLADetector | Principal ≠ object owner |
| `enumeration_signal` | **25 pts** | BOLADetector | ≥5 distinct IDs in 60 seconds |
| `endpoint_novelty` | **40 pts** | ShadowAPIDetector | Route not in OAS contract |
| `sensitive_data_exposure` | **30 pts** | ShadowAPIDetector | Shadow route contains billing/health/ssn/etc. |
| `admin_function_signal` | **30 pts** | ShadowAPIDetector | Shadow route contains admin/debug/internal |
| `deprecated_endpoint_active` | **20 pts** | ShadowAPIDetector | Route marked `deprecated: true` in OAS |

**Severity Mapping:**
- `≥ 80 pts` → 🔴 CRITICAL
- `60–79 pts` → 🟠 HIGH (BLOCK)
- `35–59 pts` → 🟡 MEDIUM (ALERT)
- `< 35 pts` → 🟢 LOW

---

## ✅ Prerequisites

| Requirement | Version | Check Command |
|------------|---------|---------------|
| Python | 3.11+ | `python --version` |
| pip | any | `python -m pip --version` |
| Git | any | `git --version` |
| Docker *(optional)* | 24+ | `docker --version` |
| Docker Compose *(optional)* | 2.x | `docker compose version` |

---

## 🚀 Quick Start (Local)

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/api-sentinel.git
cd api-sentinel
```

### Step 2 — Navigate to backend

```bash
cd backend
```

### Step 3 — Create a virtual environment

```bash
python -m venv venv
```

### Step 4 — Activate the virtual environment

**Windows (PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
.\venv\Scripts\activate.bat
```

**macOS / Linux:**
```bash
source venv/bin/activate
```

### Step 5 — Install dependencies

```bash
python -m pip install -r requirements.txt
```

### Step 6 — Start the server

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 7 — Open the dashboard

| URL | Description |
|-----|-------------|
| http://localhost:8000/ | 🖥️ Live real-time dashboard |
| http://localhost:8000/docs | 📚 Interactive Swagger API docs |
| http://localhost:8000/health | 💚 Health check |

You should see this startup output:
```
[sentinel] Loaded 13 routes from declared contract: openapi_contract.yaml
[sentinel] Ownership map seeded from ownership_seed.json
[sentinel] Detection engine started [OK]
[sentinel] API Sentinel is LIVE - http://localhost:8000
```

---

## 🐳 Quick Start (Docker)

> Starts the full stack: backend + PostgreSQL + Redis + Kafka + ZooKeeper

```bash
# Build and start all services
docker compose up --build

# Run in background (detached mode)
docker compose up -d --build

# View logs
docker compose logs -f backend

# Stop all services
docker compose down

# Stop and remove volumes (full reset)
docker compose down -v
```

Access the dashboard at **http://localhost:8000**

---

## 🎭 Demo Scenarios

Run these commands while the server is running to trigger detections:

### ✅ Legitimate Access → ALLOW

User 101 accesses their own order. Passes ownership check.

```bash
curl -H "X-User-ID: 101" http://localhost:8000/api/orders/101
```

Expected response: `200 OK` with order data.

---

### 🚨 BOLA Attack → HTTP 403 BLOCKED

User 101 tries to access billing record belonging to user 202.  
`ownership_mismatch` fires → Score 50 pts → **BLOCKED**

```bash
curl -H "X-User-ID: 101" http://localhost:8000/api/billing/202
```

Expected response:
```json
{
  "status": "BLOCKED",
  "reason": "API Sentinel: request blocked",
  "alert_type": "ownership_mismatch",
  "signals": ["ownership_mismatch"],
  "risk_score": 50.0
}
```

---

### 👻 Shadow API Discovery → ALERT

`/api/admin/debug` is **NOT** in the OpenAPI contract.  
`endpoint_novelty` (40) + `admin_function_signal` (30) = **70 pts → ALERT**

```bash
curl -H "X-User-ID: 101" http://localhost:8000/api/admin/debug
```

---

### ⚠️ Deprecated Route → ALERT

`/api/v1/legacy/orders` is marked `deprecated: true` in the OAS contract.

```bash
curl http://localhost:8000/api/v1/legacy/orders
```

---

### 🔍 Enumeration Attack → ALERT (after 5+ IDs in 60s)

User 101 scans 7 different order IDs in rapid succession.

**Bash/Linux/macOS:**
```bash
for i in 101 102 103 201 202 203 301; do
  curl -s -H "X-User-ID: 101" http://localhost:8000/api/orders/$i > /dev/null
done
```

**Windows PowerShell:**
```powershell
foreach ($i in 101, 102, 103, 201, 202, 203, 301) {
  Invoke-WebRequest -Uri "http://localhost:8000/api/orders/$i" `
    -Headers @{"X-User-ID"="101"} -UseBasicParsing | Out-Null
}
```

---

## 📡 API Endpoints

### Dashboard Endpoints (`/api/v1/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/inventory` | Full live API inventory with classifications |
| `GET` | `/api/v1/alerts` | Recent security alerts (filter by `?alert_type=BOLA`) |
| `GET` | `/api/v1/events` | Recent raw API events |
| `GET` | `/api/v1/stats` | Aggregated dashboard statistics |
| `GET` | `/api/v1/stream` | Real-time alert stream (Server-Sent Events) |
| `POST` | `/api/v1/admin/reload-contract` | Hot-reload the OpenAPI YAML contract |
| `GET` | `/api/v1/admin/ownership` | View current ownership map |
| `GET` | `/health` | Service health check |
| `GET` | `/docs` | Swagger UI (interactive docs) |

### Sandbox Endpoints (Demo)

| Endpoint | Behaviour |
|----------|-----------|
| `GET /api/orders/{id}` | Normal access — ALLOW |
| `GET /api/billing/{userId}` | Cross-user access — triggers BOLA |
| `GET /api/admin/debug` | Shadow API — triggers ALERT |
| `GET /api/v1/legacy/orders` | Deprecated route — triggers ALERT |

---

## ⚙️ Configuration

All settings live in `backend/config.py` and can be overridden via environment variables or a `.env` file:

```ini
# backend/.env (create this file for local overrides)

# Server
HOST=0.0.0.0
PORT=8000

# Database (use postgresql:// for production)
DATABASE_URL=sqlite+aiosqlite:///./sentinel.db

# Security — CHANGE THIS IN PRODUCTION
SECRET_KEY=your-very-strong-random-secret-key

# Enforcement: True=Block threats, False=Alert only (passive learning mode)
ENFORCEMENT_MODE=True

# Detection Thresholds
ANOMALY_SCORE_THRESHOLD=60.0
ENUM_WINDOW_SECONDS=60
ENUM_THRESHOLD=5

# Risk Score Weights
W_OWNERSHIP_MISMATCH=50.0
W_ENUMERATION_SIGNAL=25.0
W_ENDPOINT_NOVELTY=40.0
W_SENSITIVE_DATA_SIGNAL=30.0
W_ADMIN_FUNCTION_SIGNAL=30.0
```

---

## 🧪 Running Tests

```bash
# Make sure you are in backend/ with venv activated
cd backend

# Windows
.\venv\Scripts\Activate.ps1

# macOS/Linux
source venv/bin/activate

# Run all tests with verbose output
pytest -v

# Run with coverage report
pytest -v --tb=short
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Language | Python 3.11+ | Application runtime |
| Web Framework | FastAPI | Async REST API + OpenAPI docs |
| ASGI Server | Uvicorn | Production-grade server |
| ORM | SQLAlchemy 2.0 (async) | Database access layer |
| Database | SQLite / PostgreSQL | Event + alert persistence |
| Validation | Pydantic v2 | Request/response validation |
| Auth | python-jose | JWT token decoding |
| Streaming | sse-starlette | Real-time SSE alerts |
| Config | pyyaml | OpenAPI contract parsing |
| Testing | pytest + asyncio | Unit & integration tests |
| Containers | Docker + Compose | Full-stack orchestration |
| Messaging* | Apache Kafka | Production event streaming |
| Cache* | Redis | Production caching |
| Sensor* | eBPF (Rust) | Kernel-level packet capture |

> `*` Items marked are available in `docker-compose.yml` but not required for local development.

---

## 🔒 Security Notes for Production

1. **Change `SECRET_KEY`** — Never use the default key in production
2. **Use PostgreSQL** — SQLite is for development only
3. **Restrict CORS** — Set `cors_origins` to your exact frontend domain
4. **Add auth to dashboard** — The SSE stream and admin endpoints need authentication
5. **Start in passive mode** — Set `ENFORCEMENT_MODE=False` initially to calibrate thresholds
6. **Review Shadow API inventory** — Audit all `UNDOCUMENTED` routes regularly

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with ❤️ | API Security for Modern Applications
</p>
