# AgencyGuard Proxy + Risk Engine

AgencyGuard runs at the OS network level, not just inside a browser, so it can inspect and control outbound traffic from apps system-wide. By combining destination risk scoring with DLP-based leak prevention, it blocks sensitive data exposure in real time and directly addresses core data privacy risks.

AgencyGuard is a local traffic risk-checking prototype built with:

- `mitmproxy` addon to intercept HTTP/HTTPS requests
- `FastAPI` risk engine to score and decide (`ALLOW`, `WARN`, `BLOCK`)
- DLP scanner for sensitive payload detection
- Live dashboard for demo visibility

## Project Structure

- `mitmproxy_addon/agency_guard_addon.py`  
  Intercepts requests, calls risk engine, enforces decisions.

- `risk_engine/main.py`  
  Core `/evaluate` endpoint + dashboard event APIs.

- `risk_engine/rookie_score.py`  
  Domain-age and destination-risk scoring.

- `risk_engine/dlp_scanner.py`, `risk_engine/dlp_rules.py`, `risk_engine/dlp_config.py`  
  Sensitive-data detection logic.

- `ui_dashboard/index.html`  
  Browser dashboard served by FastAPI at `/dashboard`.

## Prerequisites

- Python 3.9+
- macOS/Linux shell (commands below use `zsh/bash`)

## Setup

```bash
cd /Users/vanajaagarwal/Desktop/wampimuk_hackathon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Start Risk Engine (Terminal 1):

```bash
cd /Users/vanajaagarwal/Desktop/wampimuk_hackathon
source .venv/bin/activate
uvicorn risk_engine.main:app --host 127.0.0.1 --port 5000 --reload
```

Start Proxy (Terminal 2):

```bash
cd /Users/vanajaagarwal/Desktop/wampimuk_hackathon
source .venv/bin/activate
mitmproxy -s mitmproxy_addon/agency_guard_addon.py -p 8080 --set console_eventlog_verbosity=info
```

Open Dashboard:

- `http://127.0.0.1:5000/dashboard`

## Proxy Configuration

Set browser/system proxy:

- Host: `127.0.0.1`
- Port: `8080`

For HTTPS browser interception, install and trust certificate from:

- `http://mitm.it`

## Quick Verification

Allowed request:

```bash
curl --http1.1 -x http://127.0.0.1:8080 https://httpbin.org/get -I
```

Denylist block test:

```bash
curl --http1.1 -x http://127.0.0.1:8080 https://pastebin.com -I
```

DLP block test:

```bash
curl --http1.1 -x http://127.0.0.1:8080 \
  -X POST https://httpbin.org/post \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "ssn=123-45-6789" -i
```

Expected blocked responses include:

- `HTTP/1.1 403 Forbidden`
- `X-AgencyGuard-Decision: BLOCK`

## API Endpoints

Risk evaluation:

- `POST /evaluate`

Health:

- `GET /health`

Dashboard data:

- `GET /api/events?limit=100&decision=ALLOW|WARN|BLOCK&include_background=false&q=...`
- `GET /api/summary?include_background=false&q=...`
- `POST /api/events/clear`

## Notes

- Dashboard hides background-app traffic by default.
- If dashboard looks stale, hard refresh browser and ensure both processes are running.
- If HTTPS requests are not being inspected, verify proxy + certificate trust setup.

## Troubleshooting

1. Port already in use (`8080`):

```bash
lsof -nP -iTCP:8080 -sTCP:LISTEN
kill <PID>
```

2. Risk Engine unreachable:

```bash
curl http://127.0.0.1:5000/health
```

3. Reset running state:

```bash
pkill -f uvicorn
pkill -f mitmproxy
```
