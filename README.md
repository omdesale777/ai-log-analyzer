# Log Brute-Force Analyzer

A FastAPI service that accepts log file text, detects brute-force–style authentication failures using regex, and returns suspicious IPs with frequency counts. Runs locally or deploys to **Vercel**.

---

## Features

- **Log text input** — Send raw log content as a single JSON field.
- **Regex-based detection** — Catches failed-auth lines (`failed`, `invalid password`, `401`, `access denied`, and more) and extracts IPv4 addresses.
- **Frequency counts** — Aggregates suspicious lines per IP, sorted by failure count.
- **Configurable threshold** — `min_count` query parameter filters out low-frequency IPs.
- **Vercel-ready** — Uses `app.py` as the FastAPI entrypoint for zero-config deployment.

---

## Project Structure

```
log_analyzer/
├── app.py            # Vercel entrypoint (re-exports FastAPI app)
├── main.py           # FastAPI app and HTTP routes
├── analyzer.py       # Regex patterns and analysis logic
├── requirements.txt  # Python dependencies
├── .python-version   # Python version pin (3.12)
└── README.md
```

---

## How It Works

### Detection Logic (`analyzer.py`)

**IPv4 regex** matches valid addresses (octets 0–255) anywhere in a log line.

**Failure regex** flags a line as suspicious if it contains any of the following (case-insensitive):

```
failed · failure · invalid · authentication failed · 401 · 403
invalid password · invalid user · access denied · unauthorized
bad password · wrong password · login failed · auth failed
```

**`analyze_log(log_content, min_count=1)`** processes the text line by line:
1. Skip lines that don't match the failure regex.
2. On matching lines, extract the first IPv4 and increment its counter.
3. Return IPs with `count >= min_count` sorted by count (descending), plus a total event count.

### API (`main.py` / `app.py`)

`main.py` defines the FastAPI app and routes. `app.py` re-exports `app` so Vercel can detect it automatically.

| Route | Method | Description |
|---|---|---|
| `/` | GET | Health / info endpoint |
| `/analyze` | POST | Analyze log text, return suspicious IPs |
| `/docs` | GET | Swagger UI (auto-generated) |

---

## Local Setup

```bash
cd log_analyzer
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Start the server

```bash
uvicorn main:app --reload
```

- Swagger UI: http://127.0.0.1:8000/docs
- Root: http://127.0.0.1:8000/
- Analyze: `POST` http://127.0.0.1:8000/analyze

---

## API Reference

### `POST /analyze`

**Request body (JSON)**

```json
{
  "log_content": "192.168.1.1 login failed\n10.0.0.5 invalid password"
}
```

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `min_count` | integer | `1` | Minimum failures for an IP to be included |

**Example — curl**

```bash
curl -X POST "http://127.0.0.1:8000/analyze?min_count=1" \
  -H "Content-Type: application/json" \
  -d '{"log_content": "192.168.1.100 login failed\n192.168.1.100 invalid password\n10.0.0.5 auth failed"}'
```

**Example response**

```json
{
  "suspicious_ips": [
    { "ip": "192.168.1.100", "count": 2 },
    { "ip": "10.0.0.5",      "count": 1 }
  ],
  "total_suspicious_events": 3
}
```

**From a real log file**

```bash
curl -X POST "http://127.0.0.1:8000/analyze?min_count=5" \
  -H "Content-Type: application/json" \
  -d "$(printf '%s' "{\"log_content\": $(cat /var/log/auth.log | jq -Rs .)}")"
```

*(`jq -Rs .` safely JSON-escapes the file contents.)*

---

## Limitations

- **Request size** — Vercel's free tier caps request bodies at ~4.5 MB. Very large log files may need to be split.
- **Execution timeout** — 10s on the free tier; sufficient for typical log sizes.
- **Stateless** — No storage; each request is analyzed independently.

---

## Possible Extensions

- IPv6 address support
- Time-window analysis (e.g. "50+ failures within 60 seconds")
- File upload support (multipart/form-data) alongside raw text
- User-configurable failure patterns
- Simple web frontend for pasting logs and viewing results as a table

---

## Requirements

- Python 3.10+
- `fastapi`
- `uvicorn[standard]`

---

## Author
- Danny (Om Desale) - Initial development
- Contributors welcome!
