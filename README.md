# Log Brute-Force Analyzer

FastAPI service that accepts log file text, analyzes it for brute-force patterns using regex, and returns suspicious IPs with frequency counts.

## Setup

```bash
cd log_analyzer
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn main:app --reload
```

API docs: http://127.0.0.1:8000/docs

## Usage

**POST /analyze**

- **Body (JSON):** `log_content` (string) — raw log file text (e.g. paste or read from file).
- **Query (optional):** `min_count` (integer) — only include IPs with at least this many failure lines (default: 1).

- **Example:**

```bash
curl -X POST "http://127.0.0.1:8000/analyze?min_count=1" \
  -H "Content-Type: application/json" \
  -d '{"log_content": "192.168.1.100 - - [01/Mar/2025] login failed\n192.168.1.100 - - [01/Mar/2025] invalid password\n10.0.0.5 - - [01/Mar/2025] authentication failed"}'
```

- **Example response:**

```json
{
  "suspicious_ips": [
    { "ip": "192.168.1.100", "count": 2 },
    { "ip": "10.0.0.5", "count": 1 }
  ],
  "total_suspicious_events": 3
}
```

## Detection

- **IP extraction:** IPv4 addresses are matched with a regex (valid octets 0–255).
- **Brute-force signals:** Lines containing (case-insensitive) any of: `failed`, `failure`, `invalid`, `authentication failed`, `401`, `403`, `invalid password`, `invalid user`, `access denied`, `unauthorized`, `bad password`, `wrong password`, `login failed`, `auth failed`.

Only lines that both match a failure phrase and contain an IPv4 address are counted; each such IP is aggregated and returned with its count.
