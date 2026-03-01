# Log Brute-Force Analyzer

FastAPI service that accepts log file text, analyzes it for brute-force patterns using regex, and returns suspicious IPs with frequency counts. Runs locally or on **Vercel**.

## Setup (local)

```bash
cd log_analyzer
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run locally

```bash
uvicorn main:app --reload
```

API docs: http://127.0.0.1:8000/docs

## Deploy on Vercel

The app is set up for **zero-config** FastAPI on Vercel (entrypoint: `app.py`).

1. **Install Vercel CLI** (optional): `npm i -g vercel`
2. **Deploy from the project root:**

   ```bash
   cd log_analyzer
   vercel
   ```

   Or connect the repo at [vercel.com/new](https://vercel.com/new) and deploy from Git.

3. **Use the deployed API:**  
   Your base URL will be like `https://your-project.vercel.app`. Then:
   - **GET** `https://your-project.vercel.app/` — service info
   - **POST** `https://your-project.vercel.app/analyze` — analyze log text (body and query same as below)
   - **Docs:** `https://your-project.vercel.app/docs`

**Local dev with Vercel:**  
After `pip install -r requirements.txt`, run:

```bash
vercel dev
```

to mimic Vercel’s routing locally (requires Vercel CLI 48.1.8+).

## API usage

**POST /analyze**

- **Body (JSON):** `log_content` (string) — raw log file text (e.g. paste or read from file).
- **Query (optional):** `min_count` (integer) — only include IPs with at least this many failure lines (default: 1).

**Example (local or Vercel URL):**

```bash
curl -X POST "https://your-project.vercel.app/analyze?min_count=1" \
  -H "Content-Type: application/json" \
  -d '{"log_content": "192.168.1.100 - - [01/Mar/2025] login failed\n192.168.1.100 - - [01/Mar/2025] invalid password\n10.0.0.5 - - [01/Mar/2025] authentication failed"}'
```

**Example response:**

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

## Project structure

```
log_analyzer/
├── app.py            # Vercel entrypoint (exports FastAPI app)
├── main.py           # FastAPI app and routes
├── analyzer.py       # Regex and analysis logic
├── requirements.txt
├── .python-version   # 3.12 for Vercel
└── README.md
```
