"""FastAPI app: accept log text, analyze for brute-force patterns, return suspicious IPs."""

from fastapi import Body, FastAPI

from analyzer import analyze_log

app = FastAPI(
    title="Log Brute-Force Analyzer",
    description="Accepts log file text, detects brute-force patterns via regex, returns suspicious IPs with frequency counts.",
    version="1.0.0",
)


@app.get("/")
def root():
    """Health / info."""
    return {
        "service": "Log Brute-Force Analyzer",
        "docs": "/docs",
        "analyze": "POST /analyze",
    }


@app.post("/analyze")
def analyze(
    log_content: str = Body(..., embed=True, description="Raw log file text to analyze"),
    min_count: int = 1,
):
    """
    Analyze log text for brute-force patterns.

    Body: `{"log_content": "line1\\nline2\\n..."}`. Optional query: `?min_count=5`.
    Returns suspicious IPs with frequency counts, sorted by count descending.
    """
    return analyze_log(log_content, min_count=min_count)
