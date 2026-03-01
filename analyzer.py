"""Log analyzer for brute-force pattern detection using regex."""

import re
from collections import Counter

# IPv4 address pattern (valid octets 0-255)
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Common brute-force / failed-auth indicators in log lines
FAILURE_PATTERN = re.compile(
    r"(?:failed|failure|invalid|authentication failed|401|403|"
    r"invalid password|invalid user|access denied|unauthorized|"
    r"bad password|wrong password|login failed|auth failed)",
    re.IGNORECASE,
)


def analyze_log(log_content: str, min_count: int = 1) -> dict:
    """
    Analyze log text for brute-force patterns and return suspicious IPs with counts.

    Args:
        log_content: Raw log file text (e.g. from file read or request body).
        min_count: Minimum failure count for an IP to be included (default 1).

    Returns:
        Dict with 'suspicious_ips' (list of {ip, count}) and 'total_suspicious_events'.
    """
    if not log_content or not log_content.strip():
        return {"suspicious_ips": [], "total_suspicious_events": 0}

    counts: Counter = Counter()
    for line in log_content.splitlines():
        if not FAILURE_PATTERN.search(line):
            continue
        match = IPV4_PATTERN.search(line)
        if match:
            counts[match.group()] += 1

    suspicious = [
        {"ip": ip, "count": n}
        for ip, n in counts.most_common()
        if n >= min_count
    ]
    return {
        "suspicious_ips": suspicious,
        "total_suspicious_events": sum(counts.values()),
    }
