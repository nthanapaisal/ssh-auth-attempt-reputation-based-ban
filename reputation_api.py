import os
from typing import Any, Dict, Optional
import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class ReputationAPIError(RuntimeError):
    pass


def check_ip_abuseipdb(
    ip: str,
    api_key: Optional[str] = None,
    max_age_days: int = 90,
    timeout_s: int = 10,
) -> Dict[str, Any]:

    key = api_key or os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        raise ReputationAPIError("Missing AbuseIPDB API key. Set ABUSEIPDB_API_KEY env var.")

    headers = {
        "Key": key,
        "Accept": "application/json",
        "User-Agent": "rep-service/1.0",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days
    }

    try:
        r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=timeout_s)
    except requests.RequestException as e:
        raise ReputationAPIError(f"Network error calling AbuseIPDB: {e}") from e

    try:
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        raise ReputationAPIError(f"Bad response from AbuseIPDB: {r.status_code}: {e}") from e

    return {
        "ip": ip, 
        "score": data["data"]["abuseConfidenceScore"], 
        "country": data["data"]["countryCode"],
        "totalReports": data["data"]["totalReports"],
        "hostnames": data["data"]["hostnames"]
    }
