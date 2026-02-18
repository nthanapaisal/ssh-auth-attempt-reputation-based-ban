import os
import time
import json
import sqlite3
import ipaddress
from typing import Any, Dict, Optional
import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def base_check_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return addr.is_global # True only when the address is public internet-routable

class ReputationAPIError(RuntimeError):
    pass

class ReputationServiceError(RuntimeError):
    pass

def check_ip_abuseipdb(
    ip: str,
    api_key: Optional[str] = None,
    max_age_days: int = 90, # abuse reports from n days
    timeout_s: int = 10, # how long wait for response in s
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

class ReputationDB:
    
    def __init__(self, db_path: Optional[str] = None):
        db_path = (
            db_path
            or os.getenv("REPUTATION_DB_PATH")
            or "./reputation.sqlite"
        )

        dir_name = os.path.dirname(db_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

        self.connection = sqlite3.connect(db_path)
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS ip_rep_db (
                ip TEXT PRIMARY KEY,
                score INTEGER NOT NULL,
                checked_at INTEGER NOT NULL,
                num_connects INTEGER NOT NULL,
                is_blocked INTEGER NOT NULL
            )
        """)
        self.connection.commit()
    
    def check_ip_db(self, ip: str):
        cur = self.connection.cursor()
        cur.execute("SELECT score, checked_at, num_connects, is_blocked FROM ip_rep_db WHERE ip=?", (ip,))
        row = cur.fetchone()

        # fresh ip
        if not row:
            return None
        
        return {
            "ip": ip,
            "score": int(row[0]),
            "checked_at": int(row[1]),
            "num_connects": int(row[2]),
            "is_blocked": int(row[3]),
        }
    
    def add_db(self, now, return_payload, is_blocked):
        # add DB for this new ip
        ip = return_payload["ip"]
        score = return_payload["score"]

        cur = self.connection.cursor()
        cur.execute(
            """
            INSERT INTO ip_rep_db (ip, score, checked_at, num_connects, is_blocked)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ip, score, now, 1, is_blocked)
        )
        self.connection.commit()
    
    def update_db(self, update_dict):
        # update DB for this new ip
        ip = update_dict["ip"]
        score = update_dict["score"]
        checked_at = update_dict["checked_at"]
        num_connects = update_dict["num_connects"]
        is_blocked = update_dict["is_blocked"]

        cur = self.connection.cursor()
        cur.execute(
            """
            UPDATE ip_rep_db
            SET score=?,
                checked_at=?,
                num_connects=?,
                is_blocked=?
            WHERE ip=?
            """,
            (score, checked_at, num_connects + 1, is_blocked, ip)
        )
        self.connection.commit()

def reputation_service(db: ReputationDB, ip: str):
    print(f"[ReputationService] Handling IP: {ip}")
    # check synthetic:not private or reserved
    if not base_check_ip(ip):
        print(f"[Decision] Blocked: False, Non-global IP")
        return False
    
    # Load thresholds
    score_threshold = 80
    cache_ttl = 3600 # 1 hour
    connection_threshold = 20
    now = int(time.time())

    # DB set up and check
    db_row = db.check_ip_db(ip)

    # Not in DB 
    if not db_row:
        print(f"[DB] IP {ip} not found in DB -> calling API")
        try:
            # Check API
            #example 
            #{'ip': '162.240.214.62', 'score': 100, 'country': 'US', 'totalReports': 398, 'hostnames': ['vps-9456455.wattsp.com.br']}
            return_payload = check_ip_abuseipdb(ip)
            score = int(return_payload["score"])
            if score > score_threshold: 
                blocked = 1
            else:
                blocked = 0

            db.add_db(now, return_payload, blocked)
            print(f"[Decision] Blocked: {bool(blocked)}, score: {score}")
            return bool(blocked)
            
        except Exception as e:
            raise ReputationServiceError(f"RepService failed: {e}") from e
    else:
        print(f"[DB] IP {ip} found in DB -> checking block status, cache freshness, frequency")
        # Already in DB
        blocked = db_row["is_blocked"]

        # Already blocked
        if blocked:    
            db.update_db(db_row)
            print(f"[Decision] Blocked: True, score: {db_row['score']}") 
            return True
        
        # Not blocked
        if (now - db_row["checked_at"]) <= cache_ttl: # fresh
            db.update_db(db_row) 
            print(f"[Decision] Blocked: False, fresh cache") 
            return False
        else:                                        # expired
            if (db_row["num_connects"] + 1) > connection_threshold:   # freq connect 
                # get recent rep score
                return_payload = check_ip_abuseipdb(ip)
                score = int(return_payload["score"])
                if score > score_threshold: 
                    blocked = 1
                else:
                    blocked = 0
                update_payload = {
                    "ip": db_row["ip"],
                    "score": return_payload["score"],
                    "checked_at": now,
                    "num_connects": 0,
                    "is_blocked": blocked
                }
                db.update_db(update_payload)
                print(f"[Decision] Blocked: {bool(blocked)}, fresh expired and frequent connects") 
                return bool(blocked)

            db.update_db(db_row)                                      # NOT freq connect
            print(f"[Decision] Blocked: False, fresh expired but non frequent") 
            return False
