"""
ScamShield-RAG :: Investigator Session & Credential Authority
Provides local role-based access control (RBAC), lockout enforcement, and chain-of-custody tagging.
"""

import os
import json
import hashlib
import secrets
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

AUTH_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "investigators.json")

# In-memory tracking of failed attempts {badge_id: {"attempts": int, "locked_until": datetime}}
FAILED_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 2


@dataclass
class InvestigatorSession:
    officer_name: str
    badge_id: str
    agency_unit: str
    role: str
    login_time: str

    def to_custody_dict(self) -> dict:
        return {
            "authorized_examiner": self.officer_name,
            "badge_identifier": self.badge_id,
            "station_unit": self.agency_unit,
            "examiner_role": self.role,
            "session_authenticated_at": self.login_time
        }


def _hash_secret(secret: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}{secret}".encode("utf-8")).hexdigest()


def generate_simulated_otp() -> str:
    return f"{random.randint(100000, 999999)}"


def load_investigators() -> dict:
    if not os.path.exists(AUTH_DB_PATH):
        default_salt = secrets.token_hex(8)
        default_records = {
            "OFFICER-701": {
                "name": "Inspector S. G. Parate",
                "badge_id": "OFFICER-701",
                "agency": "Cyber Crime Police Station / SOC Unit",
                "role": "Lead Cyber Forensics Examiner",
                "salt": default_salt,
                "pin_hash": _hash_secret("1234", default_salt),
                "created_at": datetime.now().isoformat()
            }
        }
        os.makedirs(os.path.dirname(AUTH_DB_PATH), exist_ok=True)
        with open(AUTH_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(default_records, f, indent=2)
        return default_records

    try:
        with open(AUTH_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def register_investigator(badge_id: str, name: str, agency: str, role: str, pin: str) -> tuple[bool, str]:
    db = load_investigators()
    badge_key = badge_id.strip().upper()
    if badge_key in db:
        return False, "An investigator with this Badge/Officer ID already exists."

    salt = secrets.token_hex(8)
    db[badge_key] = {
        "name": name.strip(),
        "badge_id": badge_key,
        "agency": agency.strip(),
        "role": role.strip(),
        "salt": salt,
        "pin_hash": _hash_secret(pin.strip(), salt),
        "created_at": datetime.now().isoformat()
    }
    try:
        os.makedirs(os.path.dirname(AUTH_DB_PATH), exist_ok=True)
        with open(AUTH_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        return True, "Investigator profile enlisted successfully."
    except Exception as e:
        return False, f"Failed to persist credentials: {e}"


def check_lockout_status(badge_key: str) -> tuple[bool, int]:
    """Returns (is_locked, remaining_seconds)."""
    if badge_key in FAILED_ATTEMPTS:
        rec = FAILED_ATTEMPTS[badge_key]
        locked_until = rec.get("locked_until")
        if locked_until and datetime.now() < locked_until:
            rem = int((locked_until - datetime.now()).total_seconds())
            return True, max(1, rem)
        elif locked_until and datetime.now() >= locked_until:
            del FAILED_ATTEMPTS[badge_key]
    return False, 0


def authenticate_investigator(badge_id: str, pin: str) -> tuple[bool, InvestigatorSession | None, str]:
    db = load_investigators()
    badge_key = badge_id.strip().upper()

    # 1. Check if badge is currently under lockdown
    is_locked, rem_secs = check_lockout_status(badge_key)
    if is_locked:
        return False, None, f"Badge locked due to security policy. Retry in {rem_secs}s."

    if badge_key not in db:
        return False, None, "Unrecognized Badge or Officer ID."

    record = db[badge_key]
    computed = _hash_secret(pin.strip(), record.get("salt", ""))

    # 2. Check PIN correctness
    if computed != record.get("pin_hash", ""):
        # Register failed attempt
        if badge_key not in FAILED_ATTEMPTS:
            FAILED_ATTEMPTS[badge_key] = {"attempts": 1, "locked_until": None}
        else:
            FAILED_ATTEMPTS[badge_key]["attempts"] += 1

        attempts = FAILED_ATTEMPTS[badge_key]["attempts"]
        if attempts >= MAX_FAILED_ATTEMPTS:
            lock_time = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            FAILED_ATTEMPTS[badge_key]["locked_until"] = lock_time
            return False, None, f"Maximum attempts exceeded. Account locked for {LOCKOUT_DURATION_MINUTES} minutes."
        
        remaining = MAX_FAILED_ATTEMPTS - attempts
        return False, None, f"Invalid Security PIN. ({remaining} attempts remaining before lockdown)"

    # 3. Successful authentication: Clear failed records
    if badge_key in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[badge_key]

    session = InvestigatorSession(
        officer_name=record.get("name", "Unknown Officer"),
        badge_id=record.get("badge_id", badge_key),
        agency_unit=record.get("agency", "Special Cyber Cell"),
        role=record.get("role", "Forensic Investigator"),
        login_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return True, session, "Authentication successful."