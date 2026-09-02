"""
ScamShield-RAG :: Indian UPI QR & Quishing Forensic Analyzer
"""

import urllib.parse
import re
from typing import Dict, Any

PSP_BANK_MAP = {
    "okhdfcbank": {"bank": "HDFC Bank", "provider": "Google Pay"},
    "okaxis": {"bank": "Axis Bank", "provider": "Google Pay"},
    "oksbi": {"bank": "State Bank of India", "provider": "Google Pay"},
    "okicici": {"bank": "ICICI Bank", "provider": "Google Pay"},
    "paytm": {"bank": "Paytm Payments Bank / Axis Partnered", "provider": "Paytm"},
    "ybl": {"bank": "YES Bank", "provider": "PhonePe"},
    "ibl": {"bank": "ICICI Bank", "provider": "PhonePe"},
    "axl": {"bank": "Axis Bank", "provider": "PhonePe"},
    "upi": {"bank": "NPCI Direct / BHIM", "provider": "BHIM UPI"},
    "barodampay": {"bank": "Bank of Baroda", "provider": "Baroda Pay"},
    "cnrb": {"bank": "Canara Bank", "provider": "Canara AI1"},
    "pnb": {"bank": "Punjab National Bank", "provider": "PNB One"},
    "kotak": {"bank": "Kotak Mahindra Bank", "provider": "Kotak 811"},
    "indus": {"bank": "IndusInd Bank", "provider": "IndusMobile"}
}

def analyze_qr_payload(raw_data: str) -> Dict[str, Any]:
    """Analyzes raw QR payloads for payment authenticity and threat signatures."""
    raw_data = (raw_data or "").strip()
    if not raw_data:
        return {"type": "EMPTY", "is_upi": False, "status": "INVALID", "calculated_risk": 0.0, "anomalies": ["Empty payload."]}

    # 1. Quishing Detection (Web URLs disguised as payments)
    if raw_data.startswith("http://") or raw_data.startswith("https://"):
        suspicious_tld = bool(re.search(r"\.(xyz|top|work|bid|verify|cc|su|app|click)/", raw_data, re.IGNORECASE))
        return {
            "type": "QUISHING_WEB_URL",
            "is_upi": False,
            "raw_payload": raw_data,
            "status": "CRITICAL_RISK" if suspicious_tld else "SUSPICIOUS_REDIRECT",
            "calculated_risk": 0.95 if suspicious_tld else 0.70,
            "anomalies": [
                "Payload is an HTTP/HTTPS web redirect, NOT a direct UPI payment.",
                "High probability of credential harvesting or fake payment portal."
            ] + (["Contains high-risk TLD commonly linked to phishing."] if suspicious_tld else []),
            "recommendation": "DO NOT OPEN THIS LINK in a web browser. Inspect domain safety."
        }

    # 2. Non-UPI format
    if not raw_data.startswith("upi://pay"):
        return {
            "type": "NON_PAYMENT_QR",
            "is_upi": False,
            "raw_payload": raw_data,
            "status": "UNKNOWN_FORMAT",
            "calculated_risk": 0.20,
            "anomalies": ["Standard NPCI 'upi://pay' header missing."],
            "recommendation": "Generic QR code (Wi-Fi, contact, or plain text)."
        }

    # 3. Parse NPCI URI Parameters
    parsed = urllib.parse.urlparse(raw_data)
    params = urllib.parse.parse_qs(parsed.query)

    vpa = params.get("pa", [""])[0]
    name = params.get("pn", [""])[0]
    mcc = params.get("mc", [""])[0]
    amount = params.get("am", [""])[0]
    currency = params.get("cu", ["INR"])[0]

    handle = vpa.split("@")[-1].lower() if "@" in vpa else ""
    bank_info = PSP_BANK_MAP.get(handle, {
        "bank": "Unknown / Unlisted Entity",
        "provider": "Custom Private Aggregator"
    })

    anomalies = []
    risk_score = 0.0

    if handle not in PSP_BANK_MAP:
        anomalies.append(f"Unregistered / unverified PSP handle (@{handle}).")
        risk_score += 0.35

    if amount and float(amount or 0) > 0:
        anomalies.append(f"Pre-encoded static debit amount of ₹{amount}.")
        risk_score += 0.25

    high_risk_words = ["lottery", "cashback", "refund", "police", "customs", "cbi", "tax", "income tax"]
    if any(w in name.lower() for w in high_risk_words):
        anomalies.append("Payee name impersonates government authority, lottery, or refund.")
        risk_score += 0.45

    risk_score = min(1.0, round(risk_score, 2))
    status = "LIKELY_SCAM" if risk_score >= 0.60 else ("SUSPICIOUS" if risk_score >= 0.35 else "VERIFIED_STRUCTURE")

    return {
        "type": "UPI_PAYMENT",
        "is_upi": True,
        "vpa": vpa,
        "declared_name": name or "Not Provided",
        "banking_partner": bank_info["bank"],
        "psp_application": bank_info["provider"],
        "merchant_code": mcc or "P2P / Individual",
        "currency": currency,
        "amount_locked": f"₹{amount}" if amount else "Dynamic / User-entered",
        "anomalies": anomalies or ["Standard compliant NPCI UPI format."],
        "calculated_risk": risk_score,
        "status": status,
        "raw_payload": raw_data
    }