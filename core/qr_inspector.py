"""
ScamShield-RAG :: Enterprise Bharat-QR, UPI & Quishing Forensic Analyzer
Supports EMVCo (TLV) BharatQR, NPCI UPI standard specifications, and deep link quishing triage.
"""

import urllib.parse
import re
import socket
import ssl
from typing import Dict, Any, List, Optional

# NPCI Registered Handle to Banking Partner Matrix
PSP_BANK_MAP = {
    "okhdfcbank": {"bank": "HDFC Bank", "provider": "Google Pay", "tier": "Tier-1 Scheduled Commercial"},
    "okaxis": {"bank": "Axis Bank", "provider": "Google Pay", "tier": "Tier-1 Scheduled Commercial"},
    "oksbi": {"bank": "State Bank of India", "provider": "Google Pay", "tier": "Tier-1 PSU Lead"},
    "okicici": {"bank": "ICICI Bank", "provider": "Google Pay", "tier": "Tier-1 Scheduled Commercial"},
    "paytm": {"bank": "Paytm Payments Bank / Partnered", "provider": "Paytm", "tier": "Payments Bank / Multi-bank"},
    "ptyes": {"bank": "YES Bank", "provider": "Paytm", "tier": "Scheduled Commercial"},
    "pthdfc": {"bank": "HDFC Bank", "provider": "Paytm", "tier": "Tier-1 Scheduled Commercial"},
    "ptaxis": {"bank": "Axis Bank", "provider": "Paytm", "tier": "Tier-1 Scheduled Commercial"},
    "ptsbi": {"bank": "State Bank of India", "provider": "Paytm", "tier": "Tier-1 PSU Lead"},
    "ybl": {"bank": "YES Bank", "provider": "PhonePe", "tier": "Scheduled Commercial"},
    "ibl": {"bank": "ICICI Bank", "provider": "PhonePe", "tier": "Tier-1 Scheduled Commercial"},
    "axl": {"bank": "Axis Bank", "provider": "PhonePe", "tier": "Tier-1 Scheduled Commercial"},
    "upi": {"bank": "NPCI Core Switch", "provider": "BHIM Official", "tier": "National Infrastructure"},
    "apl": {"bank": "Axis / Amazon Partnered", "provider": "Amazon Pay", "tier": "E-Commerce TPAP"},
    "cred": {"bank": "Axis Bank / Partnered", "provider": "CRED", "tier": "Fintech TPAP"},
    "waaxis": {"bank": "Axis Bank", "provider": "WhatsApp Pay", "tier": "Social Messaging TPAP"},
    "wahdfc": {"bank": "HDFC Bank", "provider": "WhatsApp Pay", "tier": "Social Messaging TPAP"},
    "wasbi": {"bank": "State Bank of India", "provider": "WhatsApp Pay", "tier": "Social Messaging TPAP"},
    "slice": {"bank": "North East Small Finance Bank", "provider": "Slice", "tier": "Small Finance Bank"},
    "jupiteraxis": {"bank": "Axis Bank", "provider": "Jupiter Money", "tier": "Neobank"},
    "barodampay": {"bank": "Bank of Baroda", "provider": "Baroda Pay", "tier": "Tier-1 PSU Lead"},
    "cnrb": {"bank": "Canara Bank", "provider": "Canara AI1", "tier": "Tier-1 PSU Lead"},
    "pnb": {"bank": "Punjab National Bank", "provider": "PNB One", "tier": "Tier-1 PSU Lead"},
    "kotak": {"bank": "Kotak Mahindra Bank", "provider": "Kotak 811", "tier": "Private Bank"},
    "indus": {"bank": "IndusInd Bank", "provider": "IndusMobile", "tier": "Private Bank"},
    "idfcbank": {"bank": "IDFC FIRST Bank", "provider": "IDFC First Mobile", "tier": "Private Bank"},
    "unionbank": {"bank": "Union Bank of India", "provider": "Vyom", "tier": "Tier-1 PSU Lead"},
    "aubank": {"bank": "AU Small Finance Bank", "provider": "AU 0101", "tier": "Small Finance Bank"},
    "postbank": {"bank": "India Post Payments Bank", "provider": "IPPB Mobile", "tier": "Postal Payments Bank"},
    "federal": {"bank": "Federal Bank", "provider": "FedMobile", "tier": "Private Bank"}
}

# ISO 18245 / NPCI Merchant Category Code (MCC) Risk Profiles
MCC_PROFILES = {
    "7995": {"category": "Gambling / Betting / Lottery", "risk_level": "CRITICAL", "weight": 0.55},
    "6211": {"category": "Securities / Unregulated Brokerage", "risk_level": "HIGH", "weight": 0.40},
    "6051": {"category": "Crypto / Quasi-Cash / Foreign Currency", "risk_level": "HIGH", "weight": 0.45},
    "5944": {"category": "Jewellery / Bullion Transfer", "risk_level": "ELEVATED", "weight": 0.25},
    "4829": {"category": "Wire Transfer / Money Order", "risk_level": "ELEVATED", "weight": 0.30},
    "5411": {"category": "Grocery Stores / Supermarkets", "risk_level": "LOW", "weight": -0.10},
    "5812": {"category": "Restaurants / Food Dining", "risk_level": "LOW", "weight": -0.10},
    "5311": {"category": "Department Stores", "risk_level": "LOW", "weight": -0.05},
    "4121": {"category": "Taxicabs / Commuter Transport", "risk_level": "LOW", "weight": -0.05}
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "rebrand.ly", "bl.ink"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "bid", "verify", "net", "cc", "su", "app", "click",
    "buzz", "link", "info", "gq", "cf", "tk", "ml", "ga"
}


def compute_crc16_ccitt(data: str) -> str:
    """Calculates CRC-16/CCITT-FALSE checksum mandated by ISO/IEC 18004 & EMVCo."""
    crc = 0xFFFF
    for ch in data.encode("utf-8"):
        crc ^= (ch << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def _parse_emvco_tlv(payload: str) -> Optional[Dict[str, str]]:
    """Deconstructs EMVCo Tag-Length-Value format."""
    if not (payload.startswith("000201") or (payload.startswith("00") and len(payload) > 12)):
        return None

    tlv_data = {}
    idx = 0
    length_payload = len(payload)

    try:
        while idx < length_payload:
            tag = payload[idx:idx+2]
            idx += 2
            if idx + 2 > length_payload:
                break
            length = int(payload[idx:idx+2])
            idx += 2
            if idx + length > length_payload:
                break
            val = payload[idx:idx+length]
            idx += length
            tlv_data[tag] = val

        if "00" in tlv_data and ("58" in tlv_data or "53" in tlv_data or "26" in tlv_data):
            return tlv_data
    except Exception:
        pass
    return None


def _perform_network_osint(domain: str) -> Dict[str, Any]:
    """Resolves DNS and TLS handshake metadata."""
    info = {"ip": "Unresolved", "ssl_issuer": "N/A", "ssl_valid": False}
    try:
        clean_domain = domain.split(":")[0]
        ip = socket.gethostbyname(clean_domain)
        info["ip"] = ip

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((clean_domain, 443), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    info["ssl_issuer"] = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown CA"))
                    info["ssl_valid"] = True
    except Exception:
        pass
    return info


def _evaluate_quishing(url: str) -> Dict[str, Any]:
    """Conducts deep forensic triage on links extracted from QR codes."""
    anomalies = []
    risk_score = 0.65
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.lower()
    domain = netloc.split(":")[0]

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        anomalies.append(f"Host uses bare raw IP address ({domain}) instead of standard domain.")
        risk_score += 0.25

    if domain in KNOWN_SHORTENERS:
        anomalies.append(f"Destination cloaked via known URL shortener ({domain}).")
        risk_score += 0.20

    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        anomalies.append(f"High-risk top-level domain (.{tld}) linked to disposable malicious hosting.")
        risk_score += 0.20

    if "xn--" in domain:
        anomalies.append("Punycode homoglyph detected (likely domain spoofing).")
        risk_score += 0.25

    if "@" in parsed.netloc:
        anomalies.append("Authority credentials ('@') embedded in URL masking actual destination host.")
        risk_score += 0.30

    telemetry = _perform_network_osint(domain)
    if telemetry["ip"] != "Unresolved":
        anomalies.append(f"DNS A-Record resolved to IP: {telemetry['ip']}")
    else:
        anomalies.append("DNS Resolution failure: Domain has no valid A-record or is unreachable.")
        risk_score += 0.15

    if telemetry["ssl_valid"]:
        anomalies.append(f"TLS Active: Cert issued by [{telemetry['ssl_issuer']}]")

    risk_score = min(1.0, round(risk_score, 2))
    return {
        "type": "QUISHING_WEB_URL",
        "is_upi": False,
        "raw_payload": url,
        "vpa": "N/A",
        "declared_name": f"Domain: {domain}",
        "banking_partner": "External Network Routing",
        "psp_application": "Web Browser Dispatch",
        "merchant_code": "Non-Payment Hyperlink",
        "amount_locked": "Non-Monetary Intent",
        "crc_status": "N/A (Standard URL)",
        "status": "CRITICAL_RISK" if risk_score >= 0.80 else "SUSPICIOUS_REDIRECT",
        "calculated_risk": risk_score,
        "anomalies": anomalies,
        "recommendation": "DO NOT OPEN. High likelihood of credential interception or malware delivery."
    }


def analyze_qr_payload(raw_data: str) -> Dict[str, Any]:
    """Main QR Forensic Analyzer for BharatQR, UPI, and Quishing."""
    raw_data = (raw_data or "").strip()
    if not raw_data:
        return {
            "type": "EMPTY",
            "is_upi": False,
            "status": "INVALID",
            "calculated_risk": 0.0,
            "anomalies": ["Zero-length or non-decodable payload supplied."]
        }

    # 1. Quishing URL Analysis
    if raw_data.startswith("http://") or raw_data.startswith("https://"):
        return _evaluate_quishing(raw_data)

    # 2. EMVCo BharatQR Standard
    emvco_tags = _parse_emvco_tlv(raw_data)
    if emvco_tags:
        tag_26 = emvco_tags.get("26", "")
        m_name = emvco_tags.get("59", "Merchant Not Named")
        mcc = emvco_tags.get("52", "0000")
        currency = "INR" if emvco_tags.get("53") == "356" else emvco_tags.get("53", "356")
        amount = emvco_tags.get("54", "")
        country = emvco_tags.get("58", "IN")
        crc_provided = emvco_tags.get("63", "").upper()

        crc_status = "UNKNOWN"
        anomalies = []
        risk_score = 0.05

        if "63" in emvco_tags:
            idx_crc = raw_data.rfind("6304")
            if idx_crc != -1:
                base_data = raw_data[:idx_crc + 4]
                computed_crc = compute_crc16_ccitt(base_data)
                if computed_crc == crc_provided:
                    crc_status = f"VALID (0x{computed_crc})"
                else:
                    crc_status = f"TAMPERED (Exp: 0x{computed_crc}, Got: 0x{crc_provided})"
                    anomalies.append("EMVCo Tag 63 CRC-16 Checksum Mismatch! Payload has been forged or altered.")
                    risk_score += 0.45

        vpa = "N/A"
        match = re.search(r"[\w.-]+@[\w.-]+", tag_26)
        if match:
            vpa = match.group(0)

        handle = vpa.split("@")[-1].lower() if "@" in vpa else ""
        bank_info = PSP_BANK_MAP.get(handle, {
            "bank": "BharatQR Acquired Terminal",
            "provider": "Interoperable Bank Rail",
            "tier": "Merchant Acquiring System"
        })

        mcc_info = MCC_PROFILES.get(mcc, {"category": "General Commercial Retail", "risk_level": "LOW", "weight": 0.0})
        if mcc_info["weight"] > 0:
            anomalies.append(f"High-Risk MCC {mcc} [{mcc_info['category']}]: Risk classification tier {mcc_info['risk_level']}.")
            risk_score += mcc_info["weight"]

        if country != "IN":
            anomalies.append(f"Foreign country specification detected in BharatQR ({country}). Domestic rail expects 'IN'.")
            risk_score += 0.30

        if amount and float(amount) > 0:
            anomalies.append(f"Static debit lock: ₹{amount} pre-fixed into BharatQR structure.")
            risk_score += 0.15

        risk_score = min(1.0, round(risk_score, 2))
        return {
            "type": "BHARAT_QR_EMVCO",
            "is_upi": True,
            "vpa": vpa,
            "declared_name": m_name,
            "banking_partner": f"{bank_info['bank']} ({bank_info['tier']})",
            "psp_application": bank_info["provider"],
            "merchant_code": f"{mcc} - {mcc_info['category']}",
            "amount_locked": f"₹{amount}" if amount else "Dynamic / Open Till",
            "crc_status": crc_status,
            "status": "CRITICAL_RISK" if risk_score >= 0.65 else ("SUSPICIOUS" if risk_score >= 0.30 else "VERIFIED_BHARATQR"),
            "calculated_risk": risk_score,
            "anomalies": anomalies or ["Cryptographic CRC-16 Checksum and BharatQR tags validated."],
            "raw_payload": raw_data
        }

    # 3. Standard NPCI UPI Scheme
    if not raw_data.startswith("upi://pay"):
        return {
            "type": "NON_PAYMENT_UTILITY",
            "is_upi": False,
            "raw_payload": raw_data,
            "vpa": "N/A",
            "declared_name": "Standard String",
            "banking_partner": "None",
            "psp_application": "System Utility",
            "merchant_code": "None",
            "amount_locked": "None",
            "crc_status": "N/A",
            "status": "BENIGN_UTILITY",
            "calculated_risk": 0.05,
            "anomalies": ["Non-payment utility code (e.g. WiFi, vCard, or plain text)."],
            "recommendation": "Generic system utility QR."
        }

    parsed = urllib.parse.urlparse(raw_data)
    params = urllib.parse.parse_qs(parsed.query)

    vpa = params.get("pa", [""])[0]
    name = params.get("pn", [""])[0]
    mcc = params.get("mc", [""])[0]
    amount = params.get("am", [""])[0]
    currency = params.get("cu", ["INR"])[0]
    mode = params.get("mode", [""])[0]
    sign = params.get("sign", [""])[0]
    url_param = params.get("url", [""])[0]

    handle = vpa.split("@")[-1].lower() if "@" in vpa else ""
    bank_info = PSP_BANK_MAP.get(handle, {
        "bank": "Unlisted / Private Co-op Entity",
        "provider": "Unverified TPAP Gateway",
        "tier": "Non-Standard Routing"
    })

    anomalies = []
    risk_score = 0.0

    if not handle:
        anomalies.append("Critical Failure: VPA address field ('pa') is missing from UPI URI.")
        risk_score += 0.50
    elif handle not in PSP_BANK_MAP:
        anomalies.append(f"Unregistered / Private PSP handle (@{handle}). Bypasses standard Tier-1 NPCI bank rails.")
        risk_score += 0.35

    mcc_info = MCC_PROFILES.get(mcc, None)
    if mcc_info:
        anomalies.append(f"MCC Identified: {mcc} [{mcc_info['category']}] -> {mcc_info['risk_level']} Risk.")
        risk_score += mcc_info["weight"]
    elif mcc:
        anomalies.append(f"Standard Merchant Category Code declared: {mcc}")
    else:
        anomalies.append("No MCC assigned: Payee operates as P2P (Peer-to-Peer Individual Account), not a verified business.")
        risk_score += 0.10

    if currency.upper() != "INR":
        anomalies.append(f"Currency mismatch alert: Designated currency is {currency}, domestic UPI requires INR.")
        risk_score += 0.40

    if amount and float(amount or 0) > 0:
        anomalies.append(f"Pre-set transaction charge of ₹{amount} locked into QR. Avoids manual payer confirmation.")
        risk_score += 0.20

    if url_param:
        anomalies.append(f"Nested URL Injection Detected in 'url=' parameter: {url_param[:45]}...")
        risk_score += 0.35

    mode_desc = "Standard Dynamic Intent"
    if mode == "01":
        mode_desc = "Static Standee (Physical Sticker)"
        if amount:
            anomalies.append("Contradiction: Mode=01 designates a static merchant standee, but includes a hardcoded debit amount.")
            risk_score += 0.15
    elif mode == "02":
        mode_desc = "Dynamic Invoicing / Generated Bill"

    coercive_terms = ["lottery", "cashback", "refund", "customs", "cbi", "police", "tax", "income tax", "rbi safe"]
    if any(t in name.lower() for t in coercive_terms):
        anomalies.append("Impersonation Alert: Recipient name claims governmental, law enforcement, or reward authority.")
        risk_score += 0.45

    risk_score = min(1.0, max(0.0, round(risk_score, 2)))
    status = "LIKELY_SCAM" if risk_score >= 0.55 else ("SUSPICIOUS" if risk_score >= 0.30 else "VERIFIED_UPI")

    return {
        "type": "UPI_INTENT_PAYMENT",
        "is_upi": True,
        "vpa": vpa or "Missing",
        "declared_name": name or "Not Provided",
        "banking_partner": f"{bank_info['bank']} ({bank_info['tier']})",
        "psp_application": bank_info["provider"],
        "merchant_code": f"{mcc} ({mcc_info['category']})" if mcc_info else (mcc or "P2P Individual"),
        "amount_locked": f"₹{amount}" if amount else "Dynamic / User-entered",
        "mode": mode_desc,
        "crc_status": "Digitally Signed" if sign else "Standard Unsigned Intent",
        "status": status,
        "calculated_risk": risk_score,
        "anomalies": anomalies,
        "raw_payload": raw_data
    }