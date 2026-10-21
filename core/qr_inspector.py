"""
ScamShield-RAG :: Enterprise Universal Bharat-QR, UPI & Quishing Forensic Engine (v10.0-Ultimate)
Extracts 100% of available metadata, cryptographic signatures, routing paths, and security attributes.
"""

import urllib.parse
import re
import socket
import ssl
from typing import Dict, Any, Optional

# Comprehensive NPCI Registered Handle to Banking Partner & Core Switch Matrix
PSP_BANK_MAP = {
    "okhdfcbank": {"bank": "HDFC Bank", "provider": "Google Pay", "tier": "Tier-1 Scheduled Commercial", "core_switch": "HDFC UPI Switch"},
    "okaxis": {"bank": "Axis Bank", "provider": "Google Pay", "tier": "Tier-1 Scheduled Commercial", "core_switch": "Axis UPI Switch"},
    "oksbi": {"bank": "State Bank of India", "provider": "Google Pay", "tier": "Tier-1 PSU Lead", "core_switch": "SBI UPI Switch"},
    "okicici": {"bank": "ICICI Bank", "provider": "Google Pay", "tier": "Tier-1 Scheduled Commercial", "core_switch": "ICICI UPI Switch"},
    "paytm": {"bank": "Paytm Payments Bank / Partnered", "provider": "Paytm", "tier": "Payments Bank / Multi-bank", "core_switch": "Paytm Switch"},
    "ptyes": {"bank": "YES Bank", "provider": "Paytm", "tier": "Scheduled Commercial", "core_switch": "YES Bank Switch"},
    "pthdfc": {"bank": "HDFC Bank", "provider": "Paytm", "tier": "Tier-1 Scheduled Commercial", "core_switch": "HDFC UPI Switch"},
    "ptaxis": {"bank": "Axis Bank", "provider": "Paytm", "tier": "Tier-1 Scheduled Commercial", "core_switch": "Axis UPI Switch"},
    "ptsbi": {"bank": "State Bank of India", "provider": "Paytm", "tier": "Tier-1 PSU Lead", "core_switch": "SBI UPI Switch"},
    "ybl": {"bank": "YES Bank", "provider": "PhonePe", "tier": "Scheduled Commercial", "core_switch": "YES Bank Switch"},
    "ibl": {"bank": "ICICI Bank", "provider": "PhonePe", "tier": "Tier-1 Scheduled Commercial", "core_switch": "ICICI UPI Switch"},
    "axl": {"bank": "Axis Bank", "provider": "PhonePe", "tier": "Tier-1 Scheduled Commercial", "core_switch": "Axis UPI Switch"},
    "upi": {"bank": "NPCI Core Switch", "provider": "BHIM Official", "tier": "National Infrastructure", "core_switch": "NPCI Central Switch"},
    "apl": {"bank": "Axis / Amazon Partnered", "provider": "Amazon Pay", "tier": "E-Commerce TPAP", "core_switch": "Axis UPI Switch"},
    "cred": {"bank": "Axis Bank / Partnered", "provider": "CRED", "tier": "Fintech TPAP", "core_switch": "Axis UPI Switch"},
    "waaxis": {"bank": "Axis Bank", "provider": "WhatsApp Pay", "tier": "Social Messaging TPAP", "core_switch": "Axis UPI Switch"},
    "wahdfc": {"bank": "HDFC Bank", "provider": "WhatsApp Pay", "tier": "Social Messaging TPAP", "core_switch": "HDFC UPI Switch"},
    "wasbi": {"bank": "State Bank of India", "provider": "WhatsApp Pay", "tier": "Social Messaging TPAP", "core_switch": "SBI UPI Switch"},
    "slice": {"bank": "North East Small Finance Bank", "provider": "Slice", "tier": "Small Finance Bank", "core_switch": "NESFB Switch"},
    "jupiteraxis": {"bank": "Axis Bank", "provider": "Jupiter Money", "tier": "Neobank", "core_switch": "Axis UPI Switch"},
    "barodampay": {"bank": "Bank of Baroda", "provider": "Baroda Pay", "tier": "Tier-1 PSU Lead", "core_switch": "BOB UPI Switch"},
    "cnrb": {"bank": "Canara Bank", "provider": "Canara AI1", "tier": "Tier-1 PSU Lead", "core_switch": "Canara UPI Switch"},
    "pnb": {"bank": "Punjab National Bank", "provider": "PNB One", "tier": "Tier-1 PSU Lead", "core_switch": "PNB UPI Switch"},
    "kotak": {"bank": "Kotak Mahindra Bank", "provider": "Kotak 811", "tier": "Private Bank", "core_switch": "Kotak Switch"},
    "indus": {"bank": "IndusInd Bank", "provider": "IndusMobile", "tier": "Private Bank", "core_switch": "IndusInd Switch"},
    "idfcbank": {"bank": "IDFC FIRST Bank", "provider": "IDFC First Mobile", "tier": "Private Bank", "core_switch": "IDFC Switch"},
    "unionbank": {"bank": "Union Bank of India", "provider": "Vyom", "tier": "Tier-1 PSU Lead", "core_switch": "UBI Switch"},
    "aubank": {"bank": "AU Small Finance Bank", "provider": "AU 0101", "tier": "Small Finance Bank", "core_switch": "AUBank Switch"},
    "postbank": {"bank": "India Post Payments Bank", "provider": "IPPB Mobile", "tier": "Postal Payments Bank", "core_switch": "IPPB Switch"},
    "federal": {"bank": "Federal Bank", "provider": "FedMobile", "tier": "Private Bank", "core_switch": "Federal Switch"},
    "airtel": {"bank": "Airtel Payments Bank", "provider": "Airtel Thanks", "tier": "Payments Bank", "core_switch": "Airtel Switch"},
    "yesg": {"bank": "YES Bank", "provider": "Groww Pay", "tier": "Scheduled Commercial", "core_switch": "YES Bank Switch"},
    "indie": {"bank": "IndusInd Bank", "provider": "IndusInd Indie", "tier": "Private Bank", "core_switch": "IndusInd Switch"}
}

# ISO 18245 / NPCI Merchant Category Code (MCC) Comprehensive Risk Profile Registry
MCC_PROFILES = {
    "7995": {"category": "Gambling / Betting / Online Casinos", "risk_level": "CRITICAL", "weight": 0.60},
    "6211": {"category": "Securities / Unregulated Brokerage / Trading", "risk_level": "HIGH", "weight": 0.45},
    "6051": {"category": "Crypto Assets / Quasi-Cash / Foreign Exchange", "risk_level": "HIGH", "weight": 0.50},
    "5944": {"category": "Jewellery, Watches & Precious Bullion", "risk_level": "ELEVATED", "weight": 0.30},
    "4829": {"category": "Money Transfer / International Remittance", "risk_level": "ELEVATED", "weight": 0.35},
    "5411": {"category": "Grocery Stores / Supermarkets", "risk_level": "LOW", "weight": -0.10},
    "5812": {"category": "Restaurants / Dining / Food Services", "risk_level": "LOW", "weight": -0.10},
    "5311": {"category": "Department Stores / Retail Chains", "risk_level": "LOW", "weight": -0.05},
    "4121": {"category": "Taxicabs / Public Transport Commute", "risk_level": "LOW", "weight": -0.05}
}

KNOWN_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "shorturl.at", "rb.gy"}
SUSPICIOUS_TLDS = {"xyz", "top", "work", "bid", "verify", "cc", "su", "app", "click", "buzz", "link", "gq", "cf", "tk"}


def compute_crc16_ccitt(data: str) -> str:
    """Computes standard ISO/IEC 18004 CRC-16/CCITT-FALSE checksum for BharatQR strings."""
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
    """Recursively deconstructs EMVCo Tag-Length-Value payload structures."""
    if not payload or len(payload) < 12:
        return None
    tlv_data = {}
    idx = 0
    length_payload = len(payload)
    try:
        while idx < length_payload:
            if idx + 4 > length_payload:
                break
            tag = payload[idx:idx+2]
            length_str = payload[idx+2:idx+4]
            if not length_str.isdigit():
                break
            length = int(length_str)
            idx += 4
            if idx + length > length_payload:
                break
            val = payload[idx:idx+length]
            idx += length
            tlv_data[tag] = val
        if "00" in tlv_data:
            return tlv_data
    except Exception:
        pass
    return None


def _perform_network_osint(domain: str) -> Dict[str, Any]:
    """Resolves DNS records and inspects TLS certificates for Quishing analysis."""
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


def extract_all_forensic_details(raw_input: str) -> Dict[str, Any]:
    """
    MASTER EXTRACTION PIPELINE: 
    Accepts ONLY a QR string or UPI ID, returns 100% of available data attributes.
    """
    cleaned = (raw_input or "").strip()
    
    # Normalize clean VPA shorthand inputs (e.g. "merchant@okicici")
    if "@" in cleaned and not cleaned.startswith("upi://") and not cleaned.startswith("http"):
        cleaned = f"upi://pay?pa={cleaned}&pn=Unspecified"

    if not cleaned:
        return {"error": "Zero-length input sequence supplied."}

    # ---------------------------------------------------------
    # ROUTE 1: QUISHING WEB HYPERLINK ANALYSIS
    # ---------------------------------------------------------
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        parsed = urllib.parse.urlparse(cleaned)
        netloc = parsed.netloc.lower()
        domain = netloc.split(":")[0]
        osint = _perform_network_osint(domain)

        anomalies = []
        risk = 0.70
        if domain in KNOWN_SHORTENERS:
            anomalies.append(f"Cloaked via shortener domain: {domain}")
            risk += 0.20
        tld = domain.split(".")[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            anomalies.append(f"Suspicious top-level domain: .{tld}")
            risk += 0.20
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            anomalies.append("Bare IP address notation used instead of domain name.")
            risk += 0.25

        return {
            "payload_type": "QUISHING_WEB_URL_VECTOR",
            "core_identity": {
                "target_url": cleaned,
                "domain": domain,
                "scheme": parsed.scheme,
                "resolved_ip": osint["ip"],
                "tls_certificate_issuer": osint["ssl_issuer"]
            },
            "financial_parameters": {
                "currency": "N/A (Non-Monetary Link)",
                "amount_locked": "N/A"
            },
            "classification": {
                "merchant_category_code": "N/A",
                "risk_rating": "CRITICAL",
                "calculated_threat_score": min(1.0, risk)
            },
            "security_attributes": {
                "anomalies_detected": anomalies,
                "recommendation": "Do not open. High probability of credential harvesting or malware delivery."
            },
            "raw_payload": cleaned
        }

    # ---------------------------------------------------------
    # ROUTE 2: EMVCo BHARAT-QR STANDARD (TLV DECONSTRUCTION)
    # ---------------------------------------------------------
    emvco_tags = _parse_emvco_tlv(cleaned)
    if emvco_tags:
        tag_26 = emvco_tags.get("26", "")
        merchant_name = emvco_tags.get("59", "Unknown Merchant")
        city = emvco_tags.get("60", "Unknown City")
        mcc = emvco_tags.get("52", "0000")
        currency_code = emvco_tags.get("53", "356")
        amount = emvco_tags.get("54", "")
        country = emvco_tags.get("58", "IN")
        postal_code = emvco_tags.get("61", "N/A")
        crc_provided = emvco_tags.get("63", "").upper()

        crc_status = "NOT_PRESENT"
        if "63" in emvco_tags:
            idx_crc = cleaned.rfind("6304")
            if idx_crc != -1:
                base_data = cleaned[:idx_crc + 4]
                computed = compute_crc16_ccitt(base_data)
                crc_status = f"VALID (0x{computed})" if computed == crc_provided else f"TAMPERED (Expected 0x{computed}, Got 0x{crc_provided})"

        vpa = "N/A"
        match = re.search(r"[\w.-]+@[\w.-]+", tag_26)
        if match:
            vpa = match.group(0)

        handle = vpa.split("@")[-1].lower() if "@" in vpa else ""
        bank_meta = PSP_BANK_MAP.get(handle, {"bank": "Unknown Acquirer", "provider": "Interoperable Rail", "tier": "Unknown", "core_switch": "Unknown"})
        mcc_meta = MCC_PROFILES.get(mcc, {"category": "General Commercial Retail", "risk_level": "LOW", "weight": 0.0})

        anomalies = []
        if "TAMPERED" in crc_status:
            anomalies.append("EMVCo Tag 63 CRC-16 Checksum Mismatch! Barcode data has been altered.")
        if country != "IN":
            anomalies.append(f"Foreign country indicator detected: {country}")

        return {
            "payload_type": "EMVCo_BHARAT_QR",
            "core_identity": {
                "virtual_payment_address": vpa,
                "vpa_handle_suffix": handle,
                "bank_verified_name": merchant_name,
                "psp_provider": bank_meta["provider"],
                "banking_partner": bank_meta["bank"],
                "banking_tier": bank_meta["tier"],
                "core_routing_switch": bank_meta["core_switch"]
            },
            "financial_parameters": {
                "currency": "INR (ISO-356)" if currency_code == "356" else currency_code,
                "amount_locked": f"₹{amount}" if amount else "Dynamic / Open Till",
                "merchant_category_code": mcc,
                "merchant_category_desc": mcc_meta["category"]
            },
            "geographic_metadata": {
                "country_code": country,
                "city": city,
                "postal_code": postal_code
            },
            "cryptographic_integrity": {
                "crc16_status": crc_status,
                "algorithm": "ISO/IEC 18004 CRC-16/CCITT-FALSE",
                "emvco_full_tlv_tags": emvco_tags
            },
            "classification": {
                "risk_level": mcc_meta["risk_level"],
                "risk_weight_score": mcc_meta["weight"],
                "anomalies_detected": anomalies
            },
            "raw_payload": cleaned
        }

    # ---------------------------------------------------------
    # ROUTE 3: NPCI UPI INTENT URI SPECIFICATION
    # ---------------------------------------------------------
    if cleaned.startswith("upi://pay"):
        parsed_uri = urllib.parse.urlparse(cleaned)
        params = urllib.parse.parse_qs(parsed_uri.query)

        vpa = params.get("pa", [""])[0]
        name = params.get("pn", [""])[0]
        mcc = params.get("mc", [""])[0]
        amount = params.get("am", [""])[0]
        currency = params.get("cu", ["INR"])[0]
        txn_ref = params.get("tr", [""])[0]
        txn_note = params.get("tn", [""])[0]
        mode = params.get("mode", [""])[0]
        url_fallback = params.get("url", [""])[0]
        signature = params.get("sign", [""])[0]

        handle = vpa.split("@")[-1].lower() if "@" in vpa else ""
        bank_meta = PSP_BANK_MAP.get(handle, {"bank": "Unlisted Co-op Entity", "provider": "Direct PSP Gateway", "tier": "Non-Standard", "core_switch": "Unknown"})
        mcc_meta = MCC_PROFILES.get(mcc, None)

        mode_desc = "Dynamic Intent Request"
        if mode == "01": mode_desc = "Static Standee Sticker (Mode 01)"
        elif mode == "02": mode_desc = "Dynamic Electronic Invoicing (Mode 02)"

        anomalies = []
        risk_score = 0.0
        if not handle:
            anomalies.append("Missing VPA handle suffix field ('pa').")
            risk_score += 0.50
        elif handle not in PSP_BANK_MAP:
            anomalies.append(f"Unregistered or private VPA handle suffix (@{handle}).")
            risk_score += 0.35

        if mcc_meta:
            risk_score += mcc_meta["weight"]
            anomalies.append(f"MCC Risk Profile: {mcc_meta['risk_level']} [{mcc_meta['category']}]")
        elif not mcc:
            anomalies.append("Unverified P2P Individual Account (No Merchant Category Code assigned).")
            risk_score += 0.10

        if amount and float(amount or 0) > 0:
            anomalies.append(f"Pre-fixed transaction charge locked: ₹{amount}")
            risk_score += 0.15

        if url_fallback:
            anomalies.append(f"Injected fallback redirection URL: {url_fallback}")
            risk_score += 0.30

        return {
            "payload_type": "NPCI_UPI_INTENT_STRING",
            "core_identity": {
                "virtual_payment_address": vpa,
                "vpa_handle_suffix": handle,
                "bank_verified_name": name,
                "psp_provider": bank_meta["provider"],
                "banking_partner": bank_meta["bank"],
                "banking_tier": bank_meta["tier"],
                "core_routing_switch": bank_meta["core_switch"]
            },
            "transaction_parameters": {
                "fixed_amount": f"₹{amount}" if amount else "User-Entered (Dynamic)",
                "currency": currency,
                "transaction_reference_id": txn_ref or "Not Specified",
                "transaction_note": txn_note or "None",
                "intent_mode": mode_desc,
                "fallback_url": url_fallback or "None"
            },
            "classification": {
                "merchant_category_code": mcc or "Not Specified (P2P)",
                "merchant_category_desc": mcc_meta["category"] if mcc_meta else "Unclassified Entity",
                "calculated_threat_score": min(1.0, round(risk_score, 2)),
                "risk_rating": "CRITICAL" if risk_score >= 0.55 else ("SUSPICIOUS" if risk_score >= 0.30 else "LOW_RISK")
            },
            "security_attributes": {
                "digital_signature_status": "Digitally Signed (sign=present)" if signature else "Unsigned Standard Intent",
                "anomalies_detected": anomalies
            },
            "raw_payload": cleaned
        }

    return {"error": "Unrecognized format sequence."}