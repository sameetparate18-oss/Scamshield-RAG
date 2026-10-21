"""
ScamShield-RAG :: Deep UPI & BharatQR Forensic Decoder
Extracts technical attributes, NPCI parameters, PSP identity, and MCC categories.
"""

import urllib.parse
import re
from typing import Dict, Any, Optional

# Standard ISO 18245 Merchant Category Code (MCC) Forensic Dictionary
MCC_DATABASE = {
    "5411": {"category": "Grocery Stores / Supermarkets", "risk": "Low"},
    "5812": {"category": "Restaurants / Food Dining", "risk": "Low"},
    "6011": {"category": "Financial Institutions - Manual Cash Disbursements", "risk": "Elevated"},
    "6012": {"category": "Financial Institutions - Merchandise & Services", "risk": "Moderate"},
    "6051": {"category": "Quasi Cash / Crypto / Foreign Currency / Binary Trading", "risk": "High"},
    "6211": {"category": "Security Brokers / Stock Trading", "risk": "Moderate"},
    "7995": {"category": "Betting / Casino / Gambling Operations", "risk": "Critical"},
    "5944": {"category": "Jewelry Stores & Precious Metals", "risk": "Moderate"},
    "4829": {"category": "Wire Transfer / Money Remittance", "risk": "Elevated"}
}

# Major PSP Handle to Bank Mapping
PSP_HANDLES = {
    "okhdfcbank": "HDFC Bank (Google Pay)",
    "okaxis": "Axis Bank (Google Pay)",
    "okicici": "ICICI Bank (Google Pay)",
    "oksbi": "State Bank of India (Google Pay)",
    "ybl": "Yes Bank (PhonePe)",
    "ibl": "IDFC FIRST Bank (PhonePe)",
    "axl": "Axis Bank (PhonePe)",
    "paytm": "Paytm Payments Bank / VPA Switch",
    "apl": "Axis Bank (Amazon Pay)",
    "waicici": "ICICI Bank (WhatsApp Pay)",
    "barodampay": "Bank of Baroda",
    "postbank": "India Post Payments Bank (IPPB)",
    "kotak": "Kotak Mahindra Bank",
    "indus": "IndusInd Bank",
    "federal": "Federal Bank"
}


def parse_emvco_tlv(raw_data: str) -> Dict[str, str]:
    """Parses EMVCo Tag-Length-Value (TLV) encoded strings (e.g., BharatQR)."""
    tags = {}
    i = 0
    while i < len(raw_data) - 4:
        tag = raw_data[i:i+2]
        try:
            length = int(raw_data[i+2:i+4])
        except ValueError:
            break
        value = raw_data[i+4:i+4+length]
        tags[tag] = value
        i += 4 + length
    return tags


def decode_upi_qr(raw_qr_content: str) -> Dict[str, Any]:
    """
    Decodes the QR payload into detailed holder, banking, and risk metadata.
    """
    details = {
        "raw_payload": raw_qr_content,
        "format": "Unknown",
        "vpa": None,
        "payee_name": None,
        "amount": "Open / Not Fixed",
        "currency": "INR",
        "transaction_ref": None,
        "transaction_note": None,
        "psp_handle": None,
        "acquirer_bank": "Unknown / Unresolved",
        "mcc_code": None,
        "mcc_category": "Personal / Peer-to-Peer (Uncategorized)",
        "risk_indicators": []
    }

    # 1. Parse Standard UPI Intent Schemes
    if raw_qr_content.startswith("upi://pay"):
        details["format"] = "NPCI UPI URI Intent"
        parsed_url = urllib.parse.urlparse(raw_qr_content)
        params = urllib.parse.parse_qs(parsed_url.query)

        # Mandatory / Common Parameters
        details["vpa"] = params.get("pa", [None])[0]
        details["payee_name"] = params.get("pn", [None])[0]
        details["currency"] = params.get("cu", ["INR"])[0]
        
        if "am" in params:
            details["amount"] = f"₹ {params['am'][0]}"
        if "tr" in params:
            details["transaction_ref"] = params["tr"][0]
        if "tn" in params:
            details["transaction_note"] = params["tn"][0]
        if "mc" in params:
            details["mcc_code"] = params["mc"][0]

    # 2. Parse EMVCo / BharatQR TLV Formats
    elif raw_qr_content.startswith("000201"):
        details["format"] = "EMVCo BharatQR (TLV)"
        tlv_tags = parse_emvco_tlv(raw_qr_content)
        
        details["payee_name"] = tlv_tags.get("59", None)
        if "54" in tlv_tags:
            details["amount"] = f"₹ {tlv_tags['54']}"
        if "52" in tlv_tags:
            details["mcc_code"] = tlv_tags["52"]
            
        # Tag 26 holds the UPI Merchant Sub-TLV data
        tag_26 = tlv_tags.get("26", "")
        if tag_26:
            sub_tags = parse_emvco_tlv(tag_26)
            details["vpa"] = sub_tags.get("01", None)

    # 3. Resolve PSP Bank and Routing Infrastructure
    if details["vpa"] and "@" in details["vpa"]:
        handle = details["vpa"].split("@")[-1].lower()
        details["psp_handle"] = f"@{handle}"
        details["acquirer_bank"] = PSP_HANDLES.get(handle, f"Custom PSP Gateway ({handle})")

    # 4. Resolve MCC Industry Category & Inherent Risk
    if details["mcc_code"]:
        mcc_meta = MCC_DATABASE.get(details["mcc_code"])
        if mcc_meta:
            details["mcc_category"] = mcc_meta["category"]
            if mcc_meta["risk"] in ["High", "Critical"]:
                details["risk_indicators"].append(
                    f"High-Risk MCC Category: {mcc_meta['category']} ({mcc_meta['risk']} Risk Profile)"
                )
        else:
            details["mcc_category"] = f"Standard Retail (MCC: {details['mcc_code']})"

    # 5. Fraud Heuristics & Static Tamper Detection
    if not details["mcc_code"]:
        details["risk_indicators"].append("Personal (P2P) VPA used for retail/commercial collection.")

    if details["payee_name"] and any(term in details["payee_name"].lower() for term in ["cbi", "police", "refund", "kyc", "lottery"]):
        details["risk_indicators"].append("Payee Name contains high-risk social engineering or impersonation keywords.")

    return details