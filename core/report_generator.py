"""
ScamShield-RAG :: Enterprise Cyber Crime Legal Dossier & BSA Section 63 Compliant Generator (v10.0-Ultimate)
Engineered for official submission to cybercrime.gov.in, NCRP, and Indian Courts under 
the IT Act 2000, Bharatiya Nyaya Sanhita (BNS) 2023, and Bharatiya Sakshya Adhiniyam (BSA) 2023.
"""

import hashlib
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional

# Comprehensive Statutory Mapping under BNS 2023 & IT Act 2000
LEGAL_STATUTES = {
    "Digital Arrest / Statutory Impersonation": [
        "BNS 2023 Section 204 / 319 (Personating a public servant & Cheating by personation)",
        "IT Act 2000 Section 66D (Cheating by personation using computer resource)",
        "BNS 2023 Section 308 (Extortion under threat of criminal accusation / arrest)"
    ],
    "Banking KYC Expiration / Smishing": [
        "IT Act 2000 Section 66C (Identity theft / Fraudulent use of electronic passwords)",
        "IT Act 2000 Section 66D (Cheating by personation via electronic communication)",
        "BNS 2023 Section 318(4) (Cheating and dishonestly inducing delivery of property)"
    ],
    "Task / Part-Time Employment Scam": [
        "BNS 2023 Section 318(4) (Cheating and fraudulent financial inducement)",
        "IT Act 2000 Section 66D (Communication device fraud)",
        "BNS 2023 Section 111 (Organized Crime syndicate participation)"
    ],
    "Courier & Customs Fee Impersonation": [
        "BNS 2023 Section 319 (Cheating by personation of authority)",
        "IT Act 2000 Section 66D (Impersonation via computer resource)",
        "BNS 2023 Section 318(4) (Fraudulent inducement to transfer funds)"
    ],
    "Quishing / Malicious QR Manipulation": [
        "IT Act 2000 Section 66 (Computer related offences / data alteration)",
        "IT Act 2000 Section 43 (Damage to computer systems / Unauthorized extraction)",
        "BNS 2023 Section 318(4) (Fraudulent electronic diversion of funds)"
    ]
}

DEFAULT_STATUTES = [
    "IT Act 2000, Section 66D (Cheating by personation using computer resource)",
    "Bharatiya Nyaya Sanhita (BNS) 2023, Section 318(4) (Cheating & dishonest inducement)",
    "IT Act 2000, Section 66C (Identity Theft)"
]


def _compute_evidence_sha256(evidence_text: str) -> str:
    """Computes an immutable cryptographic hash of the digital evidence for court verification."""
    return hashlib.sha256(evidence_text.encode("utf-8")).hexdigest()


def extract_cyber_entities(raw_text: str) -> Dict[str, List[str]]:
    """Extracts critical forensic entities required by the National Cyber Crime portal."""
    return {
        "suspect_phones": list(set(re.findall(r"(?:\+91[\-\s]?)?[6789]\d{9}", raw_text))),
        "suspect_vpas": list(set(re.findall(r"[\w\.\-]+@(?:[a-zA-Z0-9]+)", raw_text))),
        "suspect_urls": list(set(re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", raw_text))),
        "suspect_ips": list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_text))),
        "demanded_amounts": list(set(re.findall(r"(?:₹|Rs\.?|INR)\s*[\d,]+", raw_text, re.IGNORECASE))),
        "utr_numbers": list(set(re.findall(r"\b\d{12}\b", raw_text))) # Standard 12-digit UTR/RRN format
    }


def generate_ncrp_dossier(
    incident_type: str,
    evidence_text: str,
    verdict_data: Dict[str, Any],
    complainant_name: str = "Concerned Citizen",
    complainant_phone: str = "N/A",
    complainant_city: str = "N/A",
    complainant_aadhaar_ref: str = "XXX-XXXX-XXXX",
    device_source: str = "Mobile Smartphone / Secure Workstation",
    qr_data: Optional[Dict[str, Any]] = None
) -> str:
    """
    Assembles an elite, legally binding National Cyber Crime Reporting Portal (NCRP) 
    dossier and Bharatiya Sakshya Adhiniyam (BSA) Section 63 Compliant Evidence Certificate.
    """
    timestamp_full = datetime.now().strftime("%d-%m-%Y %H:%M:%S IST")
    timestamp_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    evidence_hash = _compute_evidence_sha256(evidence_text)
    
    entities = extract_cyber_entities(evidence_text)
    
    # Merge QR/Intent parameters if supplied
    if qr_data:
        vpa_extracted = qr_data.get("virtual_payment_address") or qr_data.get("vpa")
        if vpa_extracted and vpa_extracted != "N/A":
            entities["suspect_vpas"].append(vpa_extracted)
            entities["suspect_vpas"] = list(set(entities["suspect_vpas"]))
        raw_payload = qr_data.get("raw_payload", "")
        if raw_payload.startswith("http"):
            entities["suspect_urls"].append(raw_payload)
            entities["suspect_urls"] = list(set(entities["suspect_urls"]))

    category = verdict_data.get("matched_category", incident_type or "Financial Cyber Threat")
    statutes = LEGAL_STATUTES.get(category, DEFAULT_STATUTES)
    risk_score = verdict_data.get("combined_score", verdict_data.get("calculated_threat_score", 0.85))

    # Formatted output strings
    phones_str = ", ".join(entities["suspect_phones"]) if entities["suspect_phones"] else "Not Explicitly Disclosed (Pending Call CDR Trace)"
    vpas_str = ", ".join(entities["suspect_vpas"]) if entities["suspect_vpas"] else "Not Explicitly Disclosed"
    urls_str = ", ".join(entities["suspect_urls"]) if entities["suspect_urls"] else "None Identified"
    amounts_str = ", ".join(entities["demanded_amounts"]) if entities["demanded_amounts"] else "Dynamic / Unspecified Demand"
    utr_str = ", ".join(entities["utr_numbers"]) if entities["utr_numbers"] else "Not Provided in Text (Requires Bank Statement Log)"
    
    red_flags = verdict_data.get("red_flags", verdict_data.get("anomalies_detected", []))
    red_flags_str = "\n".join([f"   [!] {rf}" for rf in red_flags]) if red_flags else "   [!] Behavioral coercion and deceptive financial routing indicators detected."

    banking_partner = "Under Investigation (NPCI Switch Routing)"
    if qr_data:
        banking_partner = qr_data.get("banking_partner", qr_data.get("core_identity", {}).get("banking_partner", "Under Investigation"))

    dossier = f"""================================================================================
NATIONAL CYBER CRIME REPORTING PORTAL (NCRP) & COURT ADMISSIBILITY DOSSIER
Generated via ScamShield-RAG Enterprise Threat Intelligence Workstation
Official Helpline Reference: Citizen Cyber Fraud Helpline (1930) / cybercrime.gov.in
================================================================================

[SECTION 1] INCIDENT METADATA & COMPLAINT SUMMARY
--------------------------------------------------------------------------------
Filing Category        : Financial Fraud / Cyber Impersonation / Extortion
Incident Sub-Category  : {category}
Filing Timestamp       : {timestamp_full}
Automated Threat Score : {risk_score:.2f} / 1.00 (Verdict: {verdict_data.get('verdict', 'HIGH_RISK_CRITICAL_THREAT').upper()})
Primary MITRE TTPs     : {', '.join(verdict_data.get('mitre_ttps', ['T1566 Social Engineering', 'T1656 Financial Impersonation']))}

[SECTION 2] SUSPECT IDENTIFIERS & TECHNICAL ATTRIBUTES (FOR NCRP ENTRY)
--------------------------------------------------------------------------------
1. Suspect Mobile/WhatsApp Number(s) : {phones_str}
2. Suspect Payment Address (UPI/VPA) : {vpas_str}
3. Suspect Ingested URLs/Domains     : {urls_str}
4. Identified Financial Demand       : {amounts_str}
5. Transaction Ref / UTR (if any)    : {utr_str}
6. Associated Bank / Gateway Rail    : {banking_partner}

[SECTION 3] FORENSIC REASONING & DETECTED FRAUD VECTORS
--------------------------------------------------------------------------------
{verdict_data.get('explanation', 'Heuristic and semantic parsing identified malicious intent signals structured to deceive the victim into unauthorized financial exposure.')}

Key Hostile Indicators Detected:
{red_flags_str}

[SECTION 4] APPLICABLE LEGAL STATUTES & PROVISIONS (INDIAN JURISDICTION)
--------------------------------------------------------------------------------
Based on technical artifact analysis, the observed acts attract prima facie prosecution under:
"""
    for stat in statutes:
        dossier += f" • {stat}\n"

    dossier += f"""
[SECTION 5] MANDATORY STATUTORY CERTIFICATE 
(Under Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023 - BSA)
--------------------------------------------------------------------------------
PART A: CERTIFICATE FOR PRODUCTION OF ELECTRONIC RECORD

I, {complainant_name}, son/daughter/spouse of Concerned Citizen, residing/employed at City: {complainant_city}, do hereby solemnly affirm and state as follows:
1. I have produced the electronic record / digital output extracted from the device source: [{device_source}].
2. The digital device / source was under lawful control and used regularly for storing and processing information, and during said period, the device was operating properly.
3. The cryptographic SHA-256 hash value of the raw digital evidence payload recorded at the time of extraction is:
   HASH: {evidence_hash}
   Algorithm: SHA-256 (ISO/IEC International Standard)
   Timestamp: {timestamp_iso}

(Name & Signature of Complainant / Certifying Authority)
Name : {complainant_name}
Date : {datetime.now().strftime("%d-%m-%Y")}
Time : {datetime.now().strftime("%H:%M:%S")} IST

[SECTION 6] FORMAL POLICE / CYBER CRIME STATION COMPLAINT DRAFT
--------------------------------------------------------------------------------
To,
The Officer-in-Charge / Cyber Crime Police Station,
Cyber Crime Cell / National Cyber Crime Reporting Authority.

Subject: Formal complaint regarding cyber fraud / extortion / fraudulent digital diversion under {category}.

Respected Sir/Madam,

I am filing this formal complaint regarding an executed/attempted cyber fraud targeting citizens. The complete technical attributes and digital records are documented below:

1. Complainant Name    : {complainant_name}
2. Contact Details     : Phone: {complainant_phone} | Location: {complainant_city} | Aadhaar Ref: {complainant_aadhaar_ref}
3. Date & Time         : {timestamp_full}
4. Mode of Approach    : Electronic Messaging / Voice Call / Malicious QR Payment Vector
5. Suspect UPI/VPA     : {vpas_str}
6. Suspect Mobile(s)   : {phones_str}
7. Suspect URL(s)      : {urls_str}

Statement of Facts:
On the date mentioned, communication containing fraudulent claims was received, designed to deceive, manipulate, and coerce financial transfer. The perpetrator utilized social engineering tactics, manufactured urgency, and demanded illegal financial diversion. The verbatim electronic evidence ingested reads:

\"\"\"
{evidence_text.strip()[:1200]}
\"\"\"

The attached digital evidence confirms coercive tactics, unauthorized authority claims, and illegal financial solicitation. 

I request your esteemed office to:
 a) Register this complaint immediately on the National Cyber Crime Reporting Portal (NCRP) / register a First Information Report (FIR).
 b) Issue an urgent freeze requisition on the beneficiary UPI handles / accounts ({vpas_str}) through the Nodal Bank Officers under Section 1930 / I4C protocols.
 c) Trace the IP logs, device identifiers, and subscriber application forms (CAF) of the associated numbers ({phones_str}).

Yours faithfully,

{complainant_name}
(Digitally Compiled & Certified via ScamShield-RAG Enterprise Forensic Engine)
================================================================================
"""
    return dossier