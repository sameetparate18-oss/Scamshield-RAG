"""
ScamShield-RAG :: Cyber Crime Legal Dossier & NCRP Report Generator
Formats forensic evidence for submission to cybercrime.gov.in and police complaints
under the Information Technology Act, 2000 and Bharatiya Nyaya Sanhita (BNS), 2023.
"""

import os
import re
import time
from datetime import datetime
from typing import Dict, Any, List, Optional


# Statutory mapping for Indian cyber fraud vectors
LEGAL_STATUTES = {
    "Digital Arrest / Statutory Impersonation": [
        "BNS Section 204 / 319 (Personating a public servant / Cheating by personation)",
        "IT Act Section 66D (Cheating by personation using computer resource)",
        "BNS Section 308 (Extortion under threat of accusation / arrest)"
    ],
    "Banking KYC Expiration / Smishing": [
        "IT Act Section 66C (Identity theft / Fraudulent use of electronic signature/passwords)",
        "IT Act Section 66D (Cheating by personation using computer resource)",
        "BNS Section 318(4) (Cheating and dishonestly inducing delivery of property)"
    ],
    "Task / Part-Time Employment Scam": [
        "BNS Section 318(4) (Cheating and dishonest inducement)",
        "IT Act Section 66D (Cheating using electronic communication)",
        "BNS Section 111 (Organized Crime syndicate participation)"
    ],
    "Courier & Customs Fee Impersonation": [
        "BNS Section 319 (Cheating by personation)",
        "IT Act Section 66D (Impersonation via computer resource)",
        "BNS Section 318(4) (Fraudulent inducement to transfer funds)"
    ],
    "Quishing / Malicious QR Manipulation": [
        "IT Act Section 66 (Computer related offences / data interception)",
        "IT Act Section 43 (Damage to computer systems / Unauthorized extraction)",
        "BNS Section 318(4) (Fraudulent electronic diversion)"
    ]
}

DEFAULT_STATUTES = [
    "IT Act 2000, Section 66D (Cheating by personation by using computer resource)",
    "Bharatiya Nyaya Sanhita (BNS) 2023, Section 318(4) (Cheating & dishonest inducement)",
    "IT Act 2000, Section 66C (Identity Theft)"
]


def extract_cyber_entities(raw_text: str) -> Dict[str, List[str]]:
    """Extracts critical forensic entities required by the National Cyber Crime portal."""
    entities = {
        "suspect_phones": list(set(re.findall(r"(?:\+91[\-\s]?)?[6789]\d{9}", raw_text))),
        "suspect_vpas": list(set(re.findall(r"[\w\.\-]+@(?:[a-zA-Z0-9]+)", raw_text))),
        "suspect_urls": list(set(re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", raw_text))),
        "suspect_ips": list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_text))),
        "demanded_amounts": list(set(re.findall(r"(?:₹|Rs\.?|INR)\s*[\d,]+", raw_text, re.IGNORECASE)))
    }
    return entities


def generate_ncrp_dossier(
    incident_type: str,
    evidence_text: str,
    verdict_data: Dict[str, Any],
    complainant_name: str = "Concerned Citizen",
    complainant_phone: str = "N/A",
    complainant_city: str = "N/A",
    qr_data: Optional[Dict[str, Any]] = None
) -> str:
    """
    Assembles a complete National Cyber Crime Reporting Portal (NCRP)
    and First Information Report (FIR) formal draft.
    """
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S IST")
    entities = extract_cyber_entities(evidence_text)
    
    # Merge QR entities if supplied
    if qr_data:
        if qr_data.get("vpa") and qr_data.get("vpa") != "N/A":
            entities["suspect_vpas"].append(qr_data["vpa"])
            entities["suspect_vpas"] = list(set(entities["suspect_vpas"]))
        if qr_data.get("raw_payload", "").startswith("http"):
            entities["suspect_urls"].append(qr_data["raw_payload"])
            entities["suspect_urls"] = list(set(entities["suspect_urls"]))

    category = verdict_data.get("matched_category", "Financial Cyber Threat")
    statutes = LEGAL_STATUTES.get(category, DEFAULT_STATUTES)
    risk_score = verdict_data.get("combined_score", 0.0)

    # Format arrays
    phones_str = ", ".join(entities["suspect_phones"]) if entities["suspect_phones"] else "Not Explicitly Disclosed"
    vpas_str = ", ".join(entities["suspect_vpas"]) if entities["suspect_vpas"] else "Not Explicitly Disclosed"
    urls_str = ", ".join(entities["suspect_urls"]) if entities["suspect_urls"] else "None Identified"
    amounts_str = ", ".join(entities["demanded_amounts"]) if entities["demanded_amounts"] else "Unspecified / Dynamic Extraction"
    
    # Red flags
    red_flags = verdict_data.get("red_flags", [])
    red_flags_str = "\n".join([f"   [!] {rf}" for rf in red_flags]) if red_flags else "   [!] Behavioral coercion identified via semantic analysis."

    dossier = f"""================================================================================
NATIONAL CYBER CRIME REPORTING PORTAL (NCRP) — EVIDENCE DOSSIER
Generated via ScamShield-RAG Threat Intelligence Workstation
National Helpline Reference: Citizen Cyber Fraud Helpline (1930) / cybercrime.gov.in
================================================================================

[A] INCIDENT METADATA & COMPLAINT SUMMARY
--------------------------------------------------------------------------------
Filing Category        : Financial Fraud / Cyber Impersonation / Extortion
Incident Sub-Category  : {category}
Date & Time Generated  : {timestamp}
Automated Threat Score : {risk_score:.2f} / 1.00 (Classification: {verdict_data.get('verdict', 'SUSPICIOUS')})
Primary MITRE TTP      : {', '.join(verdict_data.get('mitre_ttps', ['T1566 Social Engineering']))}

[B] SUSPECT IDENTIFIERS & TECHNICAL ATTRIBUTES (FOR NCRP ENTRY)
--------------------------------------------------------------------------------
1. Suspect Mobile/WhatsApp Number(s) : {phones_str}
2. Suspect Payment Address (UPI/VPA) : {vpas_str}
3. Suspect Ingested URLs/Domains     : {urls_str}
4. Identified Financial Demand       : {amounts_str}
5. Associated Bank / Gateway Rail    : {qr_data.get('banking_partner', 'Under Investigation') if qr_data else 'Under Investigation'}

[C] FORENSIC REASONING & DETECTED FRAUD VECTORS
--------------------------------------------------------------------------------
{verdict_data.get('explanation', 'Heuristic analysis detected malicious manipulation signals.')}

Key Hostile Indicators Detected:
{red_flags_str}

[D] APPLICABLE LEGAL STATUTES & PROVISIONS (INDIAN JURISDICTION)
--------------------------------------------------------------------------------
Based on technical artifact analysis, the observed acts attract prima facie prosecution under:
"""
    for stat in statutes:
        dossier += f" • {stat}\n"

    dossier += f"""
[E] FORMAL POLICE / CYBER CRIME STATION COMPLAINT DRAFT
--------------------------------------------------------------------------------
To,
The Officer-in-Charge / Cyber Crime Police Station,
Cyber Crime Reporting Authority.

Subject: Complaint regarding cyber fraud / extortion / statutory impersonation attempt under {category}.

Respected Sir/Madam,

I am bringing to your immediate notice an incident of attempted/executed cyber fraud targeting citizens.
The details of the illicit communication and digital evidence are set forth below:

1. Complainant Name    : {complainant_name}
2. Contact Details     : Phone: {complainant_phone} | Location: {complainant_city}
3. Date & Time         : {timestamp}
4. Mode of Approach    : Electronic Messaging / Voice Call / Malicious QR Payment
5. Suspect UPI/VPA     : {vpas_str}
6. Suspect Mobile(s)   : {phones_str}
7. Suspect URL(s)      : {urls_str}

Statement of Facts:
On the date mentioned, communication was received containing fraudulent claims designed to deceive and coerce the recipient. The perpetrator utilized social engineering tactics, manufactured urgency, and demanded financial diversion. The raw message/artifact submitted as digital evidence reads verbatim:

\"\"\"
{evidence_text.strip()[:1000]}
\"\"\"

The digital evidence confirms coercive tactics, unauthorized authority claims, and unlawful financial solicitation. 

I request your office to:
 a) Register this complaint on the National Cyber Crime Reporting Portal (NCRP) / register a First Information Report (FIR).
 b) Issue an immediate freeze requisition on the beneficiary UPI handles / accounts ({vpas_str}) through the Nodal Bank Officers under Section 1930 / I4C protocols.
 c) Trace the IP logs and subscriber records (CAF) of the associated numbers ({phones_str}).

Yours faithfully,

{complainant_name}
(Digitally Compiled via ScamShield-RAG Automated Forensic Core)
================================================================================
"""
    return dossier
