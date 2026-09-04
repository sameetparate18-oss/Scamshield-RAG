"""
ScamShield-RAG :: Core Threat Classifier & Heuristic Analysis Engine
Evaluates communications against cyber fraud signatures and MITRE TTPs.
"""

import re
from typing import List, Dict, Any


class ThreatVerdict:
    """Standard forensic verdict container consumed by the UI pipeline."""
    def __init__(
        self,
        verdict: str,
        combined_score: float,
        confidence: float,
        matched_category: str,
        explanation: str,
        red_flags: List[str],
        mitre_ttps: List[str],
        citations: List[str]
    ):
        self.verdict = verdict
        self.combined_score = combined_score
        self.confidence = confidence
        self.matched_category = matched_category
        self.explanation = explanation
        self.red_flags = red_flags
        self.mitre_ttps = mitre_ttps
        self.citations = citations
        self.evidence_id = None
        self.vault_file = None
        self.sha256 = None


def analyze_threat(text: str, mode: str = "text") -> ThreatVerdict:
    """
    Analyzes raw communication or extracted OCR/STT text for hostile threat vectors.
    """
    raw_lower = (text or "").lower()

    # Heuristic Rule Weights & Indicators
    signatures = [
        # 1. Digital Arrest / Law Enforcement Impersonation
        {
            "category": "Digital Arrest Extortion Scheme",
            "regex": r"\b(cbi|narcotics|police|ed|customs|digital arrest|arrest warrant|court notice|skype call)\b",
            "ttp": "T1656: Impersonation",
            "flag": "Government agency or law enforcement impersonation detected.",
            "weight": 0.45
        },
        # 2. Financial / Investment Task Scam
        {
            "category": "Part-Time Task & Investment Fraud",
            "regex": r"\b(telegram|part-time|like youtube|review google maps|deposit.*return|vip task|daily income)\b",
            "ttp": "T1204: User Execution",
            "flag": "Prepaid task / high-yield daily income investment scheme detected.",
            "weight": 0.40
        },
        # 3. APK Sideloading / Malicious Dropper
        {
            "category": "Malicious APK Dropper & Infostealer",
            "regex": r"(\.apk|allow from this source|accessibility permission|security patch|install.*app)\b",
            "ttp": "T1407: Sideloading Malicious Application",
            "flag": "Prompting manual .apk installation bypassing OS security controls.",
            "weight": 0.50
        },
        # 4. Bank / KYC / Utility Disconnection Urgency
        {
            "category": "Bank KYC & Account Freeze Phishing",
            "regex": r"\b(yono|sbi|kyc|pan card|electricity.*disconnect|tonight.*9:30|account block)\b",
            "ttp": "T1566: Phishing",
            "flag": "Artificial urgency regarding account suspension or utility cutoff.",
            "weight": 0.35
        },
        # 5. Financial Diversion Rails
        {
            "category": "Unauthorized Financial Diversion",
            "regex": r"\b(upi|@okhdfcbank|@paytm|@ptaxis|deposit ₹|pay ₹|transfer rs)\b",
            "ttp": "T1657: Financial Theft",
            "flag": "Unverified peer-to-peer payment routing requested.",
            "weight": 0.30
        }
    ]

    matched_categories = []
    matched_flags = []
    matched_ttps = []
    raw_score = 0.0

    for rule in signatures:
        if re.search(rule["regex"], raw_lower):
            matched_categories.append(rule["category"])
            matched_flags.append(rule["flag"])
            matched_ttps.append(rule["ttp"])
            raw_score += rule["weight"]

    # Calculate bounded score
    combined_score = min(1.0, round(raw_score, 2))

    # Map Verdict Classification
    if combined_score >= 0.65:
        verdict_str = "LIKELY_SCAM"
        confidence = 0.94
        primary_category = matched_categories[0] if matched_categories else "Advanced Cyber Fraud Vector"
        explanation = (
            f"Forensic heuristic analysis identified multiple high-confidence scam markers. "
            f"The artifact matches established patterns for {primary_category} with intentional "
            f"coercion and malicious tactical intent."
        )
    elif combined_score >= 0.30:
        verdict_str = "SUSPICIOUS"
        confidence = 0.78
        primary_category = matched_categories[0] if matched_categories else "Unverified External Communication"
        explanation = (
            "Artifact exhibits anomalies and suspicious language typical of social engineering attempts, "
            "though definitive malicious infrastructure indicators remain partially concealed."
        )
    else:
        verdict_str = "SAFE"
        confidence = 0.88
        primary_category = "Nominal Communication"
        explanation = "No hostile threat signatures, coercive psychological vectors, or malicious infrastructure patterns were identified."

    return ThreatVerdict(
        verdict=verdict_str,
        combined_score=combined_score,
        confidence=confidence,
        matched_category=primary_category,
        explanation=explanation,
        red_flags=matched_flags or ["No hostile signatures triggered."],
        mitre_ttps=list(dict.fromkeys(matched_ttps)) or ["T1566: Social Engineering"],
        citations=[]
    )