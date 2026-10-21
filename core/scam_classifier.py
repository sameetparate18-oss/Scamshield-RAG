"""
ScamShield-RAG :: Unified Enterprise Threat Classifier & Heuristic Decision Engine (v10.0-Ultimate)
Engineered with multi-signal fusion (Hybrid RAG Vector Retrieval + Deterministic Heuristics + MITRE Mapping).
"""

import re
from typing import List, Dict, Any, Optional

class ThreatVerdict:
    """Standard forensic verdict container consumed by the UI and legal dossier pipeline."""
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


def analyze_threat(
    text: str, 
    mode: str = "text", 
    retriever_instance: Optional[Any] = None, 
    rule_engine_func: Optional[Any] = None
) -> ThreatVerdict:
    """
    UNIFIED FORENSIC CLASSIFICATION PIPELINE:
    Fuses signature matching, deterministic rule checking, and hybrid RAG retrieval.
    """
    raw_text = (text or "").strip()
    raw_lower = raw_text.lower()

    if not raw_text:
        return ThreatVerdict(
            verdict="INSUFFICIENT_DATA",
            combined_score=0.0,
            confidence=0.0,
            matched_category="Empty Payload",
            explanation="No text or artifact provided for analysis.",
            red_flags=["Zero-length input sequence."],
            mitre_ttps=["N/A"],
            citations=[]
        )

    # 1. Execute Deterministic Rule Checks (if provided, else fallback regex)
    rule_score = 0.0
    rule_findings = []
    if rule_engine_func:
        rule_report = rule_engine_func(raw_text)
        rule_score = rule_report.rule_based_score
        rule_findings = [f.description for f in rule_report.triggered_findings()]

    # 2. Execute Hybrid RAG Knowledge Base Retrieval (if provided)
    rag_score = 0.0
    rag_matches = []
    citations = []
    if retriever_instance:
        retrieved_docs = retriever_instance.retrieve(raw_text, top_k=2)
        for doc in retrieved_docs:
            if doc.label == "scam":
                rag_matches.append(doc)
                rag_score = max(rag_score, doc.hybrid_score)
                if doc.source_citation:
                    citations.append(doc.source_citation)

    # 3. Core Heuristic Signatures & MITRE ATT&CK Mapping Matrix
    signatures = [
        {
            "category": "Digital Arrest Extortion Scheme",
            "regex": r"\b(cbi|narcotics|police|ed|customs|digital arrest|arrest warrant|court notice|skype call)\b",
            "ttp": "T1656: Financial Impersonation",
            "flag": "Government agency or law enforcement impersonation detected.",
            "weight": 0.40
        },
        {
            "category": "Part-Time Task & Investment Fraud",
            "regex": r"\b(telegram|part-time|like youtube|review google maps|deposit.*return|vip task|daily income)\b",
            "ttp": "T1204: User Execution",
            "flag": "Prepaid task / high-yield daily income investment scheme detected.",
            "weight": 0.35
        },
        {
            "category": "Malicious APK Dropper & Infostealer",
            "regex": r"(\.apk|allow from this source|accessibility permission|security patch|install.*app)\b",
            "ttp": "T1407: Sideloading Malicious Application",
            "flag": "Prompting manual .apk installation bypassing OS security controls.",
            "weight": 0.45
        },
        {
            "category": "Bank KYC & Account Freeze Phishing",
            "regex": r"\b(yono|sbi|kyc|pan card|electricity.*disconnect|tonight.*9:30|account block)\b",
            "ttp": "T1566: Phishing",
            "flag": "Artificial urgency regarding account suspension or utility cutoff.",
            "weight": 0.30
        },
        {
            "category": "Unauthorized Financial Diversion",
            "regex": r"\b(upi|@okhdfcbank|@paytm|@ptaxis|deposit ₹|pay ₹|transfer rs)\b",
            "ttp": "T1657: Financial Theft",
            "flag": "Unverified peer-to-peer payment routing requested.",
            "weight": 0.25
        }
    ]

    matched_categories = []
    matched_flags = list(rule_findings)
    matched_ttps = []
    sig_score = 0.0

    for rule in signatures:
        if re.search(rule["regex"], raw_lower):
            matched_categories.append(rule["category"])
            matched_flags.append(rule["flag"])
            matched_ttps.append(rule["ttp"])
            sig_score += rule["weight"]

    # Incorporate top RAG match categories if available
    for doc in rag_matches:
        matched_categories.append(doc.category)
        matched_flags.extend(doc.red_flags)
        matched_ttps.append("T1566.002: Spearphishing Link / Social Engineering")

    # 4. Multi-Signal Fusion Mathematical Calculation
    # Combines signature score (40%), rule engine score (35%), and RAG semantic score (25%)
    combined_score = min(1.0, round((0.40 * sig_score) + (0.35 * rule_score) + (0.25 * rag_score), 2))

    # 5. Final Verdict Mapping & Forensic Explanation Generation
    if combined_score >= 0.60:
        verdict_str = "LIKELY_SCAM"
        confidence = 0.95
        primary_category = matched_categories[0] if matched_categories else "Advanced Cyber Fraud Vector"
        explanation = (
            f"Multi-signal forensic fusion identified high-confidence hostile markers. "
            f"The artifact correlates with established national threat vectors for {primary_category}, "
            f"exhibiting coercive psychological manipulation and fraudulent infrastructure patterns."
        )
    elif combined_score >= 0.28:
        verdict_str = "SUSPICIOUS"
        confidence = 0.82
        primary_category = matched_categories[0] if matched_categories else "Unverified External Communication"
        explanation = (
            "Artifact exhibits anomalies and suspicious social engineering terminology. "
            "While definitive malicious infrastructure triggers are partial, caution is strongly advised."
        )
    else:
        verdict_str = "SAFE"
        confidence = 0.90
        primary_category = "Nominal Communication"
        explanation = "No hostile threat signatures, coercive psychological vectors, or malicious infrastructure patterns were identified."

    # De-duplicate lists while preserving order
    unique_flags = list(dict.fromkeys(matched_flags)) if matched_flags else ["No hostile signatures triggered."]
    unique_ttps = list(dict.fromkeys(matched_ttps)) if matched_ttps else ["T1566: Social Engineering"]
    unique_citations = list(dict.fromkeys(citations))

    return ThreatVerdict(
        verdict=verdict_str,
        combined_score=combined_score,
        confidence=confidence,
        matched_category=primary_category,
        explanation=explanation,
        red_flags=unique_flags,
        mitre_ttps=unique_ttps,
        citations=unique_citations
    )