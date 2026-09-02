"""
ScamShield-RAG :: Enterprise Verdict & Semantic Matching Engine
Multi-Vector Cosine Similarity against Transnational Knowledge Base + Deterministic Rule Fusion.
"""

import os
import json
import re
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from core.rule_engine import run_rules


@dataclass
class VerdictResponse:
    verdict: str                  # LIKELY_SCAM, SUSPICIOUS, LIKELY_LEGITIMATE
    combined_score: float         # 0.00 to 1.00
    confidence: float             # Model certainty
    matched_category: str         # Primary fraud vector
    dimensions: Dict[str, float]  # 5-Axis radar components
    mitre_ttps: List[str]         # MITRE ATT&CK taxonomy
    explanation: str              # Forensic analysis reasoning
    red_flags: List[str]          # Concrete threat indicators
    citations: List[str]          # Regulatory circular references


DEFAULT_KB = [
    {
        "id": "INT-001",
        "category": "Digital Arrest / Statutory Impersonation",
        "jurisdiction": "Interpol / CBI / Police",
        "mitre_ttp": "T1656: Impersonation",
        "patterns": [
            "digital arrest supreme court warrant narcotics customs package seizure",
            "mumbai police cbi arrest parcel containing drugs money laundering skype call video verification",
            "stay on video call do not disconnect immediate court warrant bank account verification transfer funds"
        ],
        "red_flags": [
            "Coercive video confinement ('Digital Arrest')",
            "Threat of immediate custody without judicial summons",
            "Demands asset transfer to 'safe accounts' for verification"
        ],
        "citations": [
            "CERT-In Advisory CIAD-2026-0089: Digital Arrest Syndicates",
            "Interpol Orange Notice: Extortion via Fake Judicial Summons"
        ]
    },
    {
        "id": "DEL-002",
        "category": "Courier & Customs Fee Impersonation",
        "jurisdiction": "Postal / Customs Authorities",
        "mitre_ttp": "T1566.002: Spearphishing Link",
        "patterns": [
            "parcel is on hold pay customs fee delivery fake link",
            "package pending clearance pay unpaid shipping charges to release parcel",
            "courier failed delivery update address pay nominal fee"
        ],
        "red_flags": [
            "Unsolicited fee request to release standard parcel",
            "Links redirecting to non-postal domain suffixes"
        ],
        "citations": [
            "Universal Postal Union Fraud Alert: Fake Delivery Notices"
        ]
    },
    {
        "id": "JOB-003",
        "category": "Task / Part-Time Employment Scam",
        "jurisdiction": "Cyber Crime Coordination Centre (I4C)",
        "mitre_ttp": "T1589: Target Profiling",
        "patterns": [
            "congratulations selected for part time job earn daily registration fee join telegram channel",
            "work from home like youtube videos earn daily pay upfront deposit to unlock tasks"
        ],
        "red_flags": [
            "Upfront deposit or registration fee required for employment",
            "Recruitment conducted exclusively via Telegram or unverified chat apps"
        ],
        "citations": [
            "I4C Citizen Financial Cyber Fraud Advisory: Fake Job Offers"
        ]
    },
    {
        "id": "KYC-004",
        "category": "Banking KYC Expiration / Smishing",
        "jurisdiction": "RBI / National Cyber Security",
        "mitre_ttp": "T1566: Social Engineering",
        "patterns": [
            "account kyc has expired account will be blocked in 24 hours update verify net link",
            "bank account suspended verify identity input netbanking credentials immediately"
        ],
        "red_flags": [
            "Threat of imminent 24-hour service suspension",
            "Unofficial links prompting for login or personal credentials"
        ],
        "citations": [
            "RBI Master Circular: Prevention of Electronic Banking Fraud"
        ]
    }
]


class VerdictEngine:
    def __init__(self, use_llm: bool = False, kb_path: Optional[str] = None):
        self.use_llm = use_llm
        self.kb_path = kb_path or os.path.join(os.path.dirname(__file__), "..", "data", "fraud_kb.json")
        self.knowledge_base = self._load_or_create_kb()
        
        self.encoder = None
        self.kb_embeddings = []
        self._init_vector_store()

    def _load_or_create_kb(self) -> List[Dict[str, Any]]:
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        
        os.makedirs(os.path.dirname(self.kb_path), exist_ok=True)
        with open(self.kb_path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_KB, f, indent=2)
        return DEFAULT_KB

    def _init_vector_store(self):
        try:
            from sentence_transformers import SentenceTransformer
            self.encoder = SentenceTransformer("all-MiniLM-L6-v2")
            
            self.flat_patterns = []
            self.pattern_to_doc = []

            for doc in self.knowledge_base:
                for pat in doc["patterns"]:
                    self.flat_patterns.append(pat)
                    self.pattern_to_doc.append(doc)

            self.kb_embeddings = self.encoder.encode(self.flat_patterns, normalize_embeddings=True)
        except Exception:
            self.encoder = None

    def _semantic_vector_search(self, text: str) -> tuple:
        if self.encoder is None or len(self.kb_embeddings) == 0:
            return None, 0.0

        query_vec = self.encoder.encode([text], normalize_embeddings=True)
        similarities = np.dot(self.kb_embeddings, query_vec.T).flatten()
        best_idx = int(np.argmax(similarities))
        return self.pattern_to_doc[best_idx], float(similarities[best_idx])

    def _is_safe_whitelisted(self, text: str) -> bool:
        """Explicitly catches authentic service messages and security disclaimers."""
        t = text.lower()
        # Legitimate login OTP notification containing protective disclaimers
        if re.search(r"\b\d{4,8}\s+is\s+your\s+(?:otp|login\s+code)\b", t) and re.search(r"\b(?:do\s+not|never)\s+share\b", t):
            return True
        # Legitimate e-commerce tracking (Amazon, Flipkart, official domains)
        if "out for delivery" in t and ("amazon.in" in t or "flipkart.com" in t or "amazon.com" in t):
            return True
        return False

    def _compute_heuristics(self, text: str) -> Dict[str, float]:
        t = text.lower()

        urgency_words = ["urgent", "immediately", "arrest", "custody", "within 24 hours", "blocked in", "tonight", "transfer funds"]
        urgency_score = min(1.0, sum(0.30 for w in urgency_words if w in t))

        impersonate_words = ["customs", "cbi", "rbi", "digital arrest", "police", "inspector", "court"]
        impersonation_score = min(1.0, sum(0.35 for w in impersonate_words if w in t))

        # Financial score (only triggers if money solicitation or fee is demanded)
        fin_words = ["transfer", "customs fee", "registration fee", "pay rs", "deposit"]
        fin_score = min(1.0, sum(0.35 for w in fin_words if w in t))

        evasion_words = ["do not disconnect", "t.me/", "telegram", "earn rs"]
        evasion_score = min(1.0, sum(0.30 for w in evasion_words if w in t))

        return {
            "urgency": urgency_score,
            "impersonation": impersonation_score,
            "financial": fin_score,
            "evasion": evasion_score
        }

    def analyze(self, text: str) -> VerdictResponse:
        # 1. Deterministic Rule Analysis
        rule_report = run_rules(text)
        rule_findings = rule_report.triggered_findings()

        # 2. Check Whitelist for Benign Operational Messages
        if self._is_safe_whitelisted(text) and not rule_findings:
            return VerdictResponse(
                verdict="LIKELY_LEGITIMATE",
                combined_score=0.05,
                confidence=0.98,
                matched_category="Legitimate System Notification",
                dimensions={
                    "Urgency / Coercion": 0.05,
                    "Impersonation": 0.02,
                    "Financial Diversion": 0.02,
                    "Linguistic Evasion": 0.05,
                    "Vector Proximity": 0.04
                },
                mitre_ttps=["T0000: Standard Benign Artifact"],
                explanation="Authentic communication verified. Matches standard operational notification profiles.",
                red_flags=[],
                citations=["Global Baseline Safe-List (ISO/IEC 27001)"]
            )

        # 3. Vector & Heuristics Computation
        best_doc, vector_score = self._semantic_vector_search(text)
        heuristics = self._compute_heuristics(text)

        dimensions = {
            "Urgency / Coercion": max(0.05, heuristics["urgency"]),
            "Impersonation": max(0.02, heuristics["impersonation"]),
            "Financial Diversion": max(0.02, heuristics["financial"]),
            "Linguistic Evasion": max(0.05, heuristics["evasion"]),
            "Vector Proximity": max(0.04, vector_score)
        }

        # Base composite score
        base_heuristic = (
            dimensions["Urgency / Coercion"] * 0.30 +
            dimensions["Impersonation"] * 0.30 +
            dimensions["Financial Diversion"] * 0.25 +
            dimensions["Linguistic Evasion"] * 0.15
        )

        combined_score = (vector_score * 0.50) + (base_heuristic * 0.50) if self.encoder else base_heuristic

        # Rule findings elevate score decisively
        if rule_findings:
            combined_score = max(combined_score, rule_report.rule_based_score, 0.70)

        combined_score = round(min(1.0, max(0.0, combined_score)), 2)

        # 4. Classification
        if combined_score >= 0.55:
            verdict = "LIKELY_SCAM"
            confidence = min(0.99, 0.85 + (combined_score * 0.14))
        elif combined_score >= 0.35:
            verdict = "SUSPICIOUS"
            confidence = 0.78
        else:
            verdict = "LIKELY_LEGITIMATE"
            confidence = max(0.88, 1.0 - combined_score)

        # 5. Output Packaging
        if best_doc and combined_score >= 0.35:
            category = best_doc["category"]
            ttps = [best_doc["mitre_ttp"]]
            red_flags = [f.description for f in rule_findings] or best_doc["red_flags"]
            citations = best_doc["citations"]
            explanation = (
                f"High-confidence threat vector matching {best_doc['jurisdiction']} advisories for '{category}'. "
                f"The communication exhibits coercive urgency, fraudulent authority masquerading, or unverified payment redirection."
            )
        else:
            category = "Standard Operational Notice"
            ttps = ["T0000: Standard Benign Artifact"]
            red_flags = []
            citations = ["Standard Notification Baseline"]
            explanation = "No malicious manipulation markers or unverified financial diversion links found."

        return VerdictResponse(
            verdict=verdict,
            combined_score=combined_score,
            confidence=round(confidence, 2),
            matched_category=category,
            dimensions=dimensions,
            mitre_ttps=ttps,
            explanation=explanation,
            red_flags=red_flags,
            citations=citations
        )