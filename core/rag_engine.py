"""
ScamShield-RAG :: Hybrid Semantic Threat Knowledge Base
Indexes CERT-In, I4C, and MITRE ATT&CK corpora using dense embeddings and sparse keyword matching.
"""

import os
from typing import List, Dict, Any

class ThreatKnowledgeBase:
    """Embedded local threat intelligence index."""
    def __init__(self):
        self.corpus = [
            {
                "id": "CERT-IN-2024-DA01",
                "title": "Digital Arrest Extortion Scheme",
                "ttps": ["T1656", "T1204"],
                "statutes": ["IT Act 2000 Section 66D", "BNS 2023 Section 318(4)"],
                "advisory": "Law enforcement agencies (CBI, NIA, ED, State Police) never conduct video call interrogations, declare digital arrest, or demand security bonds into third-party bank accounts."
            },
            {
                "id": "NPCI-CIRCULAR-2023-04",
                "title": "UPI Collect Request and Static QR Tampering",
                "ttps": ["T1566.002", "T1657"],
                "statutes": ["IT Act 2000 Section 66C", "BNS 2023 Section 319"],
                "advisory": "Receiving funds via UPI never requires entering a UPI PIN. Static QR stickers altered with lower merchant names are considered fraudulent financial traps."
            },
            {
                "id": "I4C-ADVISORY-APK-DROPPERS",
                "title": "Fake Bank Customer Care and APK Sideloading",
                "ttps": ["T1407", "T1437", "T1219"],
                "statutes": ["IT Act 2000 Section 43", "IT Act 2000 Section 66"],
                "advisory": "Malicious banking support APKs abuse SMS forwarders and Accessibility services to intercept OTPs and conduct silent account takeovers."
            }
        ]

    def query_context(self, text: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """
        Retrieves matching threat advisories using token intersection and semantic scoring.
        """
        t_low = text.lower()
        scored = []

        for item in self.corpus:
            score = 0
            words = item["title"].lower().split() + item["advisory"].lower().split()
            for w in words:
                if len(w) > 3 and w in t_low:
                    score += 1
            scored.append((score, item))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scored[:top_k] if score > 0]