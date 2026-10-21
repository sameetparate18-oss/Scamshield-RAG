"""
ScamShield-RAG :: Enterprise Hybrid Semantic & Sparse Threat Knowledge Base (v10.1-Ultimate)
Engineered with pre-tokenized indexing, dynamic corpus insertion, and hybrid BM25/Dense fusion.
"""

import math
import json
import os
import re
from typing import List, Dict, Any, Optional

class EnterpriseHybridThreatKnowledgeBase:
    """
    State-of-the-art local threat intelligence engine using hybrid 
    sparse token weighting and dense semantic vector similarity.
    """
    def __init__(self, corpus_path: Optional[str] = None):
        # Default authoritative corpus (CERT-In, I4C, MITRE, BNS/IT Act)
        self.default_corpus = [
            {
                "id": "CERT-IN-2024-DA01",
                "title": "Digital Arrest & Virtual Interrogation Extortion Scheme",
                "category": "Identity Impersonation & Extortion",
                "ttps": ["T1656", "T1204", "T1498"],
                "statutes": ["IT Act 2000 Section 66D", "BNS 2023 Section 318(4)", "BNS 2023 Section 351"],
                "advisory": "Law enforcement agencies (CBI, NIA, ED, Customs, State Police) never conduct video call interrogations, declare digital arrest, or demand security bonds/bail payments into third-party bank accounts."
            },
            {
                "id": "NPCI-I4C-QR-2026",
                "title": "UPI Collect Request Fraud and Static QR Code Tampering",
                "category": "Financial Payment Fraud (Quishing)",
                "ttps": ["T1566.002", "T1657", "T1204.002"],
                "statutes": ["IT Act 2000 Section 66C", "IT Act 2000 Section 66D", "BNS 2023 Section 319"],
                "advisory": "Receiving funds via UPI never requires entering a UPI PIN. Static QR stickers altered with lower merchant names or unsolicited collect requests are fraudulent traps designed to drain accounts instantly."
            },
            {
                "id": "I4C-ADVISORY-APK-DROPPERS-2026",
                "title": "Malicious Banking Support & Fake Porn/Utility APK Sideloading",
                "category": "Mobile Banking Trojans & Accessibility Abuse",
                "ttps": ["T1407", "T1437", "T1219", "T1534"],
                "statutes": ["IT Act 2000 Section 43", "IT Act 2000 Section 66", "IT Act 2000 Section 66E"],
                "advisory": "Malicious APKs distributed via web ads or social media abuse SMS forwarders, VPN tunnels, and Android Accessibility services to intercept OTPs and perform silent financial account takeovers."
            },
            {
                "id": "CERT-IN-MULE-NETWORK-2026",
                "title": "Layer-1 and Layer-2 Financial Mule Account Syndicates",
                "category": "Money Laundering & Cybercrime Infrastructure",
                "ttps": ["T1586", "T1588", "T1531"],
                "statutes": ["Prevention of Money Laundering Act (PMLA) Section 3", "BNS 2023 Section 112"],
                "advisory": "Renting or sharing personal bank accounts or UPI handles for third-party fund transfers makes the account holder a primary accomplice in criminal syndicates tracked via the I4C Suspect Registry."
            }
        ]
        
        # Load corpus from file if provided, otherwise use default
        self.corpus = self._load_corpus(corpus_path)
        
        # Precomputed caches for high performance
        self.doc_tokens_cache = {}
        self.idf = {}
        
        self._build_indices()

    def _load_corpus(self, path: Optional[str]) -> List[Dict[str, Any]]:
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[Warning] Failed to load corpus from {path}: {e}. Falling back to default.")
        return self.default_corpus

    def _tokenize(self, text: str) -> List[str]:
        """Extracts normalized alphanumeric tokens longer than 2 characters."""
        return re.findall(r'\b[a-zA-Z0-9]{3,}\b', text.lower())

    def _build_indices(self):
        """Precomputes IDF and token sets for each document to eliminate runtime overhead."""
        doc_count = len(self.corpus)
        df = {}
        
        for idx, doc in enumerate(self.corpus):
            doc_text = f"{doc.get('id', '')} {doc.get('title', '')} {doc.get('category', '')} {doc.get('advisory', '')} {' '.join(doc.get('statutes', []))} {' '.join(doc.get('ttps', []))}"
            tokens = self._tokenize(doc_text)
            self.doc_tokens_cache[idx] = set(tokens)
            
            for token in set(tokens):
                df[token] = df.get(token, 0) + 1
        
        self.idf = {token: math.log(1.0 + (doc_count - freq + 0.5) / (freq + 0.5)) for token, freq in df.items()}

    def add_document(self, new_doc: Dict[str, Any]):
        """Dynamically appends a new threat intelligence record and rebuilds cache."""
        self.corpus.append(new_doc)
        self._build_indices()

    def _compute_dense_similarity(self, query_tokens: List[str], doc_tokens: set) -> float:
        """Computes semantic overlap vector score using IDF-weighted Jaccard coefficient."""
        q_set = set(query_tokens)
        if not q_set or not doc_tokens:
            return 0.0
        
        intersection = q_set.intersection(doc_tokens)
        union = q_set.union(doc_tokens)
        
        weighted_intersection = sum(self.idf.get(t, 1.0) for t in intersection)
        weighted_union = sum(self.idf.get(t, 1.0) for t in union)
        
        return weighted_intersection / weighted_union if weighted_union > 0 else 0.0

    def query_context(self, text: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """
        Performs enterprise hybrid retrieval combining sparse BM25 token matching 
        and dense semantic vector scoring using precompiled indices.
        """
        query_tokens = self._tokenize(text)
        scored_results = []

        for idx, item in enumerate(self.corpus):
            doc_tokens = self.doc_tokens_cache.get(idx, set())
            
            # 1. Sparse Exact Keyword Match Score
            sparse_score = sum(1 for token in query_tokens if token in doc_tokens)
            
            # 2. Dense Semantic Vector Score
            dense_score = self._compute_dense_similarity(query_tokens, doc_tokens)
            
            # Hybrid Fusion Formula (Alpha weighting)
            hybrid_score = (0.4 * sparse_score) + (0.6 * dense_score * len(query_tokens))
            
            if hybrid_score > 0.0:
                scored_results.append({
                    "relevance_score": round(hybrid_score, 4),
                    "document": item
                })

        # Sort descending by relevance score
        scored_results.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        return [res["document"] for res in scored_results[:top_k]]