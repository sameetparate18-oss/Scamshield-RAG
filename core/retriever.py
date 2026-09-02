"""
ScamShield-RAG :: Retrieval Engine
-----------------------------------
Embeds the scam-pattern knowledge base (and legit examples) using a
multilingual sentence-transformer model, indexes them with FAISS, and
exposes a retrieve() function that returns the top-k most similar
known patterns for a given input message.

Why multilingual embeddings:
Indian scam messages are frequently code-mixed (Hindi+English, "Hinglish"),
so we use `paraphrase-multilingual-MiniLM-L12-v2` which handles this much
better than an English-only model.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional

import numpy as np
import faiss

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KB_SCAM_PATH = os.path.join(BASE_DIR, "data", "knowledge_base", "scam_patterns.json")
KB_LEGIT_PATH = os.path.join(BASE_DIR, "data", "knowledge_base", "legit_examples.json")

MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"

# NOTE ON OFFLINE FALLBACK:
# The transformer embedding model needs to be downloaded from HuggingFace Hub
# on first run (requires internet). If that's unavailable (e.g. restricted
# sandbox, offline demo environment), we automatically fall back to a
# TF-IDF based vectorizer so the retrieval pipeline still runs end-to-end.
# On your own machine / Colab with normal internet access, the transformer
# path will be used automatically and will give much better semantic
# matching (important for paraphrased/code-mixed scam messages).
try:
    from sentence_transformers import SentenceTransformer
    _TRANSFORMERS_AVAILABLE = True
except ImportError:
    _TRANSFORMERS_AVAILABLE = False


@dataclass
class RetrievedEvidence:
    id: str
    label: str  # "scam" or "legit"
    category: str
    text_matched: str          # the example_text that matched
    description: str           # pattern_description or why_legit
    red_flags: List[str] = field(default_factory=list)
    source_citation: str = ""
    similarity_score: float = 0.0


class ScamKnowledgeRetriever:
    def __init__(self, model_name: str = MODEL_NAME, force_tfidf: bool = False):
        self.entries: List[Dict] = []
        self.index: Optional[faiss.Index] = None
        self.mode = None  # "transformer" or "tfidf"
        self.model = None
        self.tfidf_vectorizer = None

        if _TRANSFORMERS_AVAILABLE and not force_tfidf:
            try:
                print(f"[Retriever] Loading embedding model: {model_name} ...")
                self.model = SentenceTransformer(model_name)
                self.mode = "transformer"
            except Exception as e:
                print(f"[Retriever] Could not load transformer model ({e}).")
                print("[Retriever] Falling back to TF-IDF embeddings (offline mode).")
                self.mode = "tfidf"
        else:
            self.mode = "tfidf"

        self._build_index()

    def _load_knowledge_base(self) -> List[Dict]:
        entries = []
        with open(KB_SCAM_PATH, "r", encoding="utf-8") as f:
            scams = json.load(f)
        for s in scams:
            entries.append({
                "id": s["id"],
                "label": "scam",
                "category": s["category"],
                "text_matched": s["example_text"],
                "description": s["pattern_description"],
                "red_flags": s.get("red_flags", []),
                "source_citation": s.get("source_citation", ""),
                # what we embed: combine example text + description for richer matching
                "embed_text": s["example_text"] + " " + s["pattern_description"],
            })

        with open(KB_LEGIT_PATH, "r", encoding="utf-8") as f:
            legits = json.load(f)
        for l in legits:
            entries.append({
                "id": l["id"],
                "label": "legit",
                "category": l["category"],
                "text_matched": l["example_text"],
                "description": l.get("why_legit", ""),
                "red_flags": [],
                "source_citation": l.get("source_citation", ""),
                "embed_text": l["example_text"] + " " + l.get("why_legit", ""),
            })
        return entries

    def _embed_texts(self, texts: List[str], is_query: bool = False) -> np.ndarray:
        """Embed a list of texts using whichever backend is active."""
        if self.mode == "transformer":
            embeddings = self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
            return np.array(embeddings).astype("float32")
        else:
            # TF-IDF fallback
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.preprocessing import normalize as sk_normalize

            if is_query:
                vecs = self.tfidf_vectorizer.transform(texts)
            else:
                self.tfidf_vectorizer = TfidfVectorizer(
                    lowercase=True, ngram_range=(1, 2), max_features=5000
                )
                vecs = self.tfidf_vectorizer.fit_transform(texts)
            vecs = sk_normalize(vecs)
            return vecs.toarray().astype("float32")

    def _build_index(self):
        self.entries = self._load_knowledge_base()
        texts = [e["embed_text"] for e in self.entries]
        print(f"[Retriever] Embedding {len(texts)} knowledge base entries using '{self.mode}' backend ...")
        embeddings = self._embed_texts(texts, is_query=False)

        dim = embeddings.shape[1]
        # Inner product on normalized vectors == cosine similarity
        self.index = faiss.IndexFlatIP(dim)
        self.index.add(embeddings)
        print(f"[Retriever] FAISS index built with dimension {dim}.")

    def retrieve(self, query_text: str, top_k: int = 3) -> List[RetrievedEvidence]:
        """Return top_k most similar knowledge base entries for the query text."""
        if not query_text or not query_text.strip():
            return []

        query_emb = self._embed_texts([query_text], is_query=True)

        scores, indices = self.index.search(query_emb, top_k)
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx == -1:
                continue
            entry = self.entries[idx]
            results.append(RetrievedEvidence(
                id=entry["id"],
                label=entry["label"],
                category=entry["category"],
                text_matched=entry["text_matched"],
                description=entry["description"],
                red_flags=entry["red_flags"],
                source_citation=entry["source_citation"],
                similarity_score=float(score),
            ))
        return results


# Quick manual test when run directly
if __name__ == "__main__":
    retriever = ScamKnowledgeRetriever()

    test_messages = [
        "Sir aapka parcel customs mein hai, 39 rupees clearance fee pay karo is link par: http://fake-post.xyz",
        "123456 is your OTP for login. Do not share with anyone.",
        "You are under digital arrest, do not disconnect the call, transfer money for verification",
    ]

    for msg in test_messages:
        print("\n" + "=" * 80)
        print(f"QUERY: {msg}")
        results = retriever.retrieve(msg, top_k=2)
        for r in results:
            print(f"  -> [{r.label.upper()}] {r.category} (score={r.similarity_score:.3f})")
            print(f"     Source: {r.source_citation}")
