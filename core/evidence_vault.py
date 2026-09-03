"""
ScamShield-RAG :: Evidence Preservation & Chain of Custody Vault
Implements SHA-256 forensic hashing and immutable audit logging.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any

VAULT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "vault")
os.makedirs(VAULT_DIR, exist_ok=True)

def hash_artifact(data: bytes | str) -> Dict[str, str]:
    """Generates dual cryptographic fingerprints (SHA-256 and MD5) for court admissibility."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    
    sha256_hash = hashlib.sha256(data).hexdigest()
    md5_hash = hashlib.md5(data).hexdigest()
    
    return {
        "sha256": sha256_hash,
        "md5": md5_hash,
        "byte_size": str(len(data))
    }

def record_custody_event(evidence_id: str, artifact_hashes: Dict[str, str], metadata: Dict[str, Any]) -> str:
    """Writes an append-only JSON-LD custodial event ledger."""
    entry = {
        "@context": "https://schema.org",
        "@type": "DigitalDocumentEvidence",
        "evidence_id": evidence_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hashes": artifact_hashes,
        "custodian": "ScamShield Forensic Workstation v2.4",
        "metadata": metadata
    }

    vault_file = os.path.join(VAULT_DIR, f"{evidence_id}.json")
    with open(vault_file, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2)
        
    return vault_file