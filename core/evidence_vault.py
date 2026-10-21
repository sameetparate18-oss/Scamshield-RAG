"""
ScamShield-RAG :: Evidence Preservation & Chain of Custody Vault
Implements SHA-256 forensic hashing, tamper-evident hash chaining, and immutable audit logging.
"""

import hashlib
import json
import os
import re
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Configure module logging for forensic telemetry
logger = logging.getLogger("ScamShield-EvidenceVault")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

VAULT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "vault"))
os.makedirs(VAULT_DIR, exist_ok=True)

def sanitize_evidence_id(evidence_id: str) -> str:
    """Sanitizes evidence ID string to prevent path traversal attacks."""
    clean_id = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', evidence_id)
    if not clean_id:
        raise ValueError("Invalid or empty evidence ID provided.")
    return clean_id

def hash_artifact(data: bytes | str) -> Dict[str, str]:
    """
    Generates multi-algorithm cryptographic fingerprints (SHA-256 and SHA-512) 
    for strict legal and court admissibility standards.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    
    sha256_hash = hashlib.sha256(data).hexdigest()
    sha512_hash = hashlib.sha512(data).hexdigest()
    
    return {
        "sha256": sha256_hash,
        "sha512": sha512_hash,
        "byte_size": str(len(data))
    }

def record_custody_event(
    evidence_id: str, 
    artifact_hashes: Dict[str, str], 
    metadata: Dict[str, Any], 
    custodian: str = "ScamShield Forensic Workstation v2.6"
) -> Dict[str, Any]:
    """
    Appends an immutable, hash-chained custodial event entry to the evidence ledger.
    Ensures tamper-evidence by linking each entry to the cryptographic hash of its predecessor.
    """
    safe_id = sanitize_evidence_id(evidence_id)
    vault_file = os.path.join(VAULT_DIR, f"{safe_id}.jsonl")
    
    # Load existing chain history to compute the previous entry's hash link
    existing_events: List[Dict[str, Any]] = []
    previous_entry_hash = "GENESIS_BLOCK_ROOT"
    
    if os.path.exists(vault_file):
        try:
            with open(vault_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        event = json.loads(line)
                        existing_events.append(event)
            if existing_events:
                # Compute hash of the latest existing block for chaining
                last_block_str = json.dumps(existing_events[-1], sort_keys=True)
                previous_entry_hash = hashlib.sha256(last_block_str.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.error(f"Error reading existing vault ledger for {safe_id}: {str(e)}")

    # Construct the current custody event payload
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = {
        "@context": "https://schema.org",
        "@type": "DigitalDocumentEvidence",
        "evidence_id": safe_id,
        "timestamp_utc": timestamp,
        "previous_entry_hash": previous_entry_hash,
        "hashes": artifact_hashes,
        "custodian": custodian,
        "metadata": metadata
    }

    # Compute entry cryptographic fingerprint for the chain
    entry_str = json.dumps(entry, sort_keys=True)
    entry["current_entry_hash"] = hashlib.sha256(entry_str.encode("utf-8")).hexdigest()

    # Append atomically to the immutable JSON-L ledger file
    try:
        with open(vault_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        logger.info(f"Successfully recorded custody event for evidence ID: {safe_id}")
    except Exception as e:
        logger.error(f"Failed to write custody event to vault: {str(e)}")
        raise

    return entry

def verify_custody_chain(evidence_id: str) -> Dict[str, Any]:
    """
    Cryptographically verifies the chain of custody ledger for an evidence ID 
    to guarantee no tampering or corruption has occurred.
    """
    safe_id = sanitize_evidence_id(evidence_id)
    vault_file = os.path.join(VAULT_DIR, f"{safe_id}.jsonl")

    if not os.path.exists(vault_file):
        return {"valid": False, "error": "Evidence ledger not found in vault."}

    events = []
    try:
        with open(vault_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
    except Exception as e:
        return {"valid": False, "error": f"Failed to parse ledger: {str(e)}"}

    if not events:
        return {"valid": True, "total_events": 0, "message": "Ledger is empty."}

    expected_prev_hash = "GENESIS_BLOCK_ROOT"
    for idx, event in enumerate(events):
        # 1. Verify previous hash link
        if event.get("previous_entry_hash") != expected_prev_hash:
            return {
                "valid": False,
                "broken_at_index": idx,
                "error": f"Chain integrity broken at event {idx}: Previous hash mismatch."
            }
        
        # 2. Verify current entry hash integrity
        stored_current_hash = event.get("current_entry_hash")
        # Temporarily pop current hash to recompute exact object state
        temp_event = event.copy()
        temp_event.pop("current_entry_hash", None)
        recomputed_hash = hashlib.sha256(json.dumps(temp_event, sort_keys=True).encode("utf-8")).hexdigest()

        if stored_current_hash != recomputed_hash:
            return {
                "valid": False,
                "broken_at_index": idx,
                "error": f"Tampering detected at event {idx}: Content hash does not match signature."
            }

        expected_prev_hash = stored_current_hash

    return {
        "valid": True,
        "total_events": len(events),
        "latest_hash": expected_prev_hash,
        "message": "Chain of custody verified successfully. Zero tampering detected."
    }