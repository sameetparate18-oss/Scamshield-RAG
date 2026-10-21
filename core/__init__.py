"""
ScamShield-RAG Core Intelligence & Forensic Package
Exposes analytical engines, live threat feeds, and evidence tools.
"""

from core.scam_classifier import analyze_threat
from core.web_intel import GlobalWebIntelligence
from core.qr_forensics import decode_upi_qr
from core.dossier_generator import generate_police_requisition_order

__all__ = [
    "analyze_threat",
    "GlobalWebIntelligence",
    "decode_upi_qr",
    "generate_police_requisition_order",
]