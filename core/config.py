"""
ScamShield-RAG :: Central Configuration & Runtime Constants
Enterprise-Grade Environment & Design System Configuration
"""

import os
from typing import Dict

# Core Directory Architecture
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Runtime Data Storage Paths (Overridable via Environment Variables)
HISTORY_FILE = os.getenv("SCAMSHIELD_HISTORY_FILE", os.path.join(DATA_DIR, "scamshield_audit.json"))
KB_FILE = os.getenv("SCAMSHIELD_KB_FILE", os.path.join(DATA_DIR, "fraud_kb.json"))
MAX_AUDIT_RECORDS = int(os.getenv("SCAMSHIELD_MAX_AUDIT_RECORDS", 1000))

# Threat Intelligence Engine Parameters
DEFAULT_REQUEST_TIMEOUT = 5.0  # Seconds
MAX_REDIRECT_HOPS = 5
ENABLE_TELEMETRY_LOGGING = os.getenv("SCAMSHIELD_TELEMETRY", "True").lower() == "true"

# Legal & Academic Disclaimer
APP_DISCLAIMER = (
    "ScamShield-RAG is an academic and cyber defense intelligence prototype. "
    "Verdicts are computed via multi-vector neural matching and deterministic heuristics "
    "against international fraud databases (CERT-In, IC3, Interpol, Europol). Not a legal determination."
)

# Advanced Cyber-Theme Design System (Cyberpunk/SOC Dark Mode)
THEME: Dict[str, str] = {
    "bg_app": "#06090F",
    "bg_sidebar": "#0A0E17",
    "bg_card": "#101624",
    "bg_card_inner": "#080B13",
    "border": "#1E293B",
    "border_glow": "#38BDF8",
    "accent": "#00F0FF",
    "accent_hover": "#0EA5E9",
    "text_main": "#F8FAFC",
    "text_muted": "#94A3B8",
    "text_dim": "#475569",
    "scam": "#FF3366",
    "scam_bg": "#2A0813",
    "suspicious": "#FBBF24",
    "suspicious_bg": "#2B1A04",
    "safe": "#10B981",
    "safe_bg": "#022B1E",
    # Extended UI Design Tokens
    "font_family": "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    "shadow_card": "0 4px 20px -2px rgba(0, 240, 255, 0.05)",
    "transition_speed": "0.2s ease-in-out"
}