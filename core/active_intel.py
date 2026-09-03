"""
ScamShield-RAG :: Active Threat Intelligence & Autonomous Deception Engine
Handles live redirect unwrapping, mule handle profiling, and honeypot response generation.
"""

import urllib.request
import urllib.parse
import http.client
import ssl
import re
from typing import Dict, Any, List

def unwrap_redirect_chain(url: str, max_hops: int = 5) -> Dict[str, Any]:
    """
    Traces HTTP redirect chains passively without downloading malicious binaries.
    Unveils cloaked destinations hidden behind URL shorteners.
    """
    chain = [url]
    current_url = url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for _ in range(max_hops):
        try:
            parsed = urllib.parse.urlparse(current_url)
            if not parsed.scheme or not parsed.netloc:
                break
            
            conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(parsed.netloc, timeout=3.0, context=ctx if parsed.scheme == "https" else None)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            
            conn.request("HEAD", path, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            resp = conn.getresponse()
            
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location")
                if not location:
                    break
                # Handle relative redirects
                current_url = urllib.parse.urljoin(current_url, location)
                chain.append(current_url)
            else:
                break
        except Exception:
            break

    return {
        "original_url": url,
        "final_destination": chain[-1],
        "total_hops": len(chain) - 1,
        "redirect_chain": chain,
        "is_cloaked": len(chain) > 1
    }

def profile_mule_account(vpa: str) -> Dict[str, Any]:
    """
    Applies bank forensic heuristics to detect money-mule account patterns.
    """
    vpa = (vpa or "").strip().lower()
    score = 0.0
    flags = []

    if "@" not in vpa:
        return {"risk_score": 0.0, "mule_confidence": "N/A", "flags": ["Invalid VPA format."]}

    user, handle = vpa.split("@", 1)

    # Heuristic 1: Raw phone number used as VPA (frequently burner SIMs / mule wallets)
    if re.fullmatch(r"[6-9]\d{9}", user):
        score += 0.35
        flags.append("VPA username is a raw 10-digit mobile number (High correlation with disposable prepaid SIMs).")

    # Heuristic 2: Random alphanumeric noise / Hash (Common in crypto off-ramp P2P accounts)
    if re.fullmatch(r"[a-f0-9]{12,}", user) or (len(user) > 10 and sum(c.isdigit() for c in user) > 5):
        score += 0.40
        flags.append("VPA utilizes high-entropy algorithmic identifiers (Mule syndicate signature).")

    # Heuristic 3: Coercive / Impersonation prefixes
    spoof_terms = ["refund", "helpline", "treasury", "support", "kyc", "nodal", "cbi", "tax"]
    if any(t in user for t in spoof_terms):
        score += 0.55
        flags.append(f"Authority spoofing keyword embedded directly in payment address identifier.")

    score = min(1.0, round(score, 2))
    confidence = "CRITICAL" if score >= 0.7 else ("ELEVATED" if score >= 0.35 else "NOMINAL")

    return {
        "vpa": vpa,
        "mule_risk_score": score,
        "mule_confidence": confidence,
        "flags": flags or ["No money-mule synthetic traits identified."]
    }

def generate_honeypot_counter_bait(category: str, attacker_text: str) -> Dict[str, str]:
    """
    Autonomous Deception Engine: Generates psychological counter-bait responses
    to keep scammers on the hook while extracting their secondary accounts and phone numbers.
    """
    cat = (category or "").lower()

    if "arrest" in cat or "cbi" in cat or "narcotics" in cat:
        persona = "Panicked Elderly Citizen"
        bait = (
            "Sir please don't send police to my house, I have heart problems! I am ready to clear my name. "
            "My bank branch is closed today. Can you send me an alternate UPI ID or official bank account number "
            "where my son can directly transfer the security clearance deposit? Please give me 15 minutes."
        )
        objective = "Extracts secondary reserve mule bank account number / IFSC code."
    elif "electricity" in cat or "bill" in cat:
        persona = "Confused Homeowner"
        bait = (
            "Sir I just checked my electricity receipt and payment went through last week! Which meter number is "
            "showing unpaid on your computer? Can you give me your direct desk officer number or another payment link? "
            "The current link is showing server error."
        )
        objective = "Forces scammer to provide direct phone number or secondary payment portal."
    elif "task" in cat or "job" in cat or "telegram" in cat:
        persona = "Eager High-Roller Investor"
        bait = (
            "I completed the YouTube review task and received the ₹150! I want to join the VIP ₹50,000 tier directly. "
            "My company account requires an official merchant invoice or bank current account. Please send me the "
            "manager's Telegram link and company payment details so I can deposit ₹50,000 now."
        )
        objective = "Bates scammer into burning their highest-tier VIP mule bank accounts."
    else:
        persona = "Standard Decoy"
        bait = (
            "I received your urgent notice. I am trying to pay from my mobile app but it says transaction limit exceeded. "
            "Please provide your supervisor's phone number or an alternate bank account so I can complete this right away."
        )
        objective = "Extracts auxiliary contact vectors for NCRP complaint enrichment."

    return {
        "persona": persona,
        "bait_script": bait,
        "intelligence_objective": objective
    }