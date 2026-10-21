"""
ScamShield-RAG :: Active Threat Intelligence & Autonomous Deception Engine
Handles live redirect unwrapping, mule handle profiling, and honeypot response generation.
"""

import asyncio
import httpx
import logging
import re
from typing import Dict, Any, List

# Configure module logging for threat telemetry
logger = logging.getLogger("ScamShield-ActiveIntel")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def unwrap_redirect_chain(url: str, max_hops: int = 5) -> Dict[str, Any]:
    """
    Traces HTTP redirect chains passively without downloading malicious binaries.
    Unveils cloaked destinations hidden behind URL shorteners.
    """
    chain = [url]
    current_url = url
    status_history = []

    # Use synchronous httpx for standalone calls
    with httpx.Client(headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, verify=False) as client:
        for hop in range(max_hops):
            try:
                response = client.head(current_url, follow_redirects=False, timeout=4.0)
                status_history.append({"url": current_url, "status": response.status_code})

                # If server rejects HEAD (e.g. 403/405), fallback to GET
                if response.status_code in (403, 405):
                    response = client.get(current_url, follow_redirects=False, timeout=4.0)
                    status_history[-1]["status"] = response.status_code

                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        break
                    
                    next_url = str(httpx.URL(current_url).join(location))
                    if next_url in chain:
                        logger.warning(f"Redirect loop detected at: {next_url}")
                        break
                    
                    current_url = next_url
                    chain.append(current_url)
                else:
                    break
            except Exception as e:
                logger.error(f"Error unwrapping redirect at hop {hop} ({current_url}): {str(e)}")
                break

    return {
        "original_url": url,
        "final_destination": chain[-1],
        "total_hops": len(chain) - 1,
        "redirect_chain": chain,
        "status_history": status_history,
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
        return {"vpa": vpa, "risk_score": 1.0, "mule_confidence": "HIGH", "flags": ["Malformed VPA format."]}

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
    spoof_terms = ["refund", "helpline", "treasury", "support", "kyc", "nodal", "cbi", "tax", "police"]
    if any(t in user for t in spoof_terms):
        score += 0.55
        flags.append("Authority spoofing keyword embedded directly in payment address identifier.")

    score = min(1.0, round(score, 2))
    confidence = "CRITICAL" if score >= 0.7 else ("ELEVATED" if score >= 0.35 else "NOMINAL")

    return {
        "vpa": vpa,
        "mule_risk_score": score,
        "mule_confidence": confidence,
        "flags": flags or ["No money-mule synthetic traits identified."]
    }

def generate_honeypot_counter_bait(category: str, attacker_text: str = "") -> Dict[str, str]:
    """
    Autonomous Deception Engine: Generates psychological counter-bait responses
    to keep scammers on the hook while extracting their secondary accounts and phone numbers.
    """
    cat = (category or "").lower()

    if any(k in cat for k in ["arrest", "cbi", "narcotics", "police"]):
        persona = "Panicked Elderly Citizen"
        bait = (
            "Sir please don't send police to my house, I have heart problems! I am ready to clear my name. "
            "My bank branch is closed today. Can you send me an alternate UPI ID or official bank account number "
            "where my son can directly transfer the security clearance deposit? Please give me 15 minutes."
        )
        objective = "Extracts secondary reserve mule bank account number / IFSC code."
    elif any(k in cat for k in ["electricity", "bill"]):
        persona = "Confused Homeowner"
        bait = (
            "Sir I just checked my electricity receipt and payment went through last week! Which meter number is "
            "showing unpaid on your computer? Can you give me your direct desk officer number or another payment link? "
            "The current link is showing server error."
        )
        objective = "Forces scammer to provide direct phone number or secondary payment portal."
    elif any(k in cat for k in ["task", "job", "telegram"]):
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