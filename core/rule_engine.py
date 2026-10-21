"""
ScamShield-RAG :: Rule-Based Heuristics & Deterministic Safety Checks (v10.0-Ultimate)
Engineered with adversarial text normalization, zero-day evasion filters, 
and expanded threat patterns for digital arrest, task scams, APK trojans, and UPI fraud.
"""

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    rule_name: str
    description: str
    severity: str  # HIGH, MEDIUM, LOW


@dataclass
class RuleReport:
    rule_based_score: float
    findings: List[Finding] = field(default_factory=list)

    def triggered_findings(self) -> List[Finding]:
        return self.findings


# ==============================================================================
# ADVERSARIAL TEXT NORMALIZATION & OBFUSCATION DEFEAT
# ==============================================================================
def normalize_adversarial_text(text: str) -> str:
    """Neutralizes zero-width spaces, common leetspeak substitutions, and unicode trickery."""
    if not text:
        return ""
    # Remove zero-width spaces, soft hyphens, and invisible formatting artifacts
    cleaned = re.sub(r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]", "", text)
    
    # Basic leetspeak normalization for high-value targets (0tp -> otp, p1n -> pin)
    leetspeak_map = {
        "0tp": "otp",
        "p1n": "pin",
        "c0de": "code",
        "5bi": "sbi",
        "b4nk": "bank"
    }
    for target, replacement in leetspeak_map.items():
        cleaned = cleaned.replace(target, replacement)
        
    return cleaned


# ==============================================================================
# EXPANDED DETERMINISTIC REGEX SUITE (2026 THREAT LANDSCAPE)
# ==============================================================================

# 1. Protective security warnings (Context Guardrail)
RE_OTP_WARN = re.compile(
    r"\b(?:do\s+not|don'?t|never|should\s+not)\s+(?:ever\s+)?(?:share|disclose|give|reveal|send|tell)\b.*?\b(?:otp|pin|password|code|cvv)\b",
    re.IGNORECASE
)

# 2. Malicious OTP / Credential Request
RE_OTP_SHARE = re.compile(
    r"\b(?:please\s+)?(?:share|send|enter|give|provide|tell|reply\s+with|type)\b.*?\b(?:your\s+)?(?:otp|code|pin|cvv|password|upi\s+pin)\b",
    re.IGNORECASE
)

# 3. Digital Arrest & Law Enforcement Impersonation (CBI, ED, Customs, Supreme Court)
RE_DIGITAL_ARREST = re.compile(
    r"\b(?:digital\s+arrest|cbi|ed|enforcement\s+directorate|narcotics|customs\s+department|arrest\s+warrant|supreme\s+court\s+stay|video\s+interrogation)\b",
    re.IGNORECASE
)

# 4. Urgent KYC / Bank Account Deactivation Intimidation
RE_URGENT_KYC = re.compile(
    r"\b(?:kyc\s+expired|account\s+(?:will\s+be\s+)?(?:blocked|suspended|deactivated|frozen|terminated))\b",
    re.IGNORECASE
)

# 5. Suspicious Phishing Links (Generic TLDs & dynamic shorteners)
RE_SUSPICIOUS_LINK = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)*(?:xyz|top|work|bid|verify|net|cc|su|ru|ink|gq|ml|tk|cf|apk)/[^\s]*",
    re.IGNORECASE
)

# 6. Malicious APK Sideloading / Smishing Trojan
RE_APK_MALWARE = re.compile(
    r"\b(?:download\s+(?:this\s+)?apk|install\s+(?:the\s+)?app|update\s+app\s+via\s+link|sideload|android\s+package)\b",
    re.IGNORECASE
)

# 7. Part-Time Job / YouTube Task / Paid Rating Scams
RE_TASK_SCAM = re.compile(
    r"\b(?:part[-\s]time\s+job|work\s+from\s+home|daily\s+income|youtube\s+(?:video\s+)?like\s+and\s+earn|telegram\s+task|merchant\s+task|prepaid\s+task)\b",
    re.IGNORECASE
)

# 8. UPI Collect Request / Fake Refund Manipulation
RE_UPI_COLLECT = re.compile(
    r"\b(?:collect\s+request|approve\s+collect|receive\s+cashback|refund\s+amount|scan\s+qr\s+to\s+(?:receive|get)\s+money)\b",
    re.IGNORECASE
)


def run_rules(text: str) -> RuleReport:
    """Evaluates explicit deterministic rules against adversarial-normalized input text."""
    if not text or not text.strip():
        return RuleReport(rule_based_score=0.0, findings=[])

    normalized_text = normalize_adversarial_text(text)
    findings = []
    score = 0.0

    # 1. OTP Sharing Request vs. Legitimate Security Warning
    is_otp_warning = bool(RE_OTP_WARN.search(normalized_text))
    is_otp_request = bool(RE_OTP_SHARE.search(normalized_text))

    if is_otp_request and not is_otp_warning:
        findings.append(Finding(
            rule_name="otp_sharing_request",
            description="Message explicitly solicits an OTP, PIN, or sensitive authentication code.",
            severity="HIGH"
        ))
        score += 0.40

    # 2. Digital Arrest / Statutory Impersonation Coercion
    if RE_DIGITAL_ARREST.search(normalized_text):
        findings.append(Finding(
            rule_name="digital_arrest_coercion",
            description="Presence of law enforcement impersonation and digital arrest threats.",
            severity="HIGH"
        ))
        score += 0.45

    # 3. Urgency / KYC Block Intimidation
    if RE_URGENT_KYC.search(normalized_text):
        findings.append(Finding(
            rule_name="kyc_block_intimidation",
            description="Coercive intimidation concerning bank account deactivation or KYC expiration.",
            severity="MEDIUM"
        ))
        score += 0.30

    # 4. Phishing / Suspicious TLD Links
    if RE_SUSPICIOUS_LINK.search(normalized_text):
        findings.append(Finding(
            rule_name="suspicious_phishing_link",
            description="Contains link pointing to an unverified high-risk TLD or phishing domain.",
            severity="HIGH"
        ))
        score += 0.35

    # 5. Malicious APK Sideloading
    if RE_APK_MALWARE.search(normalized_text):
        findings.append(Finding(
            rule_name="malicious_apk_sideloading",
            description="Prompts user to install an unverified Android application package (APK Trojan).",
            severity="HIGH"
        ))
        score += 0.45

    # 6. Part-Time Job / Task Scam
    if RE_TASK_SCAM.search(normalized_text):
        findings.append(Finding(
            rule_name="part_time_task_scam",
            description="Features classic task scam vectors (YouTube likes, prepaid rating tasks, guaranteed daily profits).",
            severity="MEDIUM"
        ))
        score += 0.30

    # 7. UPI Collect Request Fraud
    if RE_UPI_COLLECT.search(normalized_text):
        findings.append(Finding(
            rule_name="upi_collect_request_fraud",
            description="Manipulates user into approving a UPI 'Collect Request' under the guise of receiving funds or refunds.",
            severity="HIGH"
        ))
        score += 0.40

    # Cap final deterministic rule score at 1.0 maximum
    final_score = min(1.0, score)
    return RuleReport(rule_based_score=final_score, findings=findings)