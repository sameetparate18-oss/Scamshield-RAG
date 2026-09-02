"""
ScamShield-RAG :: Rule-Based Heuristics & Deterministic Safety Checks
Handles regex detection for credential theft, OTP sharing requests, and link safety.
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


# Detect protective warnings (e.g., "do not share your OTP", "never tell your PIN")
RE_OTP_WARN = re.compile(
    r"\b(?:do\s+not|don'?t|never|should\s+not)\s+(?:ever\s+)?(?:share|disclose|give|reveal|send|tell)\b.*?\b(?:otp|pin|password|code)\b",
    re.IGNORECASE
)

# Detect malicious prompts to share/provide OTP
RE_OTP_SHARE = re.compile(
    r"\b(?:please\s+)?(?:share|send|enter|give|provide|tell|reply\s+with)\b.*?\b(?:your\s+)?(?:otp|code|pin)\b",
    re.IGNORECASE
)

RE_DIGITAL_ARREST = re.compile(
    r"\b(?:digital\s+arrest|cbi|narcotics|customs\s+department|arrest\s+warrant|stay\s+on\s+(?:video|call))\b",
    re.IGNORECASE
)

RE_URGENT_KYC = re.compile(
    r"\b(?:kyc\s+expired|account\s+(?:will\s+be\s+)?blocked|suspended|deactivated)\b",
    re.IGNORECASE
)

RE_SUSPICIOUS_LINK = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)*(?:xyz|top|work|bid|verify|net|cc|su)/[^\s]*",
    re.IGNORECASE
)


def run_rules(text: str) -> RuleReport:
    """Evaluates explicit deterministic rules against input text."""
    if not text or not text.strip():
        return RuleReport(rule_based_score=0.0, findings=[])

    findings = []
    score = 0.0

    # 1. OTP Sharing Request vs. Legitimate OTP Warning
    is_otp_warning = bool(RE_OTP_WARN.search(text))
    is_otp_request = bool(RE_OTP_SHARE.search(text))

    # Crucial: If the sentence is a warning telling the user NOT to share OTP,
    # it must NEVER trigger the otp_sharing_request finding.
    if is_otp_request and not is_otp_warning:
        findings.append(Finding(
            rule_name="otp_sharing_request",
            description="Message explicitly solicits an OTP or verification code.",
            severity="HIGH"
        ))
        score += 0.45

    # 2. Digital Arrest / Statutory Impersonation
    if RE_DIGITAL_ARREST.search(text):
        findings.append(Finding(
            rule_name="digital_arrest_coercion",
            description="Presence of impersonated authority or digital arrest threats.",
            severity="HIGH"
        ))
        score += 0.50

    # 3. Urgency / KYC Expiration
    if RE_URGENT_KYC.search(text):
        findings.append(Finding(
            rule_name="kyc_block_intimidation",
            description="Coercive threats of account deactivation or KYC expiration.",
            severity="MEDIUM"
        ))
        score += 0.35

    # 4. Phishing / Suspicious TLD links
    if RE_SUSPICIOUS_LINK.search(text):
        findings.append(Finding(
            rule_name="suspicious_phishing_link",
            description="Contains link to an unverified top-level domain.",
            severity="HIGH"
        ))
        score += 0.40

    final_score = min(1.0, score)
    return RuleReport(rule_based_score=final_score, findings=findings)