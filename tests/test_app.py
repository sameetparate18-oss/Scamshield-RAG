"""
Basic automated tests for ScamShield-RAG core engine.

Run with:
    python -m pytest tests/test_app.py -v
or simply:
    python tests/test_app.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rule_engine import run_rules
from core.verdict_engine import VerdictEngine


# A small, fixed set of known scam/legit examples used to sanity-check the
# pipeline. This is NOT the full evaluation set (see data/test_set for that
# once you build it) -- just a fast smoke test to catch regressions.
SMOKE_TEST_CASES = [
    ("Sir your parcel is on hold, pay Rs 39 customs fee: http://fake-delivery.xyz", "SCAM"),
    ("This is Customs Department. You are under digital arrest, do not disconnect, transfer funds now.", "SCAM"),
    ("123456 is your OTP for login to XYZ Bank. Do not share this OTP with anyone including bank staff.", "LEGIT"),
    ("Your Amazon order #402-1234567 is out for delivery today. Track: amazon.in/orders", "LEGIT"),
    ("Congratulations! Selected for part time job earn Rs 5000 daily. Registration fee Rs 500. Join: t.me/xxxx", "SCAM"),
    ("Your SBI account KYC has expired. Account will be blocked in 24 hours. Update: http://sbi-kyc-verify.net", "SCAM"),
]


def test_rule_engine_no_crash_on_empty_string():
    report = run_rules("")
    assert report.rule_based_score == 0.0


def test_rule_engine_flags_otp_sharing_request():
    report = run_rules("Please share your OTP with our agent to verify your account.")
    triggered_names = [f.rule_name for f in report.triggered_findings()]
    assert "otp_sharing_request" in triggered_names


def test_rule_engine_does_not_flag_otp_warning():
    report = run_rules("Do not share your OTP with anyone, including bank staff.")
    triggered_names = [f.rule_name for f in report.triggered_findings()]
    assert "otp_sharing_request" not in triggered_names


def test_verdict_engine_smoke_suite():
    engine = VerdictEngine(use_llm=False)
    correct = 0
    for text, expected in SMOKE_TEST_CASES:
        verdict = engine.analyze(text)
        predicted = "SCAM" if verdict.verdict in ("LIKELY_SCAM", "SUSPICIOUS") else "LEGIT"
        if predicted == expected:
            correct += 1
        else:
            print(f"MISMATCH: expected={expected} got={verdict.verdict} | {text[:60]}")
    accuracy = correct / len(SMOKE_TEST_CASES)
    assert accuracy >= 0.8, f"Smoke test accuracy too low: {accuracy:.2f}"


if __name__ == "__main__":
    # Allow running this file directly without pytest
    test_rule_engine_no_crash_on_empty_string()
    print("PASS: test_rule_engine_no_crash_on_empty_string")

    test_rule_engine_flags_otp_sharing_request()
    print("PASS: test_rule_engine_flags_otp_sharing_request")

    test_rule_engine_does_not_flag_otp_warning()
    print("PASS: test_rule_engine_does_not_flag_otp_warning")

    test_verdict_engine_smoke_suite()
    print("PASS: test_verdict_engine_smoke_suite")

    print("\nAll tests passed.")
