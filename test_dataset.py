"""
PhishGuard: GenAI-Enhanced Spear-Phishing & Quishing Detector
Module: test_dataset.py
Role: Mock Data Engineer & Pitch Lead (Member 5)

This module provides 3 ultra-realistic, battle-tested scenarios for judge demonstrations
and Streamlit UI integration:
1. Sample 1: Legitimate Enterprise Notice (Expected Score: 0–15)
2. Sample 2: Quishing MFA Device Bypass (Expected Score: 85–100)
3. Sample 3: VIP Spear-Phishing / BEC Wire Fraud (Expected Score: 80–95)
"""

from typing import Any, Dict, List

# ==============================================================================
# SAMPLE 1: LEGITIMATE ENTERPRISE NOTICE (BENIGN)
# ==============================================================================

SAMPLE_1_RAW_CONTENT = """Delivered-To: alex.morgan@fintech-global.internal
Received: by mail.fintech-global.internal with SMTP id a12so983210
        for <alex.morgan@fintech-global.internal>; Mon, 20 Oct 2026 09:14:22 -0700
Authentication-Results: mx.fintech-global.internal;
       spf=pass (fintech-global.internal: domain of benefits-noreply@corp-internal.net designates 198.51.100.24 as permitted sender) smtp.mailfrom=benefits-noreply@corp-internal.net;
       dkim=pass header.i=@corp-internal.net header.s=k1 header.b=XyZ9810;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=corp-internal.net
From: "Global Benefits Team" <benefits-noreply@corp-internal.net>
Reply-To: <benefits-noreply@corp-internal.net>
To: <alex.morgan@fintech-global.internal>
Subject: Annual Open Benefits Enrollment 2026 - Window Closes Nov 15
Date: Mon, 20 Oct 2026 09:14:00 -0700
Message-ID: <BEN-2026-90412-HR@corp-internal.net>

Dear Alex,

The Annual Open Benefits Enrollment window for the 2027 fiscal plan year is now officially open and will remain accessible until Friday, November 15, 2026, at 11:59 PM EST.

This is your scheduled annual opportunity to review and modify your healthcare, dental, vision, life insurance, and 401(k) retirement allocation elections.

What you should do:
1. Log in to the Corporate HR Portal using your standard Single Sign-On (Okta SSO):
   https://workday.internal-corp.net/benefits/enrollment-2026
2. Review your current dependent coverage and elected contribution tiers.
3. Submit any changes before the deadline. If no changes are submitted, your current elections will automatically roll over, with the exception of Flexible Spending Accounts (FSA).

For questions regarding plan comparisons, please refer to the Benefits Knowledge Base on the corporate intranet or contact People Operations at hr-support@fintech-global.internal.

Best regards,
Global Benefits & Total Rewards Team
FinTech Global Corporation
100 Financial Plaza, New York, NY
"""

SAMPLE_1_TELEMETRY: Dict[str, Any] = {
    "sender_analysis": {
        "from_header": "Global Benefits Team <benefits-noreply@corp-internal.net>",
        "reply_to": "benefits-noreply@corp-internal.net",
        "display_name_mismatch": False,
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS"
    },
    "extracted_urls": [
        {
            "source": "BODY_LINK",
            "initial_url": "https://workday.internal-corp.net/benefits/enrollment-2026",
            "final_url": "https://workday.internal-corp.net/benefits/enrollment-2026",
            "is_redirected": False,
            "domain": "internal-corp.net",
            "domain_age_days": 2840,
            "is_typosquat": False,
            "targeted_brand": None,
            "virustotal_malicious_hits": 0
        }
    ],
    "heuristic_flags": []
}


# ==============================================================================
# SAMPLE 2: QUISHING MFA BYPASS (CRITICAL MALICIOUS)
# ==============================================================================

SAMPLE_2_RAW_CONTENT = """Delivered-To: sarah.jenkins@fintech-global.internal
Received: by mail-relay04.external-mta.com with ESMTP id q882194
        for <sarah.jenkins@fintech-global.internal>; Tue, 21 Oct 2026 14:02:11 +0000
Authentication-Results: mx.fintech-global.internal;
       spf=fail (fintech-global.internal: domain of support@it-security-update-notice.com does not designate 203.0.113.89 as permitted sender) smtp.mailfrom=support@it-security-update-notice.com;
       dkim=none;
       dmarc=fail (p=REJECT) header.from=it-security-update-notice.com
From: "IT Support & Information Security" <support@it-security-update-notice.com>
Reply-To: <noreply-auth@gmail.com>
To: <sarah.jenkins@fintech-global.internal>
Subject: URGENT: Microsoft Authenticator policy update required within 24 hours to prevent account lockout
Date: Tue, 21 Oct 2026 14:01:45 +0000
Message-ID: <SECURITY-ALERT-991204@it-security-update-notice.com>

[SECURITY ALERT: MANDATORY IDENTITY TOKEN MIGRATION]

Attention sarah.jenkins,

Our enterprise Microsoft Entra ID tenant is undergoing mandatory zero-trust migration. In compliance with Information Security Directive SEC-2026-9, all employees must re-authenticate their mobile multi-factor authenticator device immediately.

ACTION REQUIRED: You have 24 HOURS to complete this registration. Failure to verify your device before 2:00 PM UTC tomorrow will trigger automated account suspension, revoking access to Microsoft 365, Outlook, and corporate VPN gateways.

------------------------------------------------------------------------
[ PHYSICAL QR CODE ATTACHMENT DETECTED ]
Decoded Payload: https://login-m1crosoft-auth.com/mfa-verify?session=893247&target=sarah.jenkins
------------------------------------------------------------------------

Instructions:
1. Open the camera or QR scanner on your corporate or personal smartphone.
2. Scan the secure QR verification code above.
3. Authenticate with your enterprise username, password, and mobile push code to sync your token.

Do NOT forward this notice. Each QR code is uniquely tied to your identity profile.

Enterprise Cyber Defense Operations Center
Microsoft Certified Cloud Solutions Partner
"""

SAMPLE_2_TELEMETRY: Dict[str, Any] = {
    "sender_analysis": {
        "from_header": "IT Support & Information Security <support@it-security-update-notice.com>",
        "reply_to": "noreply-auth@gmail.com",
        "display_name_mismatch": True,
        "spf_status": "FAIL",
        "dkim_status": "NONE",
        "dmarc_status": "FAIL"
    },
    "extracted_urls": [
        {
            "source": "QR_CODE",
            "initial_url": "https://login-m1crosoft-auth.com/mfa-verify?session=893247&target=sarah.jenkins",
            "final_url": "https://login-m1crosoft-auth.com/mfa-verify?session=893247&target=sarah.jenkins",
            "is_redirected": False,
            "domain": "login-m1crosoft-auth.com",
            "domain_age_days": 2,
            "is_typosquat": True,
            "targeted_brand": "Microsoft",
            "virustotal_malicious_hits": 14
        }
    ],
    "heuristic_flags": [
        "Domain age < 5 days (Registered 2 days ago)",
        "Typosquatting detected: Target brand 'Microsoft' mimicked with 'm1crosoft'",
        "SPF validation failed: Sender IP not authorized",
        "DMARC policy rejection: Domain authentication failed",
        "QR code payload points to external unauthenticated login lure",
        "Reply-To header routes to free consumer webmail (gmail.com)",
        "VirusTotal alert: 14 engines detect phishing/malicious host"
    ]
}


# ==============================================================================
# SAMPLE 3: VIP SPEAR-PHISHING / BEC WIRE FRAUD (HIGH-VALUE TARGET)
# ==============================================================================

SAMPLE_3_RAW_CONTENT = """Delivered-To: david.chen@fintech-global.internal
Received: by mail-out.google.com with SMTP id v92so441209
        for <david.chen@fintech-global.internal>; Wed, 22 Oct 2026 11:22:04 -0400
Authentication-Results: mx.fintech-global.internal;
       spf=pass (google.com: domain of ceo-internal-alerts@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=ceo-internal-alerts@gmail.com;
       dkim=pass header.i=@gmail.com header.s=20230601;
       dmarc=fail (p=REJECT header.from=ceo-internal-alerts@gmail.com display="Robert Sterling - Chief Executive Officer")
From: "Robert Sterling - Chief Executive Officer" <ceo-internal-alerts@gmail.com>
Reply-To: <ceo-internal-alerts@gmail.com>
To: "David Chen - VP Finance" <david.chen@fintech-global.internal>
Subject: Wire transfer for Project Falcon closing today - keep this confidential
Date: Wed, 22 Oct 2026 11:21:40 -0400
Message-ID: <CA+Gq89x20261022@mail.gmail.com>

Hey David,

I am currently on the tarmac boarding an unscheduled flight to London to finalize the definitive purchase agreement for the Project Falcon acquisition.

Our outside counsel at Latham & Watkins just notified me that the closing escrow deposit of $148,500.00 USD must be settled into the designated holding account before 3:00 PM EST today to avoid statutory default on the contract covenants.

Because this transaction is governed by strict SEC non-disclosure covenants, do NOT route this through the standard Jira procurement queue or discuss this with the broader accounting department until our public press release goes out tomorrow morning.

Please execute the wire immediately using the closing escrow instructions below:
Beneficiary Bank: Barclay's Commercial NY
Routing / ABA: 026009593
Account Number: 4892-1092-4418
Beneficiary: Falcon Acquisition Holding LLC
Amount: $148,500.00 USD
Reference: Project Falcon - Closing Tranche A

I will be in the air without cellular service for the next 6 hours, so reply directly to this email confirmation once the SWIFT/Fedwire confirmation number is generated. I'm counting on you to get this across the finish line.

Robert Sterling
Chief Executive Officer
FinTech Global Corporation
Sent from my iPad
"""

SAMPLE_3_TELEMETRY: Dict[str, Any] = {
    "sender_analysis": {
        "from_header": "Robert Sterling - Chief Executive Officer <ceo-internal-alerts@gmail.com>",
        "reply_to": "ceo-internal-alerts@gmail.com",
        "display_name_mismatch": True,
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "FAIL"
    },
    "extracted_urls": [],
    "heuristic_flags": [
        "Display name spoofing detected: Executive 'Robert Sterling' paired with external gmail.com address",
        "Sender domain is free public webmail (gmail.com) attempting to represent internal corporate executive",
        "DMARC organizational alignment failed: Sending domain does not match enterprise organization",
        "High-value financial urgency keywords identified: 'wire transfer', '$148,500.00', 'closing today', 'escrow'",
        "Authority coercion & out-of-band communication suppression: 'keep this confidential', 'do NOT route through Jira', 'on the tarmac boarding flight'"
    ]
}


# ==============================================================================
# STRUCTURED DATASET EXPORT FOR STREAMLIT UI & JUDGE DEMOS
# ==============================================================================

DEMO_SAMPLES: Dict[str, Dict[str, Any]] = {
    "sample_1": {
        "id": "sample_1",
        "name": "Sample 1: Legitimate Enterprise Notice (Benign)",
        "category": "BENIGN",
        "description": "Quarterly employee benefits notice from People Ops with valid cryptographic signatures and authentic corporate intranet links.",
        "expected_score_range": (0, 15),
        "expected_threat_level": "SAFE",
        "raw_content": SAMPLE_1_RAW_CONTENT,
        "telemetry": SAMPLE_1_TELEMETRY,
        "judge_focus": "Validates zero-false-positive precision on authentic business communication."
    },
    "sample_2": {
        "id": "sample_2",
        "name": "Sample 2: Quishing MFA Bypass (Critical Attack)",
        "category": "QUISHING",
        "description": "Urgent IT Authenticator policy lure containing a QR code payload routing to a 2-day-old typosquat domain with VirusTotal detections.",
        "expected_score_range": (85, 100),
        "expected_threat_level": "MALICIOUS",
        "raw_content": SAMPLE_2_RAW_CONTENT,
        "telemetry": SAMPLE_2_TELEMETRY,
        "judge_focus": "Demonstrates multi-modal defense against modern QR code mobile bypass vectors."
    },
    "sample_3": {
        "id": "sample_3",
        "name": "Sample 3: VIP Spear-Phishing / BEC (High-Value Fraud)",
        "category": "BEC_SPEARPHISHING",
        "description": "CEO impersonation via Gmail address with display name spoofing demanding an urgent $148.5k acquisition wire transfer under confidentiality pretext.",
        "expected_score_range": (80, 95),
        "expected_threat_level": "MALICIOUS",
        "raw_content": SAMPLE_3_RAW_CONTENT,
        "telemetry": SAMPLE_3_TELEMETRY,
        "judge_focus": "Demonstrates detection of zero-link executive impersonation and psychological authority coercion."
    }
}


def get_sample_names() -> List[str]:
    """Returns list of display names for Streamlit selectbox."""
    return [sample["name"] for sample in DEMO_SAMPLES.values()]


def get_sample_by_id(sample_id: str) -> Dict[str, Any]:
    """Fetches sample payload by key ID ('sample_1', 'sample_2', 'sample_3')."""
    return DEMO_SAMPLES.get(sample_id, DEMO_SAMPLES["sample_1"])


def get_sample_by_name(name: str) -> Dict[str, Any]:
    """Fetches sample payload by display name for Streamlit UI dropdown selection."""
    for sample in DEMO_SAMPLES.values():
        if sample["name"] == name:
            return sample
    return DEMO_SAMPLES["sample_1"]
