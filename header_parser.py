"""Extract sender identity and authentication results from raw email headers."""

import re
from email import policy
from email.parser import Parser
from email.utils import getaddresses

_AUTH_RESULT_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|hardfail|neutral|none|"
    r"temperror|permerror|policy|unknown)\b",
    re.IGNORECASE,
)
_EXECUTIVE_PATTERN = re.compile(
    r"\b(ceo|cfo|cto|coo|president|vice president|"
    r"chief executive|chief financial|chief technology|"
    r"managing director|director)\b",
    re.IGNORECASE,
)
_COMPANY_PATTERN = re.compile(
    r"\b(microsoft|google|apple|amazon|paypal|meta|netflix|"
    r"adobe|docusign|dropbox|salesforce|oracle|linkedin)\b",
    re.IGNORECASE,
)
_CONSUMER_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}
_FAILED_AUTH_RESULTS = {
    "fail",
    "softfail",
    "hardfail",
    "neutral",
    "temperror",
    "permerror",
    "policy",
}


def _status_for_result(result: str) -> str:
    normalized = result.lower()
    if normalized == "pass":
        return "PASS"
    if normalized in _FAILED_AUTH_RESULTS:
        return "FAIL"
    return "NONE"


def _has_display_name_mismatch(display_name: str, email_address: str) -> bool:
    if not display_name or "@" not in email_address:
        return False

    domain = email_address.rsplit("@", 1)[1].rstrip(">").lower()
    if domain in _CONSUMER_EMAIL_DOMAINS:
        return bool(
            _EXECUTIVE_PATTERN.search(display_name)
            or _COMPANY_PATTERN.search(display_name)
        )

    company_names = _COMPANY_PATTERN.findall(display_name)
    return any(company.lower() not in domain for company in company_names)


def parse_headers(raw_email: str) -> dict:
    """Parse sender and authentication fields from a raw email or header block."""
    result = {
        "sender_analysis": {
            "from_header": "",
            "reply_to": "",
            "display_name_mismatch": False,
            "spf_status": "NONE",
            "dkim_status": "NONE",
            "dmarc_status": "NONE",
        },
        "heuristic_flags": [],
    }

    if not raw_email or not raw_email.strip():
        return result

    try:
        message = Parser(policy=policy.default).parsestr(raw_email, headersonly=True)
        from_header = str(message.get("From", "") or "")
        reply_to = str(message.get("Reply-To", "") or "")

        sender_analysis = result["sender_analysis"]
        sender_analysis["from_header"] = from_header
        sender_analysis["reply_to"] = reply_to

        from_addresses = getaddresses([from_header]) if from_header else []
        display_name, email_address = next(
            ((name.strip(), address.strip()) for name, address in from_addresses if address),
            ("", ""),
        )
        if _has_display_name_mismatch(display_name, email_address):
            sender_analysis["display_name_mismatch"] = True
            result["heuristic_flags"].append("Display name mismatch")

        auth_results = {
            "spf": [],
            "dkim": [],
            "dmarc": [],
        }
        for header in message.get_all("Authentication-Results", []):
            for method, status in _AUTH_RESULT_PATTERN.findall(str(header)):
                auth_results[method.lower()].append(_status_for_result(status))

        for header in message.get_all("Received-SPF", []):
            match = re.match(
                r"\s*(pass|fail|softfail|hardfail|neutral|none|"
                r"temperror|permerror|policy|unknown)\b",
                str(header),
                re.IGNORECASE,
            )
            if match:
                auth_results["spf"].append(_status_for_result(match.group(1)))

        for method in ("spf", "dkim", "dmarc"):
            statuses = auth_results[method]
            status = "FAIL" if "FAIL" in statuses else "PASS" if "PASS" in statuses else "NONE"
            sender_analysis[f"{method}_status"] = status
            if status == "FAIL":
                result["heuristic_flags"].append(f"{method.upper()} validation failed")
    except Exception:
        return {
            "sender_analysis": {
                "from_header": "",
                "reply_to": "",
                "display_name_mismatch": False,
                "spf_status": "NONE",
                "dkim_status": "NONE",
                "dmarc_status": "NONE",
            },
            "heuristic_flags": [],
        }

    return result
