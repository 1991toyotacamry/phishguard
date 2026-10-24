# PhishGuard: Multi-Agent Team Integration Contract
**Prepared by:** Member 5 (Principal AI Architect & Pitch Lead)  
**Target:** To be pasted into AI agents (Cursor, Claude, Copilot, ChatGPT) used by Members 1, 2, 3, and 4 before any prompt.

---

## UNIVERSAL SYSTEM DIRECTIVES (Applies to all members)
1. **Strict File Isolation:** You only create/edit your assigned file. Never edit `llm_analyzer.py`, `test_dataset.py`, or another member's module.
2. **Data Type Uniformity:** Use Python 3.10+ and standard library types (`dict`, `list`, `str`, `int`, `bool`, `Optional`).
3. **No Duplicate Logic:** 
   - Member 1 does NOT compute risk scores.
   - Members 2, 3, and 4 do NOT call LLMs.
   - Member 5 handles all scoring, MITRE mapping, and GenAI orchestration.

---

## COPY-PASTE FOR MEMBER 1: UI & Dashboard Lead
**File to own:** `app.py`  
**Teammate prompt prefix:**
```text
[PROJECT CONTEXT: PhishGuard Streamlit UI]
You are building the frontend dashboard in `app.py` for PhishGuard.
STRICT BOUNDARY CONSTRAINTS:
1. DO NOT write risk scoring math, regex scanners, or call OpenAI directly in this file.
2. You MUST import the orchestrator and demo dataset provided by Member 5:
     from llm_analyzer import analyze_threat
     from test_dataset import get_sample_names, get_sample_by_name, DEMO_SAMPLES
3. Implement a dropdown using `get_sample_names()` allowing the user/judge to test 3 scenarios:
     - Sample 1: Legitimate Enterprise Notice
     - Sample 2: Quishing MFA Bypass (Critical Attack)
     - Sample 3: VIP Spear-Phishing / BEC (High-Value Fraud)
4. When a sample is selected, populate an editable text area for `raw_content` and display the mock `telemetry` JSON.
5. Provide a manual submission tab where users can paste raw emails or upload QR images.
6. When the 'Analyze Threat' button is clicked, execute:
     result = analyze_threat(raw_content=raw_content, telemetry=telemetry)
7. Render the returned keys into high-impact visual components:
     - result["risk_score"] (0 to 100 progress gauge / metric)
     - result["threat_level"] ("SAFE", "SUSPICIOUS", "MALICIOUS" color-coded badge)
     - result["verdict_badge"] (Big callout card)
     - result["mitre_attack_technique"] (Code chip / tag)
     - result["cognitive_analysis"] (Card detailing psychological pressure)
     - result["technical_red_flags"] (Bullet list with warning icons)
     - result["actionable_recommendations"] (Checklist for SOC triage)
     - result["judge_summary"] (Highlighted executive takeaway)
```

---

## COPY-PASTE FOR MEMBER 2: Email Header & Auth Analyst
**File to own:** `header_parser.py`  
**Teammate prompt prefix:**
```text
[PROJECT CONTEXT: PhishGuard Header Analysis]
You are building `header_parser.py` to extract sender identity and cryptographic authentication from raw email headers.
STRICT BOUNDARY CONSTRAINTS:
1. Export a single primary function:
     parse_headers(raw_email: str) -> dict
2. The output MUST return a dictionary with this exact schema:
     {
       "sender_analysis": {
         "from_header": str,
         "reply_to": str,
         "display_name_mismatch": bool,
         "spf_status": "PASS" | "FAIL" | "NONE",
         "dkim_status": "PASS" | "FAIL" | "NONE",
         "dmarc_status": "PASS" | "FAIL" | "NONE"
       },
       "heuristic_flags": list[str]
     }
3. Rules for analysis:
     - Extract display name vs actual email address in `From:`. If display name impersonates an executive or company but the email domain is external (e.g. gmail.com), set `display_name_mismatch: True`.
     - Parse `Authentication-Results:` or `Received-SPF:` headers to determine SPF, DKIM, and DMARC status.
     - Add human-readable flags to `heuristic_flags` (e.g., "SPF validation failed", "Display name mismatch").
4. Never raise unhandled exceptions; return status "NONE" and empty flags if headers are missing.
```

---

## COPY-PASTE FOR MEMBER 3: Quishing & QR Optical Engine
**File to own:** `qr_scanner.py`  
**Teammate prompt prefix:**
```text
[PROJECT CONTEXT: PhishGuard Quishing / QR Detector]
You are building `qr_scanner.py` to detect and decode physical or embedded QR codes in email screenshots, PDFs, or image attachments.
STRICT BOUNDARY CONSTRAINTS:
1. Export a primary function:
     extract_qr_payloads(image_input) -> list[dict]
   (image_input can be a file path, PIL Image, or bytes).
2. The returned list must contain URL objects matching this schema:
     [
       {
         "source": "QR_CODE",
         "initial_url": str,
         "final_url": str,
         "is_redirected": bool
       }
     ]
3. If the QR code redirects (e.g. bit.ly, tinyurl), follow redirects up to 3 hops (using requests.head/get with allow_redirects=True and timeout=3.0s) to populate `final_url` and `is_redirected`.
4. If no QR code is detected, return an empty list `[]`.
5. Use lightweight, dependable libraries (e.g., `opencv-python` with `cv2.QRCodeDetector()` or `pillow` + `pyzbar`). Handle missing or corrupted images gracefully without crashing.
```

---

## COPY-PASTE FOR MEMBER 4: URL & Domain Threat Intel
**File to own:** `url_analyzer.py`  
**Teammate prompt prefix:**
```text
[PROJECT CONTEXT: PhishGuard URL & Domain Intel Engine]
You are building `url_analyzer.py` to enrich extracted URLs with threat intelligence and heuristic flags.
STRICT BOUNDARY CONSTRAINTS:
1. Export a primary function:
     enrich_url_telemetry(extracted_urls: list[dict]) -> tuple[list[dict], list[str]]
2. Input is a list of URL objects containing at least `initial_url` and `source` ("BODY_LINK" or "QR_CODE").
3. For each URL, enrich the dictionary with:
     {
       "source": "BODY_LINK" | "QR_CODE",
       "initial_url": str,
       "final_url": str,
       "is_redirected": bool,
       "domain": str,
       "domain_age_days": int or None,
       "is_typosquat": bool,
       "targeted_brand": str or None,
       "virustotal_malicious_hits": int
     }
4. Check for:
     - Typosquatting: Compare domain against popular target brands (Microsoft, Google, Apple, PayPal, Bank of America, Workday, Okta).
     - Domain Age: Lookup WHOIS age. If lookup fails or times out, default to None.
     - VirusTotal Hits: If VIRUSTOTAL_API_KEY is available, query VT API (timeout=3s). If not available, default to 0 hits.
5. Return:
     (enriched_extracted_urls, generated_heuristic_flags)
   Where `generated_heuristic_flags` is a list of strings (e.g., "Domain age < 5 days", "Typosquatting detected").
```

---

## PIPELINE WRAPPER (HOW TO COMBINE MEMBERS 2, 3, AND 4)
When Member 1 calls the backend, Members 2, 3, and 4 feed directly into Member 5:

```python
# In pipeline.py or inside app.py:
from header_parser import parse_headers       # Member 2
from qr_scanner import extract_qr_payloads     # Member 3
from url_analyzer import enrich_url_telemetry  # Member 4
from llm_analyzer import analyze_threat        # Member 5

def run_phishguard_pipeline(raw_email_str: str, attached_image=None):
    # 1. Member 2 extracts headers
    header_res = parse_headers(raw_email_str)
    
    # 2. Member 3 extracts QR URLs if image attached
    qr_urls = extract_qr_payloads(attached_image) if attached_image else []
    
    # 3. Member 4 extracts body links & enriches all URLs
    body_urls = [{"source": "BODY_LINK", "initial_url": u, "final_url": u, "is_redirected": False} for u in extract_links_from_text(raw_email_str)]
    all_urls = qr_urls + body_urls
    enriched_urls, url_flags = enrich_url_telemetry(all_urls)
    
    # 4. Consolidate into upstream telemetry contract
    telemetry = {
        "sender_analysis": header_res["sender_analysis"],
        "extracted_urls": enriched_urls,
        "heuristic_flags": list(set(header_res["heuristic_flags"] + url_flags))
    }
    
    # 5. Member 5 executes hybrid scoring & GenAI defense
    return analyze_threat(raw_content=raw_email_str, telemetry=telemetry)
```
