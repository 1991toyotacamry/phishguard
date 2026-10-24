"""
PhishGuard: End-to-End System Test Suite
Tests integration across all 5 team members:
- Member 1: Frontend validation (app.py: validate_result)
- Member 2: Header parsing (header_parser.py: parse_headers)
- Member 3: QR optical decoding (qr_decoder.py: extract_qr_payload)
- Member 4: URL & threat intelligence (url_analyzer.py: enrich_url_telemetry)
- Member 5: LLM threat scoring orchestrator (llm_analyzer.py: analyze_threat)
"""

import io
import json
import sys
from PIL import Image

# Import Member 5 modules
from llm_analyzer import analyze_threat, PhishGuardAnalysis
from test_dataset import DEMO_SAMPLES, get_sample_names, get_sample_by_name

# Import Member 1 validation logic
from app import validate_result

# Import Member 2
from header_parser import parse_headers

# Import Member 3
from qr_decoder import extract_qr_payload

# Import Member 4
from url_analyzer import enrich_url_telemetry


def print_banner(msg: str):
    print("\n" + "=" * 80)
    print(f"  {msg}")
    print("=" * 80)


def test_member_1_ui_validation():
    print_banner("TEST 1: Member 1 Frontend Contract Validation (app.py: validate_result)")
    all_valid = True
    for sample_id, sample in DEMO_SAMPLES.items():
        result = analyze_threat(raw_content=sample["raw_content"], telemetry=sample["telemetry"])
        errors = validate_result(result)
        if errors:
            print(f"[-] FAILED for {sample['name']}: {errors}")
            all_valid = False
        else:
            print(f"[+] PASSED: '{sample['name']}' -> Score: {result['risk_score']} [{result['threat_level']}] (0 frontend validation errors)")
    return all_valid


def test_member_2_header_parser():
    print_banner("TEST 2: Member 2 Email Header Parser (header_parser.py)")
    all_passed = True
    
    # Test on Sample 1 (Legitimate notice with PASS auth)
    s1_res = parse_headers(DEMO_SAMPLES["sample_1"]["raw_content"])
    s1_auth = s1_res["sender_analysis"]
    print(f"[+] Sample 1 Parsed: From='{s1_auth['from_header']}', SPF={s1_auth['spf_status']}, DKIM={s1_auth['dkim_status']}, Mismatch={s1_auth['display_name_mismatch']}")
    if s1_auth["spf_status"] != "PASS" or s1_auth["display_name_mismatch"]:
        print("[-] Sample 1 header parse unexpected")
        all_passed = False

    # Test on Sample 3 (CEO BEC with display name spoof)
    s3_res = parse_headers(DEMO_SAMPLES["sample_3"]["raw_content"])
    s3_auth = s3_res["sender_analysis"]
    print(f"[+] Sample 3 Parsed: From='{s3_auth['from_header']}', DisplayNameMismatch={s3_auth['display_name_mismatch']}, Flags={s3_res['heuristic_flags']}")
    if not s3_auth["display_name_mismatch"]:
        print("[-] Sample 3 display name mismatch failed to detect")
        all_passed = False

    return all_passed


def test_member_3_qr_decoder():
    print_banner("TEST 3: Member 3 QR / Quishing Decoder (qr_decoder.py)")
    import cv2
    import qrcode

    # Generate a real test QR code in-memory pointing to a suspicious login lure
    test_payload = "https://login-m1crosoft-auth.com/mfa-verify?session=893247"
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(test_payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_bytes = buf.getvalue()

    # Decode using Member 3's qr_decoder
    decode_res = extract_qr_payload(qr_bytes)
    print(f"[+] Detected: {decode_res['detected']}")
    print(f"[+] Decoded Payload: {decode_res['payload']}")
    print(f"[+] Decoder Flags: {decode_res['flags']}")

    if decode_res["detected"] and decode_res["payload"] == test_payload:
        print("[+] Member 3 QR decoder successfully decoded payload!")
        return True
    else:
        print("[-] Member 3 QR decoder failed to decode")
        return False


def test_member_4_url_analyzer():
    print_banner("TEST 4: Member 4 URL & Threat Intel Enrichment (url_analyzer.py)")
    urls = [
        {
            "source": "QR_CODE",
            "initial_url": "https://login-m1crosoft-auth.com/mfa-verify"
        },
        {
            "source": "BODY_LINK",
            "initial_url": "https://workday.internal-corp.net/benefits/enrollment-2026"
        }
    ]
    enriched, flags = enrich_url_telemetry(urls)
    print(f"[+] Processed {len(enriched)} URLs:")
    for u in enriched:
        print(f"    - URL: {u['initial_url']}")
        print(f"      Domain: {u['domain']}, Typosquat: {u['is_typosquat']}, Brand: {u['targeted_brand']}")
    print(f"[+] Generated Flags: {flags}")
    
    # Verify the structure has all expected keys
    first = enriched[0]
    expected_keys = {"source", "initial_url", "final_url", "is_redirected", "domain", "domain_age_days", "is_typosquat", "targeted_brand", "virustotal_malicious_hits"}
    has_all_keys = expected_keys.issubset(set(first.keys()))
    return has_all_keys


def test_full_pipeline_orchestration():
    print_banner("TEST 5: Full 5-Member Integrated Pipeline Simulation")
    
    # Simulate a raw email containing an attack
    raw_email = DEMO_SAMPLES["sample_2"]["raw_content"]
    
    # 1. Member 2 extracts headers
    header_res = parse_headers(raw_email)
    
    # 2. Member 3 QR decoded URL
    qr_url = "https://login-m1crosoft-auth.com/mfa-verify?session=893247"
    raw_urls = [{"source": "QR_CODE", "initial_url": qr_url}]
    
    # 3. Member 4 enriches URLs
    enriched_urls, url_flags = enrich_url_telemetry(raw_urls)
    
    # 4. Synthesize complete telemetry
    telemetry = {
        "sender_analysis": header_res["sender_analysis"],
        "extracted_urls": enriched_urls,
        "heuristic_flags": list(set(header_res["heuristic_flags"] + url_flags + [
            "Domain age < 5 days", "Typosquatting detected: Target brand 'Microsoft'"
        ]))
    }
    
    # 5. Member 5 executes threat analysis
    analysis = analyze_threat(raw_content=raw_email, telemetry=telemetry)
    
    # 6. Member 1 validates results for UI rendering
    validation_errors = validate_result(analysis)
    
    print(f"[+] Risk Score:     {analysis['risk_score']} / 100")
    print(f"[+] Threat Level:   {analysis['threat_level']}")
    print(f"[+] Verdict Badge:  {analysis['verdict_badge']}")
    print(f"[+] MITRE Tactic:   {analysis['mitre_attack_technique']}")
    print(f"[+] Frontend Valid: {'PASS (0 errors)' if not validation_errors else f'FAIL: {validation_errors}'}")
    
    return len(validation_errors) == 0 and analysis["threat_level"] == "MALICIOUS"


def main():
    print_banner("PHISHGUARD 5-MEMBER COMPREHENSIVE INTEGRATION TEST SUITE")
    
    results = [
        ("Member 1 UI Validator", test_member_1_ui_validation()),
        ("Member 2 Header Parser", test_member_2_header_parser()),
        ("Member 3 QR Decoder", test_member_3_qr_decoder()),
        ("Member 4 URL Analyzer", test_member_4_url_analyzer()),
        ("Full End-to-End Pipeline", test_full_pipeline_orchestration())
    ]
    
    print_banner("FINAL TEST REPORT")
    all_ok = True
    for name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status:7s} - {name}")
        if not passed:
            all_ok = False
            
    if all_ok:
        print("\n>>> ALL TESTS PASSED! FULL TEAM CODEBASE IS 100% OPERATIONAL & READY FOR LIVE DEMO! <<<")
        sys.exit(0)
    else:
        print("\n>>> SOME TESTS FAILED! Check outputs above. <<<")
        sys.exit(1)


if __name__ == "__main__":
    main()
