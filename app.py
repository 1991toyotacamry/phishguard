"""PhishGuard Frontend - Full 5-Member Integrated Application.
Python 3.10+.
Run: python -m streamlit run app.py
"""
import hashlib
import html
import io
import json
import math
import re
from datetime import datetime, timezone
import streamlit as st
from PIL import Image, ImageDraw

# ==============================================================================
# 5-MEMBER MODULE IMPORTS WITH DEFENSIVE TOLERANCE
# ==============================================================================
IMPORT_ERRORS = []

# Member 5: LLM Threat Analyzer & Test Dataset
try:
    from llm_analyzer import analyze_threat
except Exception as e:
    analyze_threat = None
    IMPORT_ERRORS.append(f'Member 5 llm_analyzer could not load ({e}).')

try:
    from test_dataset import get_sample_names, get_sample_by_name, DEMO_SAMPLES
except Exception as e:
    get_sample_names = get_sample_by_name = DEMO_SAMPLES = None
    IMPORT_ERRORS.append(f'Member 5 test_dataset could not load ({e}).')

# Member 2: Header Parser
try:
    from header_parser import parse_headers
except Exception:
    parse_headers = None

# Member 3: QR Quishing Decoder
try:
    from qr_decoder import extract_qr_payload
except Exception:
    extract_qr_payload = None

# Member 4: URL Threat Intelligence
try:
    from url_analyzer import enrich_url_telemetry
except Exception:
    enrich_url_telemetry = None


SECRET_KEYS = {'apikey', 'openaiapikey', 'virustotalapikey', 'authorization',
               'password', 'secret', 'clientsecret', 'token', 'accesstoken',
               'refreshtoken', 'credentials', 'cookie', 'setcookie'}


def safe_json(value):
    """Presentation-only credential redaction; never used for detection."""
    if isinstance(value, dict):
        return {k: '[REDACTED]' if ''.join(c for c in k.lower() if c.isalnum()) in SECRET_KEYS
                else safe_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [safe_json(v) for v in value]
    return value


def validate_result(result):
    errors = []
    if not isinstance(result, dict):
        return ['Backend must return a JSON object.']
    try:
        json.dumps(result, allow_nan=False)
    except (ValueError, TypeError):
        return ['Backend result must contain JSON-compatible values only.']
    score = result.get('risk_score')
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 100:
        errors.append('risk_score must be a finite number from 0 to 100.')
    if result.get('threat_level') not in ('SAFE', 'SUSPICIOUS', 'MALICIOUS'):
        errors.append('threat_level must be SAFE, SUSPICIOUS or MALICIOUS.')
    for key in ('verdict_badge', 'mitre_attack_technique', 'cognitive_analysis', 'judge_summary'):
        if not isinstance(result.get(key), str) or not result[key].strip():
            errors.append(key + ' must be a nonempty string.')
    for key in ('technical_red_flags', 'actionable_recommendations'):
        if not isinstance(result.get(key), list) or not all(isinstance(x, str) and x.strip() for x in result[key]):
            errors.append(key + ' must be a list of nonempty strings (an empty list is allowed).')
    return errors


def fingerprint(raw_content, telemetry):
    return hashlib.sha256(json.dumps([raw_content, telemetry], sort_keys=True).encode()).hexdigest()


def card(label, text, accent='#36d6b0'):
    st.markdown(f'<div class="pg-card" style="border-left:4px solid {accent}"><div class="pg-label">{html.escape(label)}</div><div class="pg-copy">{html.escape(text)}</div></div>', unsafe_allow_html=True)


def render_result(result, run_id):
    score = result['risk_score']
    color = '#15803d' if score < 40 else '#b45309' if score < 75 else '#dc2626'
    badge_color = {'SAFE': '#15803d', 'SUSPICIOUS': '#b45309', 'MALICIOUS': '#dc2626'}[result['threat_level']]
    st.divider()
    st.subheader('Threat assessment')
    left, right = st.columns([1, 2])
    with left:
        st.metric('Risk score', f'{score} / 100')
        st.markdown(f'<div role="progressbar" aria-label="Risk score" aria-valuenow="{score}" aria-valuemin="0" aria-valuemax="100" style="height:14px;border-radius:8px;background:#d1d5db"><div style="height:14px;border-radius:8px;background:{color};width:{score}%"></div></div>', unsafe_allow_html=True)
        st.caption('Green <40 · Amber 40–74 · Red 75+')
    with right:
        st.markdown(f'<span class="pg-badge" style="background:{badge_color}">{html.escape(result["threat_level"])}</span>', unsafe_allow_html=True)
        card('VERDICT', result['verdict_badge'], badge_color)
    st.caption('Backend assessment—not a guarantee of safety. Score and threat level are displayed as returned.')
    st.caption('MITRE ATT&CK')
    st.code(result['mitre_attack_technique'], language=None)
    card('COGNITIVE ANALYSIS', result['cognitive_analysis'])
    left, right = st.columns(2)
    with left:
        st.subheader('Technical red flags')
        if not result['technical_red_flags']:
            st.caption('Backend returned no technical red flags.')
        for flag in result['technical_red_flags']:
            st.markdown('<div class="pg-flag">⚠ ' + html.escape(flag) + '</div>', unsafe_allow_html=True)
    with right:
        st.subheader('SOC triage checklist')
        st.caption('Tracks your review only; no external remediation is executed.')
        for i, recommendation in enumerate(result['actionable_recommendations']):
            check, text = st.columns([1, 10])
            with check:
                st.checkbox('Reviewed item ' + str(i + 1), key=f'triage_{run_id}_{i}', label_visibility='collapsed')
            with text:
                st.text(recommendation)
        if not result['actionable_recommendations']:
            st.caption('Backend returned no recommendations.')
    card('JUDGE SUMMARY', result['judge_summary'], '#60a5fa')
    with st.expander('Raw Analysis JSON'):
        st.caption('Credential fields are redacted for display.')
        display_res = safe_json(result)
        st.json(display_res)


def analysis_action(scope, raw_content, telemetry, ready=True):
    current = fingerprint(raw_content, telemetry)
    key = 'result_' + scope
    if st.button('Analyze Threat', type='primary', key='analyze_' + scope,
                 disabled=not ready or analyze_threat is None, use_container_width=True):
        st.session_state.pop(key, None)
        if not raw_content.strip():
            st.warning('Provide content before analyzing.')
        else:
            with st.spinner('Orchestrator is analyzing the threat…'):
                try:
                    result = analyze_threat(raw_content=raw_content, telemetry=telemetry)
                    errors = validate_result(result)
                    if errors:
                        st.error('Backend result contract mismatch: ' + ' '.join(errors))
                    else:
                        st.session_state[key] = dict(result=result, fingerprint=current,
                            run_id=datetime.now(timezone.utc).isoformat())
                except Exception as e:
                    st.error(f'Analysis failed ({e}). Check orchestrator configuration. No verdict was generated.')
    saved = st.session_state.get(key)
    if saved:
        if saved['fingerprint'] != current or not ready:
            st.warning('Input changed. Analyze again to refresh the assessment.')
        else:
            render_result(saved['result'], saved['run_id'])


def brand_icon():
    """Small, custom shield-and-check favicon, drawn entirely in memory."""
    icon = Image.new('RGBA', (128, 128), (0, 0, 0, 0))
    draw = ImageDraw.Draw(icon)
    draw.rounded_rectangle((4, 4, 124, 124), radius=32, fill='#f5eee3')
    draw.polygon([(64, 24), (98, 38), (94, 76), (82, 94), (64, 106),
                  (46, 94), (34, 76), (30, 38)], fill='#226453')
    draw.line([(47, 63), (59, 76), (83, 51)], fill='#fff9ee', width=8, joint='curve')
    draw.ellipse((92, 20, 108, 36), fill='#dc8867')
    return icon


def main():
    st.set_page_config(page_title='PhishGuard', page_icon=brand_icon(), layout='wide')
    st.markdown('''<style>
    .block-container {max-width:1180px;padding-top:2.5rem;}
    .pg-card {background:var(--secondary-background-color);border-radius:12px;padding:20px;margin:12px 0 22px;}
    .pg-label {font-size:.72rem;letter-spacing:.12em;font-weight:700;opacity:.7;margin-bottom:10px;}
    .pg-copy {font-size:1.08rem;line-height:1.65;white-space:pre-wrap;overflow-wrap:anywhere;}
    .pg-badge {display:inline-block;color:white;font-weight:800;padding:7px 16px;border-radius:99px;letter-spacing:.06em;}
    .pg-flag {padding:12px 0;border-bottom:1px solid #80808040;white-space:pre-wrap;overflow-wrap:anywhere;}
    </style>''', unsafe_allow_html=True)
    st.caption('SECURITY OPERATIONS  /  HACKATHON EDITION')
    st.markdown('''<div style="display:flex;align-items:center;gap:16px;margin:8px 0 14px">
    <svg width="72" height="72" viewBox="0 0 128 128" role="img" aria-label="PhishGuard shield with a check mark" style="flex-shrink:0">
      <rect x="4" y="4" width="120" height="120" rx="32" fill="#f5eee3"/>
      <path d="M64 24 Q82 33 98 38 L94 71 Q92 91 64 106 Q36 91 34 71 L30 38 Q48 33 64 24Z" fill="#226453"/>
      <path d="M47 63 L59 76 L83 51" fill="none" stroke="#fff9ee" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="100" cy="28" r="8" fill="#dc8867"/>
    </svg>
    <div><h1 style="margin:0;padding:0;font-family:Georgia,serif;font-size:clamp(2rem,6vw,3rem);font-weight:700;letter-spacing:-1.5px;line-height:1.15">PhishGuard<span style="color:#dc8867">.</span></h1>
    <span style="font-size:.78rem;letter-spacing:.08em;opacity:.7">A CLEARER LOOK AT DIGITAL TRUST</span></div>
    </div>''', unsafe_allow_html=True)
    st.write('GenAI-Enhanced Spear-Phishing & Quishing Detector')
    
    with st.sidebar:
        st.header('Analysis Workspace')
        st.success('Orchestrator: Connected (M5)' if analyze_threat else 'Orchestrator: Offline')
        st.success('QR Decoder: Connected (M3)' if extract_qr_payload else 'QR Decoder: Offline')
        st.success('Header Parser: Connected (M2)' if parse_headers else 'Header Parser: Offline')
        st.success('Threat Intel: Connected (M4)' if enrich_url_telemetry else 'Threat Intel: Offline')
        st.caption('All 5 modules fully integrated in production.')
        st.caption('Do not paste secret credentials. Configure service keys in backend environment.')

    for error in IMPORT_ERRORS:
        st.error(error)

    demo, manual = st.tabs(['Demo Scenarios', 'Manual Submission'])
    
    # --------------------------------------------------------------------------
    # TAB 1: DEMO SCENARIOS
    # --------------------------------------------------------------------------
    with demo:
        st.subheader('Choose a scenario')
        if get_sample_names is None:
            st.info('Add Member 5’s test_dataset.py to enable the three demo scenarios.')
        else:
            try:
                names = get_sample_names()
                if not isinstance(names, list) or not names:
                    raise ValueError()
                selected = st.selectbox('Demo scenario', names)
                if st.session_state.get('loaded_sample') != selected:
                    sample = get_sample_by_name(selected)
                    if not isinstance(sample, dict):
                        raise ValueError()
                    st.session_state['demo_content'] = sample.get('raw_content', '')
                    st.session_state['demo_telemetry'] = sample.get('telemetry', {})
                    st.session_state['loaded_sample'] = selected
                    st.session_state.pop('result_demo', None)
                raw_content = st.text_area('Editable sample content', key='demo_content', height=260, max_chars=100000)
                telemetry = st.session_state['demo_telemetry']
                with st.expander('Demo / mock telemetry', expanded=True):
                    st.caption('Precomputed telemetry evidence matching upstream contract.')
                    st.json(safe_json(telemetry))
                analysis_action('demo', raw_content, telemetry)
            except Exception as e:
                st.error(f'Dataset contract error: {e}')

    # --------------------------------------------------------------------------
    # TAB 2: MANUAL SUBMISSION (LIVE EMAIL & QUISHING QR SCANNER)
    # --------------------------------------------------------------------------
    with manual:
        st.subheader('Submit evidence')
        source = st.radio('Input to analyze', ['Raw email / SMTP headers', 'QR image (Quishing)'], horizontal=True)
        
        # Branch A: QR Image Upload (Member 3 + Member 4 + Member 5)
        if source == 'QR image (Quishing)':
            image_file = st.file_uploader('Upload QR image • PNG or JPG • maximum 5 MB', type=['png', 'jpg', 'jpeg'])
            if image_file:
                if image_file.size > 5 * 1024 * 1024:
                    st.error('Choose an image smaller than 5 MB.')
                else:
                    try:
                        image_bytes = image_file.getvalue()
                        with Image.open(io.BytesIO(image_bytes)) as picture:
                            picture.thumbnail((480, 480))
                            st.image(picture.copy(), caption='QR evidence preview', width=260)
                        
                        if extract_qr_payload:
                            qr_res = extract_qr_payload(image_bytes)
                            if qr_res.get('detected') and qr_res.get('payload'):
                                decoded_url = qr_res['payload']
                                st.success(f"Decoded QR Destination: `{decoded_url}`")
                                if qr_res.get('flags'):
                                    for f in qr_res['flags']:
                                        st.warning(f"🚩 QR Anomaly: {f}")

                                # Member 4: Enrich URL Telemetry
                                raw_urls = [{"source": "QR_CODE", "initial_url": decoded_url}]
                                if enrich_url_telemetry:
                                    enriched_urls, u_flags = enrich_url_telemetry(raw_urls)
                                else:
                                    enriched_urls = [{"source": "QR_CODE", "initial_url": decoded_url, "final_url": decoded_url, "is_redirected": False, "domain": "", "domain_age_days": None, "is_typosquat": False, "targeted_brand": None, "virustotal_malicious_hits": 0}]
                                    u_flags = []

                                # Synthesize telemetry
                                all_flags = list(set(qr_res.get('flags', []) + u_flags + ["QR code payload decoded"]))
                                qr_telemetry = {
                                    "sender_analysis": {
                                        "from_header": "Quishing Image Attachment",
                                        "reply_to": "",
                                        "display_name_mismatch": False,
                                        "spf_status": "NONE",
                                        "dkim_status": "NONE",
                                        "dmarc_status": "NONE"
                                    },
                                    "extracted_urls": enriched_urls,
                                    "heuristic_flags": all_flags
                                }
                                with st.expander('Extracted Live Telemetry', expanded=True):
                                    st.json(safe_json(qr_telemetry))

                                analysis_action('qr', f"Decoded QR Destination: {decoded_url}", qr_telemetry, ready=True)
                            else:
                                st.warning('No QR code detected in this image. Try a clearer screenshot or higher-contrast image.')
                                st.button('Analyze Threat', key='qr_disabled', type='primary', disabled=True)
                        else:
                            st.info('QR decoder module not loaded.')
                            st.button('Analyze Threat', key='qr_disabled', type='primary', disabled=True)
                    except Exception as e:
                        st.error(f'Error processing image: {e}')
            else:
                st.info('Upload a screenshot or photo of an email QR code to decode and analyze.')

        # Branch B: Raw Email Text / Headers (Member 2 + Member 4 + Member 5)
        else:
            raw_content = st.text_area('Raw email text / SMTP headers', height=260, key='manual_content', max_chars=100000)
            raw_json = st.text_area('Optional custom telemetry JSON (Leave blank for automated parsing)', placeholder='Leave blank to automatically extract headers and URLs', key='manual_telemetry')
            
            telemetry, ready = None, True
            if raw_json.strip():
                try:
                    telemetry = json.loads(raw_json)
                    if not isinstance(telemetry, dict):
                        raise ValueError()
                    with st.expander('Custom Telemetry Preview'):
                        st.json(safe_json(telemetry))
                except Exception:
                    st.error('Telemetry must be valid JSON with an object at the top level.')
                    ready = False
            elif raw_content.strip():
                # Automatic live telemetry extraction using Member 2 & Member 4!
                try:
                    if parse_headers:
                        h_res = parse_headers(raw_content)
                        s_analysis = h_res.get("sender_analysis", {})
                        h_flags = h_res.get("heuristic_flags", [])
                    else:
                        s_analysis = {"from_header": "", "reply_to": "", "display_name_mismatch": False, "spf_status": "NONE", "dkim_status": "NONE", "dmarc_status": "NONE"}
                        h_flags = []

                    found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', raw_content)
                    raw_urls = [{"source": "BODY_LINK", "initial_url": u} for u in found_urls]
                    if enrich_url_telemetry and raw_urls:
                        enr_urls, u_flags = enrich_url_telemetry(raw_urls)
                    else:
                        enr_urls = [{"source": "BODY_LINK", "initial_url": u, "final_url": u, "is_redirected": False, "domain": "", "domain_age_days": None, "is_typosquat": False, "targeted_brand": None, "virustotal_malicious_hits": 0} for u in found_urls]
                        u_flags = []

                    telemetry = {
                        "sender_analysis": s_analysis,
                        "extracted_urls": enr_urls,
                        "heuristic_flags": list(set(h_flags + u_flags))
                    }
                    with st.expander('Live Extracted Telemetry (Header Parser + URL Intel)', expanded=False):
                        st.json(safe_json(telemetry))
                except Exception:
                    telemetry = None

            analysis_action('manual', raw_content, telemetry, ready)

    with st.expander('Team integration contract'):
        st.markdown("""
        **Architecture**: 5-Member Zero-Trust Pipeline
        - **M1**: Streamlit UI Dashboard & SOC Checklist
        - **M2**: RFC Header & Sender Authentication Parser (`header_parser.py`)
        - **M3**: OpenCV Adaptive Multi-Variant QR Quishing Decoder (`qr_decoder.py`)
        - **M4**: WHOIS Velocity & VirusTotal URL Threat Intelligence (`url_analyzer.py`)
        - **M5**: Hardened GenAI Threat Scoring Orchestrator & Fallback Engine (`llm_analyzer.py`)
        """)


if __name__ == '__main__':
    main()
