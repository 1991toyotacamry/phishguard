"""PhishGuard frontend only. Python 3.10+.
Install: python -m pip install 'streamlit>=1.40' pillow
Run: python -m streamlit run app.py
Place Member 5's llm_analyzer.py and test_dataset.py beside this file.

Integration contracts (required; teammate files were not supplied):
get_sample_names() -> list[str]
get_sample_by_name(name) -> dict with raw_content: str, telemetry: dict
DEMO_SAMPLES must be exported; the UI does not assume its container format.
Expected names:
 Sample 1: Legitimate Enterprise Notice
 Sample 2: Quishing MFA Bypass (Critical Attack)
 Sample 3: VIP Spear-Phishing / BEC (High-Value Fraud)
analyze_threat(*, raw_content: str, telemetry: dict | None) -> JSON dict:
 risk_score: number 0..100 (not bool)
 threat_level: SAFE | SUSPICIOUS | MALICIOUS
 verdict_badge, mitre_attack_technique, cognitive_analysis, judge_summary: str
 technical_red_flags, actionable_recommendations: list[str]
No inferred sample field mappings or fake results are provided.
QR decoding: interface not supplied. Preview is available; QR analysis is
explicitly disabled. Wire the teammate decoder's documented output into
raw_content and telemetry before enabling QR analysis.
Security: backend must never return secrets. Defensive credential-key
redaction is applied to displayed JSON; arbitrary prose cannot reliably be
classified as a secret. Do not put credentials in submitted messages.
"""
import hashlib
import html
import io
import json
import math
from datetime import datetime, timezone
import streamlit as st
from PIL import Image, ImageDraw

IMPORT_ERRORS = []
try:
    from llm_analyzer import analyze_threat
except Exception:
    analyze_threat = None
    IMPORT_ERRORS.append('llm_analyzer could not load. Provide analyze_threat and install its dependencies.')
try:
    from test_dataset import (
        get_sample_names,
        get_sample_by_name,
        DEMO_SAMPLES,
    )
except Exception:
    get_sample_names = get_sample_by_name = None
    IMPORT_ERRORS.append('test_dataset could not load. Provide get_sample_names, get_sample_by_name and DEMO_SAMPLES.')

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
        result = safe_json(result)
        st.json(result)


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
                        # Store the result without recomputing any findings or scores.
                        st.session_state[key] = dict(result=result, fingerprint=current,
                            run_id=datetime.now(timezone.utc).isoformat())
                except Exception:
                    st.error('Analysis failed. Ask Member 5 to check the orchestrator configuration and service availability. No verdict was generated.')
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
        st.header('Analysis workspace')
        st.success('Orchestrator connected' if analyze_threat else 'Frontend ready')
        st.caption('All threat assessments are supplied by the team backend.')
        st.info('QR decoder: awaiting teammate integration')
        st.caption('Do not paste API credentials. Configure service keys in the backend.')
    for error in IMPORT_ERRORS:
        st.error(error)
    demo, manual = st.tabs(['Demo Scenarios', 'Manual Submission'])
    with demo:
        st.subheader('Choose a scenario')
        if get_sample_names is None:
            st.info('Add Member 5’s test_dataset.py to enable the three demo scenarios.')
        else:
            try:
                names = get_sample_names()
                if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names) or len(set(names)) != len(names):
                    raise ValueError()
                selected = st.selectbox('Demo scenario', names)
                if st.session_state.get('loaded_sample') != selected:
                    sample = get_sample_by_name(selected)
                    if not isinstance(sample, dict) or not isinstance(sample.get('raw_content'), str) or not isinstance(sample.get('telemetry'), dict):
                        raise ValueError()
                    json.dumps(sample['telemetry'], allow_nan=False)
                    st.session_state['demo_content'] = sample['raw_content']
                    st.session_state['demo_telemetry'] = sample['telemetry']
                    st.session_state['loaded_sample'] = selected
                    st.session_state.pop('result_demo', None)
                raw_content = st.text_area('Editable sample content', key='demo_content', height=260, max_chars=100000)
                telemetry = st.session_state['demo_telemetry']
                with st.expander('Demo / mock telemetry', expanded=True):
                    st.caption('Synthetic dataset evidence; not a live lookup. Editing the message does not regenerate this mock telemetry.')
                    st.json(safe_json(telemetry))
                analysis_action('demo', raw_content, telemetry)
            except Exception:
                st.error('Dataset contract mismatch. get_sample_names() must return unique string names; get_sample_by_name() must return raw_content (string) and telemetry (JSON object). Ask Member 5 to supply an explicit field mapping if their structure differs.')
    with manual:
        st.subheader('Submit evidence')
        source = st.radio('Input to analyze', ['Raw email / SMTP headers', 'QR image'], horizontal=True)
        if source == 'QR image':
            image = st.file_uploader('QR image • PNG or JPG • maximum 5 MB', type=['png', 'jpg', 'jpeg'])
            if image:
                if image.size > 5 * 1024 * 1024:
                    st.error('Choose an image smaller than 5 MB.')
                else:
                    try:
                        with Image.open(io.BytesIO(image.getvalue())) as picture:
                            if picture.format not in ('PNG', 'JPEG') or picture.width * picture.height > 16000000:
                                raise ValueError()
                            picture.thumbnail((640, 640))
                            st.image(picture.copy(), caption='QR evidence preview', width=280)
                    except Exception:
                        st.error('Preview unavailable. Use a valid PNG/JPEG up to 16 megapixels.')
            st.info('QR analysis requires the teammate decoder interface. This upload is a preview only; no content has been extracted.')
            st.button('Analyze Threat', key='qr_disabled', type='primary', disabled=True)
        else:
            raw_content = st.text_area('Raw email text / SMTP headers', height=260, key='manual_content', max_chars=100000)
            raw_json = st.text_area('Optional telemetry JSON object', placeholder='Leave blank if unavailable', key='manual_telemetry')
            telemetry, ready = None, True
            if raw_json.strip():
                try:
                    telemetry = json.loads(raw_json, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                    if not isinstance(telemetry, dict):
                        raise ValueError()
                    with st.expander('Telemetry preview (credential fields redacted)'):
                        st.json(safe_json(telemetry))
                except (ValueError, TypeError):
                    st.error('Telemetry must be valid JSON with an object at the top level.')
                    ready = False
            analysis_action('manual', raw_content, telemetry, ready)
    with st.expander('Team integration contract'):
        st.text(__doc__)


if __name__ == '__main__':
    main()
