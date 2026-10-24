"""
PhishGuard - QR / Quishing Decoder
Stack: opencv-python-headless + Pillow + numpy
Export: extract_qr_payload(image_bytes: bytes) -> dict
"""

import io
import ipaddress
import re
import cv2
import numpy as np
from PIL import Image, ImageOps
from typing import Dict, List
from urllib.parse import urlparse, unquote

# --- Flag Patterns ---
CREDENTIAL_AT_REGEX = re.compile(r'https?://[^/\s]+:[^/\s]*@|https?://[^/\s]+@[^/\s]+', re.I)
ENCODED_REGEX = re.compile(r'%[0-9a-fA-F]{2}')
BASE64_LIKE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

def _uses_ip_address(payload: str) -> bool:
    """Return whether an HTTP(S) URL uses an IP literal as its host."""
    try:
        hostname = urlparse(payload).hostname
        if hostname is None:
            return False
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def _analyze_flags(payload: str) -> List[str]:
    """Immediate red flags from raw payload"""
    flags: List[str] = []
    if not payload:
        return flags

    p = payload.strip()
    pl = p.lower()

    # 1. Insecure HTTP
    if pl.startswith('http://'):
        flags.append("Insecure protocol: uses http:// instead of https://")

    # 2. IP address instead of domain
    if _uses_ip_address(p):
        flags.append("IP address used instead of domain name - highly suspicious (evades domain reputation)")

    # 3. Credential '@' syntax: https://user:pass@evil.com or https://paypal.com@evil.com
    if '@' in p and 'http' in pl:
        parsed = urlparse(p)
        if parsed.username or parsed.password:
            flags.append(f"Credential injection: URL contains username/password '{parsed.username}'")
        elif p.count('@') == 1:
            # Classic @-trick: https://trusted.com@attacker.com
            before, after = p.split('@', 1)
            if '.' in before and '.' in after:
                flags.append(f"Obfuscated '@' trick: real destination is after '@' -> {after[:60]}")

    # 4. URL encoding anomalies - excessive encoding, double encoding
    encoded_count = len(ENCODED_REGEX.findall(p))
    if encoded_count > 5:
        flags.append(f"URL encoding anomaly: {encoded_count} percent-encoded characters - possible obfuscation")
    if '%25' in pl:  # %25 is encoded %
        flags.append("Double URL encoding detected (%25) - evasion attempt")
    decoded_payload = unquote(p)
    if decoded_payload != p and decoded_payload.lower().startswith(('http://', 'https://')) \
            and not pl.startswith(('http://', 'https://')):
        flags.append("URL-encoded HTTP(S) destination detected - possible obfuscation")

    # 5. Punycode / homograph
    if 'xn--' in pl:
        flags.append("Punycode (xn--) detected - possible homograph / lookalike domain attack")

    # 6. Data URI, javascript, etc
    if pl.startswith('data:') or pl.startswith('javascript:'):
        flags.append(f"Dangerous protocol in QR: {pl.split(':')[0]}:")

    # 7. Unusually long / base64 blob
    if len(p) > 200:
        flags.append(f"Unusually long payload ({len(p)} chars) - possible redirect chain or tracking")
    if BASE64_LIKE.search(p) and 'http' not in pl:
        flags.append("Base64-like blob in payload - possible hidden URL")

    # 8. Shortener inside QR (needs unshortening by Member 3)
    shorteners = ('bit.ly', 'tinyurl', 't.co', 'is.gd', 'cutt.ly')
    if any(s in pl for s in shorteners):
        flags.append("URL shortener inside QR - final destination hidden")

    return flags

def _preprocess_variants(gray: np.ndarray) -> List[np.ndarray]:
    """Create variants to handle blurry / low-contrast screenshots"""
    variants = []

    # 1. Original gray
    variants.append(gray)

    # 2. Adaptive threshold - best for low-contrast phone screenshots
    adaptive = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 21, 5
    )
    variants.append(adaptive)

    # 3. Otsu threshold - handles uneven lighting
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(otsu)

    # 4. Inverted + adaptive - for white-on-black stylized QR
    inverted = cv2.bitwise_not(gray)
    inv_adaptive = cv2.adaptiveThreshold(
        inverted, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 21, 5
    )
    variants.append(inv_adaptive)

    # 5. Sharpened - fixes blurry screenshots (unsharp mask)
    blur = cv2.GaussianBlur(gray, (0, 0), 3)
    sharpened = cv2.addWeighted(gray, 1.6, blur, -0.6, 0)
    variants.append(sharpened)

    # 6. CLAHE enhanced - boosts contrast
    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    variants.append(enhanced)

    # 7. Upscaled 2x - helps small QRs from screenshots
    upscaled = cv2.resize(gray, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)
    variants.append(upscaled)

    return variants

def extract_qr_payload(image_bytes: bytes) -> Dict:
    """
    Detect and decode QR codes from image byte stream.

    Args:
        image_bytes: Raw bytes of uploaded image (from Streamlit / FastAPI)

    Returns:
        {
            "detected": bool,
            "payload": str | None,
            "flags": List[str],
            "meta": {"preprocessing_used": str, "variant_count": int}
        }
    """
    if not image_bytes:
        return {"detected": False, "payload": None, "flags": ["Empty image bytes"], "meta": {}}

    # Load with Pillow -> convert to OpenCV gray
    try:
        pil_img = ImageOps.exif_transpose(Image.open(io.BytesIO(image_bytes))).convert("RGB")
        img_np = np.array(pil_img)
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
    except Exception as e:
        return {"detected": False, "payload": None, "flags": [f"Failed to load image: {e}"], "meta": {}}

    detector = cv2.QRCodeDetector()
    variants = _preprocess_variants(gray)
    variant_names = [
        "original", "adaptive_threshold", "otsu_threshold",
        "inverted_adaptive", "sharpened", "clahe_enhanced", "upscaled_2x"
    ]

    payload = None
    used = "none"

    # Try each variant
    for idx, var in enumerate(variants):
        try:
            data, bbox, _ = detector.detectAndDecode(var)
            if data and data.strip():
                payload = data.strip()
                used = variant_names[idx]
                break

            # Try multi-QR (OpenCV 4.5+)
            ret, infos, _, _ = detector.detectAndDecodeMulti(var)
            if ret and infos and infos[0]:
                payload = infos[0].strip()
                used = variant_names[idx] + "_multi"
                break
        except Exception:
            continue

    if not payload:
        return {
            "detected": False,
            "payload": None,
            "flags": [],
            "meta": {
                "preprocessing_used": "none - all variants failed",
                "variant_count": len(variants),
                "tried": variant_names
            }
        }

    # Analyze flags
    flags = _analyze_flags(payload)

    return {
        "detected": True,
        "payload": payload,
        "flags": flags,
        "meta": {
            "preprocessing_used": used,
            "payload_length": len(payload),
            "is_url": bool(urlparse(payload).scheme)
        }
    }

# --- Standalone test block ---
if __name__ == "__main__":
    import sys
    import json
    import pathlib

    print("PhishGuard QR Decoder - Test Mode")
    print("Usage: python qr_decoder.py <path_to_image>\n")

    if len(sys.argv) < 2:
        # Try default test files
        test_candidates = ["test_qr.png", "sample.png", "qr.jpg", "quishing.png"]
        found = None
        for cand in test_candidates:
            if pathlib.Path(cand).exists():
                found = cand
                break
        if not found:
            print("No image provided. Provide path: python qr_decoder.py my_qr.png")
            sys.exit(1)
        image_path = found
    else:
        image_path = sys.argv[1]

    path = pathlib.Path(image_path)
    if not path.exists():
        print(f"File not found: {image_path}")
        sys.exit(1)

    print(f"Reading: {path} ({path.stat().st_size} bytes)")
    image_bytes = path.read_bytes()

    result = extract_qr_payload(image_bytes)

    print("\n--- Result ---")
    print(json.dumps(result, indent=2))

    if result["detected"]:
        print(f"\n✅ Decoded payload: {result['payload']}")
        if result["flags"]:
            print("\n🚩 Immediate Red Flags:")
            for f in result["flags"]:
                print(f"  - {f}")
        else:
            print("\nNo immediate flags (still verify domain age / VirusTotal in threat_intel.py)")
    else:
        print("\n❌ No QR detected - try a clearer image or different preprocessing")