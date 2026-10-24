"""
PhishGuard - QR / Quishing Decoder (Multi-Engine Resilient Pipeline)
Stack: OpenCV + Pillow + numpy + zxing-cpp + pyzbar
Export: extract_qr_payload(image_bytes: bytes) -> dict
"""

import io
import ipaddress
import re
import cv2
import numpy as np
from PIL import Image, ImageOps
from typing import Dict, List, Optional
from urllib.parse import urlparse, unquote

try:
    import zxingcpp
except ImportError:
    zxingcpp = None

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
except ImportError:
    pyzbar_decode = None


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
            before, after = p.split('@', 1)
            if '.' in before and '.' in after:
                flags.append(f"Obfuscated '@' trick: real destination is after '@' -> {after[:60]}")

    # 4. URL encoding anomalies
    encoded_count = len(ENCODED_REGEX.findall(p))
    if encoded_count > 5:
        flags.append(f"URL encoding anomaly: {encoded_count} percent-encoded characters - possible obfuscation")
    if '%25' in pl:
        flags.append("Double URL encoding detected (%25) - evasion attempt")
    decoded_payload = unquote(p)
    if decoded_payload != p and decoded_payload.lower().startswith(('http://', 'https://')) \
            and not pl.startswith(('http://', 'https://')):
        flags.append("URL-encoded HTTP(S) destination detected - possible obfuscation")

    # 5. Punycode / homograph
    if 'xn--' in pl:
        flags.append("Punycode (xn--) detected - possible homograph / lookalike domain attack")

    # 6. Dangerous protocols
    if pl.startswith('data:') or pl.startswith('javascript:'):
        flags.append(f"Dangerous protocol in QR: {pl.split(':')[0]}:")

    # 7. Unusually long / base64 blob
    if len(p) > 200:
        flags.append(f"Unusually long payload ({len(p)} chars) - possible redirect chain or tracking")
    if BASE64_LIKE.search(p) and 'http' not in pl:
        flags.append("Base64-like blob in payload - possible hidden URL")

    # 8. Shortener inside QR
    shorteners = ('bit.ly', 'tinyurl', 't.co', 'is.gd', 'cutt.ly')
    if any(s in pl for s in shorteners):
        flags.append("URL shortener inside QR - final destination hidden")

    return flags


def _preprocess_variants(gray: np.ndarray) -> List[tuple[str, np.ndarray]]:
    """Create enhanced image variants including white borders (quiet zone)."""
    variants = []

    # 1. Padded original (restores ISO Quiet Zone)
    padded = cv2.copyMakeBorder(gray, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    variants.append(("padded_original", padded))

    # 2. Raw original
    variants.append(("original", gray))

    # 3. Otsu threshold
    _, otsu = cv2.threshold(padded, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(("otsu_threshold", otsu))

    # 4. Adaptive threshold (handles low-contrast screenshots)
    adaptive = cv2.adaptiveThreshold(
        padded, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 21, 5
    )
    variants.append(("adaptive_threshold", adaptive))

    # 5. Inverted adaptive (for dark-mode / stylized QR codes)
    inverted = cv2.bitwise_not(padded)
    inv_adaptive = cv2.adaptiveThreshold(
        inverted, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 21, 5
    )
    variants.append(("inverted_adaptive", inv_adaptive))

    # 6. CLAHE enhanced contrast
    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
    enhanced = clahe.apply(padded)
    variants.append(("clahe_enhanced", enhanced))

    # 7. Upscaled 2x
    upscaled = cv2.resize(padded, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)
    variants.append(("upscaled_2x", upscaled))

    return variants


def _decode_candidate(image_np: np.ndarray) -> tuple[Optional[str], str]:
    """Tries decoding with zxing-cpp, pyzbar, and cv2.QRCodeDetector in priority order."""
    # Engine 1: zxing-cpp (Fastest & Most Fault-Tolerant)
    if zxingcpp is not None:
        try:
            res = zxingcpp.read_barcode(image_np)
            if res and res.text and res.text.strip():
                return res.text.strip(), "zxing-cpp"
        except Exception:
            pass

    # Engine 2: pyzbar
    if pyzbar_decode is not None:
        try:
            results = pyzbar_decode(image_np)
            if results and results[0].data:
                text = results[0].data.decode("utf-8", errors="ignore").strip()
                if text:
                    return text, "pyzbar"
        except Exception:
            pass

    # Engine 3: OpenCV native QRCodeDetector
    try:
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(image_np)
        if data and data.strip():
            return data.strip(), "opencv"
    except Exception:
        pass

    return None, "none"


def extract_qr_payload(image_bytes: bytes) -> Dict:
    """
    Multi-engine resilient QR decoder for PhishGuard.
    Handles cropped screenshots, missing quiet zones, aspect skew, and JPEG compression.
    """
    if not image_bytes:
        return {"detected": False, "payload": None, "flags": ["Empty image bytes"], "meta": {}}

    try:
        pil_img = ImageOps.exif_transpose(Image.open(io.BytesIO(image_bytes))).convert("RGB")
        img_np = np.array(pil_img)
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
    except Exception as e:
        return {"detected": False, "payload": None, "flags": [f"Failed to load image: {e}"], "meta": {}}

    payload = None
    engine_used = "none"
    preprocessing_used = "none"

    # Step 1: Try preprocessed variants with multi-engine decoder
    variants = _preprocess_variants(gray)
    for name, var in variants:
        decoded_text, engine = _decode_candidate(var)
        if decoded_text:
            payload = decoded_text
            engine_used = engine
            preprocessing_used = name
            break

    # Step 2: Fallback - Contour Isolation for cropped cards & dark UI themes
    if not payload:
        try:
            _, thresh = cv2.threshold(gray, 180, 255, cv2.THRESH_BINARY)
            contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            for c in contours:
                x, y, w, h = cv2.boundingRect(c)
                if w > 80 and h > 80:
                    crop = gray[max(0, y-10):min(gray.shape[0], y+h+10), max(0, x-10):min(gray.shape[1], x+w+10)]
                    padded_crop = cv2.copyMakeBorder(crop, 50, 50, 50, 50, cv2.BORDER_CONSTANT, value=255)
                    decoded_text, engine = _decode_candidate(padded_crop)
                    if decoded_text:
                        payload = decoded_text
                        engine_used = f"{engine}_contour_crop"
                        preprocessing_used = "contour_isolated_card"
                        break
        except Exception:
            pass

    if not payload:
        return {
            "detected": False,
            "payload": None,
            "flags": [],
            "meta": {
                "preprocessing_used": "none - all engines and variants exhausted",
                "engines_available": [k for k, v in [("zxingcpp", zxingcpp), ("pyzbar", pyzbar_decode), ("opencv", True)] if v]
            }
        }

    # Extract red flags from payload
    flags = _analyze_flags(payload)

    return {
        "detected": True,
        "payload": payload,
        "flags": flags,
        "meta": {
            "engine": engine_used,
            "preprocessing_used": preprocessing_used,
            "payload_length": len(payload),
            "is_url": bool(urlparse(payload).scheme)
        }
    }


if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        with open(sys.argv[1], "rb") as f:
            res = extract_qr_payload(f.read())
        print(json.dumps(res, indent=2))
    else:
        print("Usage: python qr_decoder.py <image_path>")
