"""
email_parser.py - phishing triage helpers for raw RFC 822 messages.

Public API
----------
parse_email_text(raw_input, trusted_domains=None) -> dict
unshorten_url(url, ...) -> (final_url, redirect_chain)

Dependencies: beautifulsoup4, requests (everything else is stdlib).

Caveats
-------
* Authentication-Results / Received-SPF are only trustworthy when they were
  stamped by YOUR gateway. In an arbitrary sample the sender can forge them,
  so treat "pass" as informational and "fail" as a strong signal.
* `_registered_domain` is a naive eTLD+1 approximation (no Public Suffix
  List). Swap in `tldextract` / `publicsuffix2` for production use.
* Display-name checks are heuristics; tune the constants below for your org.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import sys
from email import message_from_string, policy
from email.message import Message
from email.utils import getaddresses, parseaddr
from typing import Any, Iterable, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

__all__ = ["parse_email_text", "unshorten_url"]

# --------------------------------------------------------------------------- #
# Tunable constants
# --------------------------------------------------------------------------- #

FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "proton.me", "protonmail.com", "icloud.com",
    "gmx.com", "mail.com", "yandex.com", "zoho.com",
}

# Phrases that imply an internal/privileged sender.
_ROLE_RE = re.compile(
    r"\b(it[\s_-]*(help\s*desk|helpdesk|support|service\s*desk|department|dept|"
    r"admin(istrator)?|security|team)|help\s*desk|helpdesk|service\s*desk|"
    r"sys(tem)?\s*admin(istrator)?|network\s*admin(istrator)?|mail\s*admin(istrator)?|"
    r"administrator|human\s+resources|hr|payroll|accounts?\s+payable|"
    r"security\s+team|ceo|cfo|cto)\b",
    re.I,
)

# Brand keyword (lowercase) -> registered domains the brand legitimately uses.
BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "office.com", "office365.com", "microsoftonline.com",
                  "outlook.com", "live.com"},
    "office 365": {"microsoft.com", "office.com", "office365.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.ca",
               "amazon.fr", "amazon.es", "amazon.it", "amazon.co.jp", "amazon.com.au"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "chase": {"chase.com", "jpmorgan.com", "jpmchase.com"},
    "wells fargo": {"wellsfargo.com"},
    "bank of america": {"bankofamerica.com", "bofa.com"},
    "adobe": {"adobe.com", "adobesign.com"},
    "zoom": {"zoom.us", "zoom.com"},
}

_SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}
_FAIL_RESULTS = {"fail", "softfail", "permerror"}
_AUTH_RESULT_TOKENS = r"pass|fail|softfail|hardfail|neutral|none|temperror|permerror|policy"

_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
_PLAIN_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
_HTML_HINT_RE = re.compile(r"<\s*(a|html|body|div|p|table)\b", re.I)
# A URL or bare domain appearing inside anchor text, e.g. "https://paypal.com".
_SHOWN_URL_RE = re.compile(
    r"(?<![@\w.-])(?:https?://|www\.)?"
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}"
    r"(?::\d+)?(?:/[^\s<>\"']*)?",
    re.I,
)

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _safe_urlparse(url: str):
    try:
        return urlparse(url)
    except ValueError:
        return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _registered_domain(host: str) -> str:
    """Naive eTLD+1 (see module caveats)."""
    host = (host or "").lower().strip(".")
    if not host or _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL_LABELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
        return " ".join(str(value).split()) if value is not None else ""
    except Exception:  # malformed header objects can raise on access
        return ""


def _header_all(msg: Message, name: str) -> list[str]:
    try:
        return [" ".join(str(v).split()) for v in (msg.get_all(name) or [])]
    except Exception:
        return []


def _addr_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


# --------------------------------------------------------------------------- #
# Authentication results
# --------------------------------------------------------------------------- #


def _normalize_result(token: str) -> str:
    token = token.lower()
    return "fail" if token == "hardfail" else token


def _worst(results: list[str]) -> str:
    order = ["fail", "permerror", "softfail", "temperror", "neutral", "none", "policy", "pass"]
    return min(results, key=lambda r: order.index(r) if r in order else len(order))


def _parse_authentication(msg: Message) -> dict[str, Any]:
    out: dict[str, Any] = {
        m: {"result": None, "source": None} for m in ("spf", "dkim", "dmarc")
    }

    # Only the top-most header carrying a given mechanism is used: each hop
    # prepends its own, so the first one is the most recent / most trusted.
    auth_headers = _header_all(msg, "Authentication-Results")
    for mech in out:
        pattern = re.compile(
            rf"(?<![\w.-]){mech}\s*=\s*({_AUTH_RESULT_TOKENS})\b", re.I
        )
        for value in auth_headers:
            found = [_normalize_result(m) for m in pattern.findall(value)]
            if found:
                # DKIM can carry several signatures; report the worst.
                out[mech] = {"result": _worst(found), "source": "Authentication-Results"}
                break

    if out["spf"]["result"] is None:
        for value in _header_all(msg, "Received-SPF"):
            m = re.match(rf"\s*({_AUTH_RESULT_TOKENS})\b", value, re.I)
            if m:
                out["spf"] = {"result": _normalize_result(m.group(1)), "source": "Received-SPF"}
                break

    out["failed"] = [m for m in ("spf", "dkim", "dmarc")
                     if out[m]["result"] in _FAIL_RESULTS]
    out["all_passed"] = all(out[m]["result"] == "pass" for m in ("spf", "dkim", "dmarc"))
    return out


# --------------------------------------------------------------------------- #
# Display-name spoofing
# --------------------------------------------------------------------------- #


def _check_display_name_spoofing(
    display_name: str,
    from_address: str,
    recipient_domains: set[str],
    trusted_domains: set[str],
) -> dict[str, Any]:
    reasons: list[dict[str, str]] = []
    sender_domain = _addr_domain(from_address)
    sender_reg = _registered_domain(sender_domain)
    name = (display_name or "").strip()

    if name and sender_domain:
        # 1. Display name embeds a different email address.
        for m in _EMAIL_RE.finditer(name):
            embedded = _registered_domain(_addr_domain(m.group(0)))
            if embedded != sender_reg:
                reasons.append({
                    "code": "embedded_address_mismatch",
                    "detail": f"display name contains {m.group(0)!r} but mail is from {sender_domain}",
                })

        # 2. Well-known brand name sent from a domain the brand doesn't use.
        lowered = name.lower()
        for brand, domains in BRAND_DOMAINS.items():
            if re.search(rf"\b{re.escape(brand)}\b", lowered) and sender_reg not in domains:
                reasons.append({
                    "code": "brand_impersonation",
                    "detail": f"display name mentions {brand!r} but sender domain is {sender_domain}",
                })

        # 3. Internal-sounding role (IT Helpdesk, Payroll...) from an external domain.
        if _ROLE_RE.search(name):
            internal = {_registered_domain(d) for d in trusted_domains} | recipient_domains
            if sender_reg in internal:
                pass
            elif sender_reg in FREE_MAIL_DOMAINS:
                reasons.append({
                    "code": "role_name_from_free_mail",
                    "detail": f"role-style display name {name!r} sent from free mail provider {sender_domain}",
                })
            elif internal:
                reasons.append({
                    "code": "role_name_from_external_domain",
                    "detail": f"role-style display name {name!r} sent from external domain {sender_domain}",
                })

    return {
        "suspicious": bool(reasons),
        "display_name": name,
        "sender_domain": sender_domain,
        "reasons": reasons,
    }


# --------------------------------------------------------------------------- #
# Body / link extraction
# --------------------------------------------------------------------------- #


def _part_text(part: Message) -> str:
    try:
        return part.get_content()
    except Exception:  # unknown charset, bad encoding, ...
        payload = part.get_payload(decode=True)
        if payload is None:
            raw = part.get_payload()
            return raw if isinstance(raw, str) else ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def _collect_bodies(msg: Message) -> tuple[list[str], list[str]]:
    html_parts: list[str] = []
    text_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/html", "text/plain"):
            continue
        text = _part_text(part)
        if not text:
            continue
        if ctype == "text/html" or _HTML_HINT_RE.search(text):
            html_parts.append(text)
        if ctype == "text/plain":
            text_parts.append(text)
    return html_parts, text_parts


def _analyze_anchor(text: str, href: str) -> dict[str, Any]:
    reasons: list[str] = []
    shown_url: Optional[str] = None
    parsed = _safe_urlparse(href)
    host = (parsed.hostname or "") if parsed else ""

    match = _SHOWN_URL_RE.search(text)
    if match and host:
        shown_url = match.group(0).rstrip(".,;:!?)")
        shown = _safe_urlparse(shown_url if "://" in shown_url else "http://" + shown_url)
        shown_host = (shown.hostname or "") if shown else ""
        if shown_host and _registered_domain(shown_host) != _registered_domain(host):
            reasons.append("anchor_text_domain_mismatch")

    if parsed is not None and parsed.username is not None:
        reasons.append("userinfo_in_url")  # e.g. https://paypal.com@evil.example/
    if host and _is_ip(host):
        reasons.append("ip_address_host")
    if any(label.startswith("xn--") for label in host.split(".")):
        reasons.append("punycode_host")

    return {
        "text": text,
        "href": href,
        "shown_url": shown_url,
        "mismatch": "anchor_text_domain_mismatch" in reasons,
        "suspicious": bool(reasons),
        "reasons": reasons,
    }


def _extract_links(html: str) -> list[dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("//"):
            href = "http:" + href
        if not re.match(r"https?://", href, re.I):
            continue  # skip mailto:, tel:, javascript:, #anchors, relative links
        text = a.get_text(" ", strip=True)
        if not text:
            img = a.find("img", alt=True)
            text = img["alt"].strip() if img else ""
        links.append(_analyze_anchor(text, href))
    return links


# --------------------------------------------------------------------------- #
# Public: parse_email_text
# --------------------------------------------------------------------------- #


def parse_email_text(
    raw_input: str,
    trusted_domains: Optional[Iterable[str]] = None,
) -> dict[str, Any]:
    """
    Parse raw email text (full message or headers only) and return indicators.

    `trusted_domains` is optional: your organisation's own domains, used to
    decide whether a role-style display name ("IT Helpdesk") is external.
    Without it, recipient domains from To/Cc/Delivered-To are used as a proxy.
    """
    if isinstance(raw_input, (bytes, bytearray)):
        raw_input = bytes(raw_input).decode("utf-8", errors="replace")
    if not isinstance(raw_input, str):
        raise TypeError("raw_input must be str")

    raw = raw_input.lstrip("\r\n \t")
    msg = message_from_string(raw, policy=policy.default)
    has_headers = bool(msg.keys())
    if not has_headers:
        # Not an RFC 822 message: treat the whole input as a body.
        msg = message_from_string("Content-Type: text/plain\n\n" + raw, policy=policy.default)

    # --- Addresses ---------------------------------------------------------
    display_name, from_address = parseaddr(_header(msg, "From"))
    from_address = from_address.lower()
    reply_addrs = [a.lower() for _, a in getaddresses([_header(msg, "Reply-To")]) if a]
    reply_to = reply_addrs[0] if reply_addrs else None
    subject = _header(msg, "Subject")

    recipient_domains = {
        _registered_domain(_addr_domain(a.lower()))
        for hdr in ("To", "Cc", "Delivered-To", "X-Original-To")
        for _, a in getaddresses(_header_all(msg, hdr))
        if "@" in a
    }

    # --- Authentication ----------------------------------------------------
    auth = _parse_authentication(msg)

    # --- Display-name spoofing & reply-to ----------------------------------
    spoof = _check_display_name_spoofing(
        display_name, from_address, recipient_domains, set(trusted_domains or [])
    )
    reply_to_mismatch = bool(
        reply_to and from_address
        and _registered_domain(_addr_domain(reply_to)) != _registered_domain(_addr_domain(from_address))
    )

    # --- Links -------------------------------------------------------------
    html_parts, text_parts = _collect_bodies(msg)
    links: list[dict[str, Any]] = []
    for html in html_parts:
        links.extend(_extract_links(html))
    mismatched = [l for l in links if l["mismatch"]]

    urls: list[str] = []
    seen: set[str] = set()
    candidates = [l["href"] for l in links]
    for body in text_parts:
        candidates.extend(u.rstrip(".,;:!?") for u in _PLAIN_URL_RE.findall(body))
    for u in candidates:
        if u not in seen:
            seen.add(u)
            urls.append(u)

    # --- Summary flags -----------------------------------------------------
    indicators: list[str] = [f"{m}_{auth[m]['result']}" for m in auth["failed"]]
    if spoof["suspicious"]:
        indicators.append("display_name_spoofing")
    if reply_to_mismatch:
        indicators.append("reply_to_mismatch")
    if mismatched:
        indicators.append("link_text_href_mismatch")
    if any(l["suspicious"] and not l["mismatch"] for l in links):
        indicators.append("suspicious_link_structure")

    return {
        "from_address": from_address or None,
        "from_display_name": display_name or None,
        "reply_to": reply_to,
        "subject": subject or None,
        "authentication": auth,
        "display_name_spoofing": spoof,
        "reply_to_mismatch": reply_to_mismatch,
        "links": links,
        "link_mismatches": mismatched,
        "urls": urls,
        "risk_indicators": indicators,
    }


# --------------------------------------------------------------------------- #
# Public: unshorten_url
# --------------------------------------------------------------------------- #

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_UA = "Mozilla/5.0 (compatible; PhishTriage/1.0)"


def _host_is_private(url: str) -> bool:
    """True if the URL's host resolves to a non-public address (SSRF guard)."""
    parsed = _safe_urlparse(url)
    host = parsed.hostname if parsed else None
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False  # unresolvable; the request itself will fail
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
    return False


def unshorten_url(
    url: str,
    max_hops: int = 10,
    timeout: float = 5.0,
    block_private: bool = True,
) -> tuple[str, list[str]]:
    """
    Follow a redirect chain with `requests.head` and return (final_url, chain).

    `chain` lists every URL visited, starting with the input and ending with
    `final_url`. Redirects are followed manually so each hop can be validated:
    only http(s) is allowed, loops are detected, and (by default) hops that
    resolve to private/loopback/link-local addresses are not contacted.
    Network errors end the walk and return whatever was resolved so far.

    Note: fetching a phishing URL reveals your IP to the attacker and can mark
    the recipient as "active"; run this from an isolated egress if possible.
    """
    current = (url or "").strip()
    chain = [current]
    session = requests.Session()
    session.headers["User-Agent"] = _UA

    for _ in range(max_hops):
        parsed = _safe_urlparse(current)
        if not parsed or parsed.scheme not in ("http", "https"):
            break
        if block_private and _host_is_private(current):
            break
        try:
            resp = session.head(current, allow_redirects=False, timeout=timeout)
            if resp.status_code in (403, 405, 501):
                # Some servers reject HEAD; peek with a body-less GET.
                resp.close()
                resp = session.get(current, allow_redirects=False, timeout=timeout, stream=True)
            location = resp.headers.get("Location")
            status = resp.status_code
            resp.close()
        except requests.RequestException:
            break

        if status in _REDIRECT_CODES and location:
            nxt = urljoin(current, location.strip())
            if nxt in chain:  # redirect loop
                break
            chain.append(nxt)
            current = nxt
            continue
        break

    return current, chain


# --------------------------------------------------------------------------- #
# CLI: python email_parser.py message.eml   (or pipe via stdin)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    data = open(sys.argv[1], encoding="utf-8", errors="replace").read() if len(sys.argv) > 1 else sys.stdin.read()
    print(json.dumps(parse_email_text(data), indent=2))
