"""URL enrichment helpers for PhishGuard."""

from datetime import date, datetime, timezone
from difflib import SequenceMatcher
import ipaddress
import os
import socket
from urllib.parse import urljoin, urlsplit

import requests

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    import whois
except ImportError:
    whois = None


REQUEST_TIMEOUT_SECONDS = 3
MAX_REDIRECTS = 5
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BRAND_DOMAINS = {
    "Microsoft": "microsoft.com",
    "Google": "google.com",
    "Apple": "apple.com",
    "PayPal": "paypal.com",
    "Bank of America": "bankofamerica.com",
    "Workday": "workday.com",
    "Okta": "okta.com",
}

_AUTH_TERMS = {
    "account",
    "auth",
    "billing",
    "login",
    "secure",
    "signin",
    "support",
    "update",
    "verify",
}

_TLD_EXTRACTOR = (
    tldextract.TLDExtract(suffix_list_urls=()) if tldextract is not None else None
)


def _get_hostname(url: str) -> str | None:
    """Parse an HTTP(S) URL and return its normalized hostname."""
    if not isinstance(url, str) or not url.strip():
        return None

    value = url.strip()
    if "://" not in value and not value.startswith("//"):
        value = "//" + value
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        _ = parsed.port
        hostname = parsed.hostname
        if hostname is None:
            return None
        return hostname.rstrip(".").encode("idna").decode("ascii").lower() or None
    except (UnicodeError, ValueError):
        return None


def _get_domain(hostname: str) -> str | None:
    """Return the registrable domain using the local tldextract suffix data."""
    if _TLD_EXTRACTOR is None:
        return None
    try:
        result = _TLD_EXTRACTOR(hostname)
    except Exception:
        return None
    return result.top_domain_under_public_suffix or None


def _domain_age_days(domain: str) -> int | None:
    """Look up the WHOIS creation date; return None when unavailable."""
    if whois is None:
        return None
    try:
        record = whois.whois(domain, timeout=REQUEST_TIMEOUT_SECONDS)
    except Exception:
        return None

    created = getattr(record, "creation_date", None)
    if isinstance(created, (list, tuple)):
        created = next((item for item in created if item is not None), None)
    if isinstance(created, date) and not isinstance(created, datetime):
        created = datetime(created.year, created.month, created.day)
    if not isinstance(created, datetime):
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    else:
        created = created.astimezone(timezone.utc)

    age = (datetime.now(timezone.utc) - created).days
    return age if age >= 0 else None


def _normalize_homoglyphs(text: str) -> str:
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})
    return text.translate(table)


def _brand_impersonation(
    hostname: str, domain: str | None
) -> tuple[bool, str | None]:
    """Check the hostname and registrable label for likely brand impersonation."""
    if not domain:
        return False, None

    labels = hostname.split(".")
    domain_labels = domain.split(".")
    subdomain_labels = labels[: -len(domain_labels)]
    registered_label = domain_labels[0].replace("-", "")
    norm_registered_label = _normalize_homoglyphs(registered_label)

    for brand, official_domain in BRAND_DOMAINS.items():
        official_label = official_domain.split(".")[0]
        brand_label = official_label.replace("-", "")
        is_official_domain = domain == official_domain

        if not is_official_domain and any(
            brand_label in _normalize_homoglyphs(label.replace("-", "")) for label in subdomain_labels
        ):
            return True, brand

        if is_official_domain:
            continue

        tokens = domain_labels[0].lower().split("-")
        norm_tokens = [_normalize_homoglyphs(t) for t in tokens]
        similarity = SequenceMatcher(
            None, registered_label.lower(), brand_label.lower()
        ).ratio()
        norm_similarity = SequenceMatcher(
            None, norm_registered_label.lower(), brand_label.lower()
        ).ratio()
        suspicious_combination = (
            (brand_label in registered_label.lower() or brand_label in norm_registered_label.lower())
            and any(term in tokens or term in norm_tokens for term in _AUTH_TERMS)
        )
        brand_plus_other_word = (brand_label in tokens or brand_label in norm_tokens) and len(tokens) > 1
        if similarity >= 0.82 or norm_similarity >= 0.82 or suspicious_combination or brand_plus_other_word:
            return True, brand

    return False, None


def _is_public_http_url(url: str) -> bool:
    """Reject non-HTTP URLs and hosts that resolve to non-public IP addresses."""
    hostname = _get_hostname(url)
    if hostname is None:
        return False
    try:
        parsed = urlsplit(url if "://" in url else "//" + url)
    except ValueError:
        return False
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return False

    try:
        addresses = {ipaddress.ip_address(hostname)}
    except ValueError:
        try:
            address_records = socket.getaddrinfo(
                hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
            )
        except OSError:
            return False
        addresses = {
            ipaddress.ip_address(record[4][0]) for record in address_records
        }
    return bool(addresses) and all(address.is_global for address in addresses)


def _get_final_url(url: str) -> tuple[str, bool, str | None]:
    """Follow a small number of public HTTP redirects using timed HEAD requests."""
    start_url = url.strip()
    if start_url.startswith("//"):
        start_url = "https:" + start_url
    elif "://" not in start_url:
        start_url = "https://" + start_url
    current_url = start_url
    session = requests.Session()
    session.trust_env = False
    try:
        for _ in range(MAX_REDIRECTS + 1):
            if not _is_public_http_url(current_url):
                return url, False, "Redirect check skipped for a non-public or invalid host."
            try:
                response = session.head(
                    current_url,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
            except requests.RequestException as error:
                return url, False, f"Redirect check failed ({type(error).__name__})."

            if response.status_code not in {301, 302, 303, 307, 308}:
                return current_url, current_url != start_url, None
            location = response.headers.get("Location")
            if not location:
                return current_url, current_url != start_url, None
            next_url = urljoin(current_url, location)
            if _get_hostname(next_url) is None:
                return url, False, "Redirect target was invalid."
            current_url = next_url
        return url, False, "Redirect limit exceeded."
    finally:
        session.close()


def _virustotal_malicious_hits(domain: str, api_key: str | None) -> int:
    """Return VirusTotal's malicious count, or zero if unavailable."""
    if not api_key:
        return 0
    try:
        response = requests.get(
            VIRUSTOTAL_DOMAIN_URL + domain,
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            return 0
        payload = response.json()
        hits = payload["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return hits if isinstance(hits, int) and not isinstance(hits, bool) else 0
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return 0


def enrich_url_telemetry(
    extracted_urls: list[dict],
) -> tuple[list[dict], list[str]]:
    """Enrich extracted URL objects with redirect, WHOIS, and reputation data."""
    enriched_urls: list[dict] = []
    generated_flags: list[str] = []
    api_key = os.getenv("VIRUSTOTAL_API_KEY") or VIRUSTOTAL_API_KEY

    def add_flag(flag: str) -> None:
        if flag not in generated_flags:
            generated_flags.append(flag)

    for item in extracted_urls:
        enriched = dict(item)
        initial_url = item.get("initial_url")
        if not isinstance(initial_url, str):
            initial_url = ""

        hostname = _get_hostname(initial_url)
        domain = _get_domain(hostname) if hostname else None
        if not domain and hostname:
            try:
                ipaddress.ip_address(hostname)
                domain = hostname
            except ValueError:
                pass

        final_url, is_redirected, redirect_warning = _get_final_url(initial_url)
        final_hostname = _get_hostname(final_url)
        if final_hostname:
            hostname = final_hostname
            final_domain = _get_domain(final_hostname)
            if final_domain:
                domain = final_domain

        is_typosquat, targeted_brand = (
            _brand_impersonation(hostname, domain) if hostname else (False, None)
        )
        is_ip_address = False
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_ip_address = True
            except ValueError:
                pass

        age_days = _domain_age_days(domain) if domain and not is_ip_address else None
        malicious_hits = (
            _virustotal_malicious_hits(domain, api_key)
            if domain and not is_ip_address
            else 0
        )

        if age_days is not None and age_days < 5:
            add_flag("Domain age < 5 days")
        if is_typosquat:
            add_flag("Typosquatting detected")
        if malicious_hits > 0:
            add_flag("VirusTotal malicious detections")
        if is_redirected:
            add_flag("URL redirected")

        enriched.update(
            {
                "initial_url": initial_url,
                "final_url": final_url,
                "is_redirected": is_redirected,
                "domain": domain or "",
                "domain_age_days": age_days,
                "is_typosquat": is_typosquat,
                "targeted_brand": targeted_brand,
                "virustotal_malicious_hits": malicious_hits,
            }
        )
        if redirect_warning:
            enriched["warnings"] = [redirect_warning]
        enriched_urls.append(enriched)

    return enriched_urls, generated_flags