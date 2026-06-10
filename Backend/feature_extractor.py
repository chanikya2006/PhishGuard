# feature_extractor.py
import re
import tldextract
import math
import socket
import dns.resolver
import whois
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone
import requests
import difflib

# ---- Typosquatting: top legitimate domains to compare against ----
TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "youtube.com", "twitter.com", "instagram.com",
    "linkedin.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "paypal.com", "ebay.com", "yahoo.com", "bing.com", "reddit.com",
    "wikipedia.org", "whatsapp.com", "tiktok.com", "dropbox.com", "github.com",
    "stackoverflow.com", "adobe.com", "wordpress.com", "shopify.com", "zoom.us",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com", "hsbc.com",
    "steampowered.com", "twitch.tv", "discord.com", "spotify.com", "pinterest.com"
]

# ---- URL Obfuscation Decoding ----

def decode_url(url):
    """
    Decode common URL obfuscation techniques:
    - Percent encoding (%2F, %40, etc.)
    - Unicode/punycode homoglyph detection
    - Hex-encoded domain parts
    - Double encoding
    """
  
    decoded = url
    for _ in range(3):
        new = unquote(decoded)
        if new == decoded:
            break
        decoded = new

    
    hex_pattern = r'0x[0-9a-fA-F]+'
    hex_matches = re.findall(hex_pattern, decoded)

   
    homoglyph_map = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',  
        'ο': 'o', 'ρ': 'p', 'ν': 'v',                        
        'ℯ': 'e', 'ℓ': 'l', '℮': 'e',                         
    }
    has_homoglyph = any(ch in homoglyph_map for ch in decoded)

    
    has_punycode = 'xn--' in decoded.lower()

    return {
        'decoded_url': decoded,
        'has_hex_encoding': 1 if hex_matches else 0,
        'has_homoglyph': 1 if has_homoglyph else 0,
        'has_punycode': 1 if has_punycode else 0,
        'encoding_layers': sum([
            1 if '%' in url else 0,
            1 if hex_matches else 0,
            1 if has_homoglyph else 0,
            1 if has_punycode else 0,
        ])
    }


# ---- Live DNS Lookup ----

def dns_lookup(domain):
    """
    Perform live DNS lookups:
    - A record (does domain resolve?)
    - MX record (does it have mail?)
    - NS record (nameserver info)
    Returns a dict of findings.
    """
    result = {
        'dns_resolves': 0,
        'has_mx_record': 0,
        'has_ns_record': 0,
        'ip_address': None,
        'is_cdn_ip': 0,
        'dns_ttl': None,
    }

    # Known CDN/hosting IP ranges (Cloudflare, Fastly, etc.) — suspicious for phishing
    cdn_ranges = ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.',
                  '172.64.', '172.65.', '172.66.', '151.101.']

    try:
        # A record — does it resolve?
        answers = dns.resolver.resolve(domain, 'A', lifetime=3)
        result['dns_resolves'] = 1
        ip = str(answers[0])
        result['ip_address'] = ip
        result['is_cdn_ip'] = 1 if any(ip.startswith(r) for r in cdn_ranges) else 0
        try:
            result['dns_ttl'] = answers.rrset.ttl
        except:
            pass
    except:
        pass

    try:
        dns.resolver.resolve(domain, 'MX', lifetime=3)
        result['has_mx_record'] = 1
    except:
        pass

    try:
        dns.resolver.resolve(domain, 'NS', lifetime=3)
        result['has_ns_record'] = 1
    except:
        pass

    return result


# ---- WHOIS Lookup ----

def whois_lookup(domain):
    """
    Perform WHOIS lookup to determine:
    - Domain age (newly registered = suspicious)
    - Expiry date
    - Registrar
    """
    result = {
        'domain_age_days': -1,
        'is_newly_registered': 0,    # < 90 days old
        'expires_soon': 0,           # expires within 1 year
        'whois_available': 0,
    }

    try:
        w = whois.whois(domain)
        result['whois_available'] = 1

        # Creation date
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - created).days
            result['domain_age_days'] = age_days
            result['is_newly_registered'] = 1 if age_days < 90 else 0

        # Expiry date
        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        if expires:
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            days_to_expiry = (expires - datetime.now(timezone.utc)).days
            result['expires_soon'] = 1 if days_to_expiry < 365 else 0

    except:
        pass

    return result


# ---- Typosquatting Detection ----

def detect_typosquatting(domain):
    """
    Compare the scanned domain against a list of trusted domains using
    similarity scoring to catch typosquatting attempts like:
    - paypa1.com  vs paypal.com
    - g00gle.com  vs google.com
    - arnazon.com vs amazon.com
    """
    result = {
        'is_typosquatting': 0,
        'typosquatting_target': None,
        'typosquatting_score': 0.0,
    }

    # Strip www and extract just the registered domain
    extracted = tldextract.extract(domain)
    scanned = f"{extracted.domain}.{extracted.suffix}".lower()

    best_score = 0.0
    best_match = None

    for trusted in TRUSTED_DOMAINS:
        # Don't flag exact matches
        if scanned == trusted:
            return result

        score = difflib.SequenceMatcher(None, scanned, trusted).ratio()
        if score > best_score:
            best_score = score
            best_match = trusted

    # Flag if similarity > 0.80 but not exact match (> 0.99)
    if 0.80 < best_score < 0.99:
        result['is_typosquatting'] = 1
        result['typosquatting_target'] = best_match
        result['typosquatting_score'] = round(best_score, 3)

    return result


# ---- Main Feature Extractor ----

def extract_safe_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc

    features['URLLength'] = len(url)
    features['DomainLength'] = len(domain)

    # IsDomainIP
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features['IsDomainIP'] = 1 if re.match(ip_pattern, domain) else 0

    # CharContinuationRate
    runs = [len(match.group()) for match in re.finditer(r'(.)\1*', url)]
    features['CharContinuationRate'] = sum(runs) / len(runs) if runs else 0

    # TLD extraction
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    features['TLDLength'] = len(tld)
    legit_tlds = {'.com', '.org', '.net', '.gov', '.edu', '.io', '.co.uk'}
    suspect_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.loan', '.zip', '.mov'}
    if '.' + tld in legit_tlds or tld in legit_tlds:
        features['TLDLegitimateProb'] = 0.9
    elif '.' + tld in suspect_tlds or tld in suspect_tlds:
        features['TLDLegitimateProb'] = 0.1
    else:
        features['TLDLegitimateProb'] = 0.5

    # URLCharProb: character entropy (normalised)
    char_counts = {}
    for ch in url:
        char_counts[ch] = char_counts.get(ch, 0) + 1
    if len(url) > 0:
        entropy = -sum((c/len(url)) * math.log2(c/len(url)) for c in char_counts.values())
        features['URLCharProb'] = entropy / 8.0
    else:
        features['URLCharProb'] = 0

    # Subdomain count (excluding www)
    subdomains = domain.split('.')
    if subdomains[0] == 'www':
        subdomains = subdomains[1:]
    features['NoOfSubDomain'] = len(subdomains) - 1 if len(subdomains) > 1 else 0

    # Obfuscation (basic character count)
    obf_chars = ['@', '%', '\\', '&', '?', '#', ';']
    obf_count = sum(url.count(c) for c in obf_chars)
    features['HasObfuscation'] = 1 if obf_count > 0 else 0
    features['NoOfObfuscatedChar'] = obf_count
    features['ObfuscationRatio'] = obf_count / len(url) if len(url) > 0 else 0

    # Letters and digits
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    features['NoOfLettersInURL'] = letters
    features['LetterRatioInURL'] = letters / len(url) if len(url) > 0 else 0
    features['NoOfDegitsInURL'] = digits
    features['DegitRatioInURL'] = digits / len(url) if len(url) > 0 else 0

    # Special characters
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')
    other_special = sum(url.count(c) for c in '~!@#$%^&*()_+{}|:"<>?`')
    features['NoOfOtherSpecialCharsInURL'] = other_special
    features['SpacialCharRatioInURL'] = other_special / len(url) if len(url) > 0 else 0

    # HTTPS
    features['IsHTTPS'] = 1 if parsed.scheme == 'https' else 0

    # Placeholders for redirects
    features['NoOfURLRedirect'] = 0
    features['NoOfSelfRedirect'] = 0

    return features


def get_redirect_info(url, timeout=3):
    """Lightweight HEAD request to count redirects."""
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True,
                                 headers={'User-Agent': 'Mozilla/5.0'})
        redirect_count = len(response.history)
        final_domain = urlparse(response.url).netloc
        initial_domain = urlparse(url).netloc
        self_redirect = 1 if (redirect_count > 0 and final_domain == initial_domain) else 0
        return redirect_count, self_redirect
    except:
        return 0, 0


def get_threat_intelligence(url):
    """
    Run all threat intelligence checks:
    - URL obfuscation decoding
    - DNS lookup
    - WHOIS lookup
    - Typosquatting detection

    Returns a combined dict of all findings.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    # Strip port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    # Strip www
    clean_domain = domain.replace('www.', '')

    obfuscation = decode_url(url)
    dns_info = dns_lookup(clean_domain)
    whois_info = whois_lookup(clean_domain)
    typosquat = detect_typosquatting(clean_domain)

    return {
        **obfuscation,
        **dns_info,
        **whois_info,
        **typosquat,
    }