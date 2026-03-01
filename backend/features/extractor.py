import re, math, urllib.parse, base64
from collections import Counter

# ── Attack pattern regexes ──────────────────────────────
SQL = re.compile(
    r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDROP\b|\bOR\b.*=|--|/\*)",
    re.IGNORECASE)
XSS = re.compile(
    r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",
    re.IGNORECASE)
RCE = re.compile(
    r"(eval\(|exec\(|system\(|passthru|shell_exec|`[^`]+`)",
    re.IGNORECASE)
LFI = re.compile(
    r"(\.\./|\.\.\\\\|/etc/passwd|php://|file://)",
    re.IGNORECASE)
CMD = re.compile(
    r"(;\s*\w+|&&|\|\||`[^`]+`|\$\([^)]+\))",
    re.IGNORECASE)

def shannon_entropy(text: str) -> float:
    """High entropy = randomness = possible encoding/obfuscation"""
    if not text: return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

def extract_features(payload: str) -> dict:
    # Multi-layer decode to catch encoded attacks
    decoded = urllib.parse.unquote(payload)
    double_decoded = urllib.parse.unquote(decoded)

    # Base64 detection
    b64 = False
    try:
        if len(payload) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', payload):
            base64.b64decode(payload)
            b64 = True
    except: pass

    return {
        'length':              len(payload),
        'entropy':             shannon_entropy(payload),
        'special_char_density': sum(1 for c in payload if c in "'\";()=<>|&%#/\\") / max(len(payload),1),
        'sql_hits':            len(SQL.findall(decoded)),
        'xss_hits':            len(XSS.findall(decoded)),
        'rce_hits':            len(RCE.findall(decoded)),
        'lfi_hits':            len(LFI.findall(decoded)),
        'cmd_hits':            len(CMD.findall(decoded)),
        'url_encoded':         int(decoded != payload),
        'double_encoded':      int(double_decoded != decoded),
        'base64_suspected':    int(b64),
        'null_byte':           int("\x00" in payload),
        'quote_count':         payload.count("'") + payload.count('"'),
        'comment_count':       payload.count('--') + payload.count('/*'),
        'semicolon_count':     payload.count(';'),
        'path_traversal':      payload.count('../'),
    }