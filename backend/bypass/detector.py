import re, urllib.parse, unicodedata
from features.extractor import SQL, XSS

class BypassDetector:
    def analyze(self, raw: str, prediction: dict) -> dict:
        flags = []
        norm  = self._normalize(raw)

        # Low-confidence but decoded payload matches attack patterns
        if prediction["confidence"] < 0.50:
            if SQL.search(norm) or XSS.search(norm):
                flags.append("ENCODING_BYPASS: Attack visible after normalization")

        # Null byte injection
        if "\x00" in raw:
            flags.append("NULL_BYTE: Parser termination attempt")

        # Unicode homoglyph attack
        if unicodedata.normalize("NFKC", raw) != raw:
            flags.append("UNICODE: Homoglyph or fullwidth characters used")

        # Comment-fragmented SQL keywords (SE/**/LECT)
        if re.search(r'S[^\w]*E[^\w]*L[^\w]*E[^\w]*C[^\w]*T', raw, re.I):
            flags.append("COMMENT_FRAG: SQL keyword broken with comments")

        # Whitespace alternatives in SQL
        if re.search(r'(SELECT|UNION|DROP)[\t\n\r\x0b]', raw, re.I):
            flags.append("WHITESPACE_OBFUSC: Non-standard whitespace in keywords")

        return {
            "is_bypass_attempt":  len(flags) > 0,
            "bypass_flags":       flags,
            "normalized_payload": norm,
        }

    def _normalize(self, payload: str) -> str:
        for _ in range(3):
            new = urllib.parse.unquote(payload)
            new = new.replace("&lt;","<").replace("&gt;",">")
            new = unicodedata.normalize("NFKC", new)
            if new == payload: break
            payload = new
        return payload