import re

def extract_iocs(text: str) -> dict:
    iocs = {
        "ips": re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text),
        "hashes": re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text),  # MD5/SHA1/SHA256
        "urls": re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    }
    return {k: list(set(v)) for k, v in iocs.items() if v}  # unique & non-empty