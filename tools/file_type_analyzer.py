# tools/file_type_analyzer.py

def detect_file_type(file_bytes: bytes) -> dict:
    """
    Returns dict with 'type' and 'description'
    Adapt this to your real P1 implementation
    """
    signatures = {
        b'\x4D\x5A': ("PE Executable", "Windows executable or DLL – check for malicious payloads"),
        b'\x25\x50\x44\x46': ("PDF", "PDF document – possible embedded exploits"),
        b'\x50\x4B\x03\x04': ("ZIP", "ZIP archive – check for malicious macros/scripts"),
        b'\x7F\x45\x4C\x46': ("ELF", "Linux executable – potential backdoor"),
        # add more from your P1 code
    }

    for sig, (typ, desc) in signatures.items():
        if file_bytes.startswith(sig):
            return {"type": typ, "description": desc, "suspicious": "high" if "executable" in typ.lower() else "medium"}

    return {"type": "Unknown", "description": "No known signature match", "suspicious": "low"}