import re, hashlib

INJECTION_PATTERNS = [
    (r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)', 'instruction_override', 'CRITICAL', 75, 'Ignore instructions'),
    (r'disregard\s+(all\s+)?(previous|prior|above|earlier)', 'instruction_override', 'CRITICAL', 75, 'Disregard instructions'),
    (r'\bDAN\b|do\s+anything\s+now', 'jailbreak', 'CRITICAL', 80, 'DAN attack'),
    (r'developer\s+mode|jailbreak\s+mode|unrestricted\s+mode', 'jailbreak', 'CRITICAL', 75, 'Jailbreak mode'),
    (r'pretend\s+(you\s+have\s+no\s+(rules|guidelines)|you\s+are)', 'instruction_override', 'HIGH', 60, 'Pretend no rules'),
    (r'show\s+me\s+your\s+system\s+prompt|repeat.*instructions.*received', 'prompt_leak', 'HIGH', 75, 'System prompt'),
    (r'verbatim\s+word\s+for\s+word|exact\s+instructions.*init', 'prompt_leak', 'HIGH', 75, 'Verbatim extraction'),
    (r'write.*phishing|phishing.*impersonat', 'harmful_content', 'CRITICAL', 75, 'Phishing'),
    (r'malware.*steal|brute\s+force.*login|steal.*password', 'harmful_content', 'CRITICAL', 75, 'Malware'),
    (r'send.*conversation.*http|forward.*chat.*history.*@', 'data_exfiltration', 'CRITICAL', 75, 'Exfiltration'),
    (r'upload.*user.*data.*credential|fetch.*https?://evil', 'data_exfiltration', 'CRITICAL', 75, 'Data upload exfil'),
    (r'collect\?data=', 'data_exfiltration', 'HIGH', 65, 'Markdown exfil'),
    (r'my\s+credit\s+card\s+is\s+\d|\d{4}\s+\d{4}\s+\d{4}\s+\d{4}', 'pii_leak', 'HIGH', 60, 'Credit card'),
    (r'SSN\s*:\s*\d{3}-\d{2}-\d{4}|social\s+security', 'pii_leak', 'HIGH', 60, 'SSN'),
    (r'aws\s+key|AKIA[A-Z0-9]+|access\s+key\s+id', 'pii_leak', 'HIGH', 60, 'AWS key'),
    (r'card\s+\d{4}\s+\d{4}|process.*order.*card\s+\d', 'pii_leak', 'HIGH', 60, 'Card in order'),
    (r'thought\s+experiment.*what\s+would\s+happen|as\s+a\s+thought\s+experiment', 'evasion_attempt', 'HIGH', 60, 'Thought experiment'),
    (r'academic\s+research\s+purposes|demonstrate\s+bypass', 'evasion_attempt', 'HIGH', 60, 'Academic evasion'),
    (r'play\s+a\s+game\s+where\s+you\s+are|completely\s+different\s+ai', 'evasion_attempt', 'HIGH', 60, 'Roleplay trick'),
    (r'hypothetically.*restrictions\s+were\s+removed|if\s+all\s+your\s+restrictions', 'evasion_attempt', 'HIGH', 60, 'Hypothetical'),
    (r'simulate\s+(a\s+)?world\s+where.*(no\s+)?(rules|ethics|laws)', 'manipulation', 'CRITICAL', 75, 'No-rules simulation'),
]

def scan_text(text: str, threshold: int = 70) -> dict:
    matches = []
    raw_score = 0
    for pattern, attack_type, severity, weight, description in INJECTION_PATTERNS:
        found = re.findall(pattern, text, re.IGNORECASE)
        if found:
            raw_score += weight
            matches.append({'pattern': attack_type, 'attack_type': attack_type, 'severity': severity, 'description': description, 'match_count': len(found), 'weight': weight})
    risk_score = min(raw_score, 100)
    verdict = 'BLOCKED' if risk_score >= threshold else 'ALLOWED'
    input_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
    return {'verdict': verdict, 'risk_score': risk_score, 'matches_found': len(matches), 'matches': matches, 'input_hash': input_hash}
