import sys
from pathlib import Path
from hasher import sha256_of_file
from scan import lookup
from yara_scan import yara_scan
from entropy import file_entropy, section_entropies

ENTROPY_LIMIT = 7.0
MIN_SIZE = 4096

def analyze(path):
    path = Path(path)
    stats, _ = lookup(sha256_of_file(path))
    hash_hit = bool(stats) and stats["malicious"] >= 1
    rules = yara_scan(path)
    values = [file_entropy(path)]
    sections = section_entropies(path)
    if sections:
        values += [e for _, size, e in sections if size > 0]
    high = path.stat().st_size >= MIN_SIZE and max(values) > ENTROPY_LIMIT
    return hash_hit, rules, high

def mark(flag):
    return "FLAG" if flag else "pass"

if __name__ == "__main__":
    path = Path(sys.argv[1])
    hash_hit, rules, high = analyze(path)
    s1 = hash_hit
    s2 = s1 or bool(rules)
    s3 = s2 or high
    print(f"{path.name:22s} hash-only:{mark(s1):5s} +YARA:{mark(s2):5s} +entropy:{mark(s3):5s}")