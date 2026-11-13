import sys
from pathlib import Path
from hasher import sha256_of_file
from scan import lookup
from yara_scan import yara_scan
from entropy import file_entropy, section_entropies
from heuristics import double_extension, has_rlo, is_hidden, web_zone

BLOCK_AT = 70
WARN_AT = 30
ENTROPY_LIMIT = 7.0
MIN_SIZE = 4096

def score_file(path):
    path = Path(path)
    points = 0
    reasons = []

    def add(pts, why):
        nonlocal points
        points += pts
        reasons.append(f"+{pts:<3d} {why}")

    stats, _ = lookup(sha256_of_file(path))
    if stats is None:
        reasons.append("+0   VirusTotal has never seen this file (no information)")
    else:
        m = stats["malicious"]
        if m >= 15:
            add(80, f"VirusTotal: {m} engines flag it")
        elif m >= 5:
            add(40, f"VirusTotal: {m} engines flag it")
        elif m >= 1:
            add(10, f"VirusTotal: only {m} engine(s) flag it")

    rules = yara_scan(path)
    if rules:
        add(20, "YARA matched: " + ", ".join(rules))

    values = [file_entropy(path)]
    sections = section_entropies(path)
    if sections:
        values += [e for _, size, e in sections if size > 0]
    if path.stat().st_size >= MIN_SIZE and max(values) > ENTROPY_LIMIT:
        add(15, f"high entropy ({max(values):.2f})")

    if double_extension(path.name):
        add(30, "double extension")
    if has_rlo(path.name):
        add(40, "right-to-left filename trick")
    if is_hidden(path):
        add(10, "hidden attribute")
    if web_zone(path) == 3:
        add(10, "downloaded from the internet")

    if points >= BLOCK_AT:
        verdict = "BLOCK"
    elif points >= WARN_AT:
        verdict = "SUSPICIOUS"
    else:
        verdict = "ALLOW"
    return points, verdict, reasons

if __name__ == "__main__":
    p = Path(sys.argv[1])
    points, verdict, reasons = score_file(p)
    print(f"{p.name}: {verdict} ({points} points)")
    for r in reasons:
        print("   ", r)
