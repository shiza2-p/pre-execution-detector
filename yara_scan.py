import sys
import yara
from pathlib import Path

RULES_DIR = Path(__file__).with_name("rules")

def load_rules():
    files = {p.stem: str(p) for p in RULES_DIR.glob("*.yar")}
    return yara.compile(filepaths=files)

def yara_scan(path):
    return [m.rule for m in load_rules().match(str(path))]

if __name__ == "__main__":
    print(yara_scan(sys.argv[1]) or "no rule matched")