import re
import stat
import sys
from pathlib import Path

RISKY = {".exe", ".bat", ".cmd", ".scr", ".com", ".vbs", ".js", ".ps1", ".lnk", ".hta", ".msi", ".jar"}
DECOY = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".zip", ".rar"}
RLO = "\u202e"

def double_extension(name):
    parts = [s.lower() for s in Path(name).suffixes]
    return len(parts) >= 2 and parts[-1] in RISKY and parts[-2] in DECOY

def has_rlo(name):
    return RLO in name

def is_hidden(path):
    attrs = getattr(Path(path).stat(), "st_file_attributes", 0)
    return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)

def web_zone(path):
    try:
        with open(str(path) + ":Zone.Identifier", "r") as f:
            m = re.search(r"ZoneId=(\d)", f.read())
            return int(m.group(1)) if m else None
    except OSError:
        return None

if __name__ == "__main__":
    p = Path(sys.argv[1])
    print(f"{p.name}")
    print(f"  double extension : {double_extension(p.name)}")
    print(f"  right-to-left trick: {has_rlo(p.name)}")
    print(f"  hidden attribute : {is_hidden(p)}")
    print(f"  web zone (3=internet): {web_zone(p)}")