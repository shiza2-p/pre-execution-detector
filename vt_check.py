import sys
import requests
from pathlib import Path
from hasher import sha256_of_file

KEY_FILE = Path.home() / ".config" / "pre_execution" / "vt_key.txt"

def vt_lookup(sha256):
    key = KEY_FILE.read_text().strip()
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    r = requests.get(url, headers={"x-apikey": key}, timeout=20)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()["data"]["attributes"]["last_analysis_stats"]

if __name__ == "__main__":
    h = sha256_of_file(sys.argv[1])
    print("SHA-256:", h)
    stats = vt_lookup(h)
    if stats is None:
        print("VirusTotal has never seen this file.")
    else:
        print("Malicious engines:", stats["malicious"])
        print("Full stats:", stats)