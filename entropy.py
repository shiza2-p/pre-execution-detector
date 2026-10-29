import math
import sys
from collections import Counter
import pefile

def shannon(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return max(0.0, -sum((c / n) * math.log2(c / n) for c in counts.values()))

def file_entropy(path):
    with open(path, "rb") as f:
        return shannon(f.read())

def section_entropies(path):
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError:
        return None
    result = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", "replace")
        result.append((name, s.SizeOfRawData, shannon(s.get_data())))
    pe.close()
    return result

if __name__ == "__main__":
    path = sys.argv[1]
    print(f"Whole-file entropy: {file_entropy(path):.2f} / 8.00")
    sections = section_entropies(path)
    if sections is None:
        print("Not a Windows program (PE file), so no section check.")
    else:
        print("Per-section entropy:")
        for name, size, ent in sections:
            print(f"  {name:10s} size={size:8d}  entropy={ent:.2f}")