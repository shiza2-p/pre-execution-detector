import hashlib
import sys

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

if __name__ == "__main__":
    print(sha256_of_file(sys.argv[1]))