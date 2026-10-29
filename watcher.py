import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scoring import score_file
from enforce import deny_file

WATCH_DIR = Path(__file__).with_name("watched")

def wait_until_stable(path, tries=20):
    last = -1
    for _ in range(tries):
        size = path.stat().st_size
        if size == last:
            return True
        last = size
        time.sleep(0.5)
    return False

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        try:
            if not wait_until_stable(path):
                print(f"[!] {path.name}: file kept changing, skipped")
                return
            points, verdict, reasons = score_file(path)
            print(f"[{verdict}] {path.name} ({points} points)")
            for r in reasons:
                print("      ", r)
            if verdict == "BLOCK":
                try:
                    created = deny_file(path)
                    print("       -> AppLocker deny rule", "created" if created else "already existed")
                except Exception as e:
                    print("       -> could not create deny rule:", e)
        except Exception as e:
            print(f"[!] {path.name}: error: {e}")

if __name__ == "__main__":
    WATCH_DIR.mkdir(exist_ok=True)
    observer = Observer()
    observer.schedule(Handler(), str(WATCH_DIR), recursive=False)
    observer.start()
    print(f"Watching {WATCH_DIR} ... (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()