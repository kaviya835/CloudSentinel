
import hashlib
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
TARGET_FILE = BASE_DIR / "fim_test_file.txt"
HASH_FILE = BASE_DIR / "fim_hash.json"


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def monitor_file():
    if not TARGET_FILE.exists():
        TARGET_FILE.write_text(
            "CloudSentinel file integrity test.",
            encoding="utf-8"
        )
        print("Test file created.")
        print("Run the command again to create its baseline hash.")
        return

    current_hash = calculate_hash(TARGET_FILE)

    if not HASH_FILE.exists():
        HASH_FILE.write_text(
            json.dumps({"sha256": current_hash}, indent=2),
            encoding="utf-8"
        )
        print("Baseline hash saved successfully.")
        print("SHA-256:", current_hash)
        return

    saved_data = json.loads(
        HASH_FILE.read_text(encoding="utf-8")
    )
    saved_hash = saved_data["sha256"]

    print("Saved hash:  ", saved_hash)
    print("Current hash:", current_hash)

    if current_hash == saved_hash:
        print("SAFE: File has not changed.")
    else:
        print("ALERT: File integrity changed!")
        print("Verify the change before updating the baseline.")


if __name__ == "__main__":
    monitor_file()
