
import boto3
import hashlib
import json
from pathlib import Path
from botocore.exceptions import ClientError

BUCKET_NAME = "cloudsentinel-fim-test-2026"
FILE_NAME = "cloud_test.txt"
BASELINE_FILE = Path("s3_baseline.json")


def get_s3_file_hash():
    s3 = boto3.client("s3")

    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=FILE_NAME
    )

    content = response["Body"].read()
    return hashlib.sha256(content).hexdigest()


try:
    current_hash = get_s3_file_hash()

    print("\nCloudSentinel - AWS S3 File Monitor")
    print("----------------------------------")
    print("File:", FILE_NAME)

    if not BASELINE_FILE.exists():
        baseline = {
            "bucket": BUCKET_NAME,
            "file": FILE_NAME,
            "sha256": current_hash
        }

        BASELINE_FILE.write_text(
            json.dumps(baseline, indent=4),
            encoding="utf-8"
        )

        print("Baseline saved successfully.")
        print("Status: File integrity baseline created.")

    else:
        baseline = json.loads(
            BASELINE_FILE.read_text(encoding="utf-8")
        )

        if (
            baseline.get("bucket") != BUCKET_NAME
            or baseline.get("file") != FILE_NAME
        ):
            print("ERROR: Baseline belongs to another file.")
        elif current_hash == baseline["sha256"]:
            print("Status: SAFE - No content change detected.")
        else:
            print("ALERT: S3 file content has changed!")
            print("Previous hash:", baseline["sha256"])
            print("Current hash: ", current_hash)

except ClientError as error:
    print("AWS Error:", error.response["Error"]["Code"])
except (OSError, ValueError, KeyError) as error:
    print("Monitor error:", error)
