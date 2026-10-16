
import boto3
from botocore.exceptions import ClientError

BUCKET_NAME = "cloudsentinel-fim-test-2026"
FILE_NAME = "cloud_test.txt"

try:
    s3 = boto3.client("s3")
    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=FILE_NAME
    )

    content = response["Body"].read().decode("utf-8")
    print("CloudSentinel AWS S3 connection successful!")
    print("File content:", content)

except ClientError as error:
    print("AWS error:", error.response["Error"]["Code"])
