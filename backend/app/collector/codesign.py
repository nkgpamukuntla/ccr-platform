"""The collector's code-signing certificate: made once, then reused by every build.

Run by the CodeBuild project inside the freshly built image (scripts/sign-collector.sh):

    python -m app.collector.codesign --key <kms key id> --bucket <source bucket>

prints the PEM certificate. The first run builds a self-signed certificate over the KMS
RSA-3072 code-signing key (signature by kms:Sign; the private key never leaves KMS, R3) and
keeps it at s3://<bucket>/codesign/<key id>.pem, so the thumbprint counties trust stays the
same across builds. Lab only: production uses a commercial certificate issued for this key.
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

from app.microsoft.certificate import build_certificate, to_pem
from app.microsoft.signer import KmsSigner

COMMON_NAME = "CCR Evidence Collector (lab, self-signed)"
ORGANIZATION = "D-Biz Solutions"
DAYS = 730


def ensure(key_id: str, bucket: str, region: str) -> str:
    s3 = boto3.client("s3", region_name=region)
    obj = f"codesign/{key_id}.pem"
    try:
        body: bytes = s3.get_object(Bucket=bucket, Key=obj)["Body"].read()
        return body.decode()
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") not in ("NoSuchKey", "404", "AccessDenied"):
            raise
    der = build_certificate(KmsSigner(key_id, region), COMMON_NAME, DAYS, organization=ORGANIZATION, code_signing=True)
    pem = to_pem(der)
    s3.put_object(Bucket=bucket, Key=obj, Body=pem.encode(), ContentType="application/x-pem-file")
    print(f"created code-signing certificate s3://{bucket}/{obj}", file=sys.stderr)
    return pem


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--key", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--region", default="us-east-1")
    a = p.parse_args()
    sys.stdout.write(ensure(a.key, a.bucket, a.region))


if __name__ == "__main__":
    main()
