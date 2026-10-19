"""Source credentials (EDR API keys, tokens) go straight to Secrets Manager under
ec/<env>/source/<office>/<source>, encrypted with the secrets key. The portal can create and
overwrite them but has no permission to read them back; only the worker can (R5)."""

from uuid import UUID

import boto3

from app.config import get_settings


def secret_name(office_id: UUID, source: str) -> str:
    return f"{get_settings().source_secret_prefix}{office_id}/{source}"


def put_source_secret(office_id: UUID, source: str, value: str) -> str:
    s = get_settings()
    sm = boto3.client("secretsmanager", region_name=s.aws_region)
    name = secret_name(office_id, source)
    try:
        arn: str = sm.put_secret_value(SecretId=name, SecretString=value)["ARN"]
    except sm.exceptions.ResourceNotFoundException:
        arn = sm.create_secret(
            Name=name,
            SecretString=value,
            KmsKeyId=s.secrets_kms_key_id,
            Tags=[{"Key": "office_id", "Value": str(office_id)}, {"Key": "source", "Value": source}],
        )["ARN"]
    return arn
