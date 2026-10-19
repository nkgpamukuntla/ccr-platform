"""Runtime settings. Everything comes from the environment (ECS task definition or a local .env)."""

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "local"  # EC_ENVIRONMENT in AWS
    aws_region: str = "us-east-1"

    # Database. In AWS the password is an RDS IAM auth token minted per connection (no stored secret).
    pghost: str = "127.0.0.1"
    pgport: int = 5432
    pgdatabase: str = "evidence"
    pguser: str = "ec_portal"
    pgpassword: str | None = None
    pgsslmode: str = "prefer"
    pgsslrootcert: str | None = None
    db_iam_auth: bool = False

    # Sign-in. "cognito" in AWS; "dev" only on a workstation (a header picks the user).
    auth_mode: Literal["cognito", "dev"] = "cognito"
    cognito_domain: str = ""  # e.g. https://ccr-dev-123.auth.us-east-1.amazoncognito.com
    cognito_client_id: str = ""
    cognito_user_pool_id: str = ""
    public_url: str = "http://localhost:8000"  # the CloudFront URL in AWS

    # Source credentials written by onboarding (R5: never through Terraform).
    source_secret_prefix: str = "ec/local/source/"  # noqa: S105 (a name prefix, not a secret)
    secrets_kms_key_id: str = ""

    static_dir: str = "static"

    # Microsoft source (Phase 2). None of these is a secret: the private key never leaves KMS (R3).
    ms_client_id: str = ""  # the multi-tenant app registration's Application (client) ID
    ms_cert_thumbprint_sha1: str = ""  # x5t of the uploaded certificate (base64url)
    ms_cert_thumbprint_sha256: str = ""  # x5t#S256
    ec_signing_key_id: str = ""  # KMS RSA-2048 signing key ARN
    ec_fingerprint_key_id: str = ""  # KMS HMAC key ARN
    ec_raw_bucket: str = ""
    ec_raw_keys: dict[str, str] = {}  # collector tenant id (office id) -> raw key ARN, JSON in env
    ec_heartbeat_namespace: str = "EvidenceCollector"
    ec_heartbeat_metric: str = "CollectionHeartbeat"

    @model_validator(mode="after")
    def _no_dev_auth_outside_local(self) -> "Settings":
        if self.auth_mode == "dev" and self.environment != "local":
            raise ValueError("auth_mode=dev is only allowed when environment=local")
        return self

    @property
    def cognito_issuer(self) -> str:
        return f"https://cognito-idp.{self.aws_region}.amazonaws.com/{self.cognito_user_pool_id}"

    @property
    def secure_cookies(self) -> bool:
        return self.public_url.startswith("https://")


@lru_cache
def get_settings() -> Settings:
    return Settings()
