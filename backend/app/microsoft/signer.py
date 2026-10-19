"""RS256 signing with the non-exportable KMS RSA-2048 key (R3).

Only the worker role may call kms:Sign on it, and only with RSASSA_PKCS1_V1_5_SHA_256
(the key policy pins the algorithm), so everything that signs runs as the worker.
"""

from typing import Protocol

import boto3


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes: ...

    def public_key_der(self) -> bytes: ...


class KmsSigner:
    def __init__(self, key_id: str, region: str) -> None:
        self._key_id = key_id
        self._kms = boto3.client("kms", region_name=region)

    def sign(self, message: bytes) -> bytes:
        # MessageType RAW: KMS hashes with SHA-256 itself; 4096-byte limit is far above a JWT or TBS certificate.
        r = self._kms.sign(KeyId=self._key_id, Message=message, MessageType="RAW", SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")
        sig: bytes = r["Signature"]
        return sig

    def public_key_der(self) -> bytes:
        der: bytes = self._kms.get_public_key(KeyId=self._key_id)["PublicKey"]  # SubjectPublicKeyInfo
        return der
