"""Issue the app registration's certificate, signed inside KMS.

    python -m app.tools.make_cert --cn "CCR Evidence Collector dev" --days 365

Must run as the worker role (only it may kms:Sign), so it is started as a one-off ECS task
with the worker task definition and this command. It prints the public certificate (PEM, safe
to log) and its thumbprints; nothing secret exists to print. Use --days 1 to issue a
short-lived certificate and observe what Microsoft returns when one expires.
"""

import argparse
import json
import sys

from app.config import get_settings
from app.microsoft.certificate import build_certificate, thumbprints, to_pem
from app.microsoft.signer import KmsSigner


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cn", required=True)
    p.add_argument("--days", type=int, default=365)
    a = p.parse_args()
    s = get_settings()
    der = build_certificate(KmsSigner(s.ec_signing_key_id, s.aws_region), a.cn, a.days)
    x5t, x5t_s256 = thumbprints(der)
    print(to_pem(der))
    print(json.dumps({"x5t": x5t, "x5t#S256": x5t_s256, "days": a.days, "cn": a.cn}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
