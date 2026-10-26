#!/usr/bin/env bash
# Signs the offline collector before the final image build. CodeBuild only (buildspec.yml):
# the signing key is a KMS RSA-3072 key only the build role may use (R3, R4).
#  1. Builds the image once and runs app.collector.codesign in it to fetch (or, the first time,
#     create) the self-signed code-signing certificate kept in the source bucket.
#  2. Authenticode-signs collector/Collect-CCREvidence.ps1 with jsign (open source, Apache-2.0)
#     through KMS, with an RFC 3161 timestamp so the signature outlives the certificate.
#  3. Keeps a copy of the signed script under codesign/<tag>/ for checking on Windows.
set -euo pipefail
: "${CODESIGN_KEY_ID:?}" "${SOURCE_BUCKET:?}" "${AWS_REGION:?}" "${IMAGE_TAG:?}"

JSIGN_VERSION=7.5
JSIGN_SHA256=602a51c3545a6dc4fb99bd2ea7152b26d1345916d0c93ddfbd5936cb735af91c
curl -fsSL -o /tmp/jsign.jar "https://repo1.maven.org/maven2/net/jsign/jsign/${JSIGN_VERSION}/jsign-${JSIGN_VERSION}.jar"
echo "${JSIGN_SHA256}  /tmp/jsign.jar" | sha256sum -c -

# The build role's short-lived credentials, for the container in step 1 and for jsign.
creds=$(curl -fsS "http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}")
field() { printf '%s' "$creds" | python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"; }
AWS_ACCESS_KEY_ID=$(field AccessKeyId)
AWS_SECRET_ACCESS_KEY=$(field SecretAccessKey)
AWS_SESSION_TOKEN=$(field Token)
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

docker build --platform linux/arm64 -t ccr-presign .
docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN ccr-presign \
  python -m app.collector.codesign --key "$CODESIGN_KEY_ID" --bucket "$SOURCE_BUCKET" --region "$AWS_REGION" \
  > collector/ccr-collector-signing.cer
grep -q "BEGIN CERTIFICATE" collector/ccr-collector-signing.cer

java -jar /tmp/jsign.jar --storetype AWS --keystore "$AWS_REGION" \
  --storepass "${AWS_ACCESS_KEY_ID}|${AWS_SECRET_ACCESS_KEY}|${AWS_SESSION_TOKEN}" \
  --alias "$CODESIGN_KEY_ID" --certfile collector/ccr-collector-signing.cer --alg SHA-256 \
  --tsaurl http://timestamp.digicert.com --tsmode RFC3161 --tsretries 3 --tsretrywait 10 \
  --replace collector/Collect-CCREvidence.ps1
grep -q "SIG # Begin signature block" collector/Collect-CCREvidence.ps1

aws s3 cp --only-show-errors collector/Collect-CCREvidence.ps1 "s3://${SOURCE_BUCKET}/codesign/${IMAGE_TAG}/Collect-CCREvidence.ps1"
aws s3 cp --only-show-errors collector/ccr-collector-signing.cer "s3://${SOURCE_BUCKET}/codesign/${IMAGE_TAG}/ccr-collector-signing.cer"
echo "collector signed for ${IMAGE_TAG}"
