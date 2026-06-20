#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${REPO_ROOT}/envoy/certs"

CA_VALIDITY_DAYS=3650
LEAF_VALIDITY_DAYS=825

FORCE=0
if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
fi

EXPECTED_FILES=(
  ca.pem ca-key.pem
  server.pem server-key.pem
  client.pem client-key.pem
  protected-client.pem protected-client-key.pem
)

all_present() {
  for f in "${EXPECTED_FILES[@]}"; do
    [[ -f "${CERT_DIR}/${f}" ]] || return 1
  done
  return 0
}

if [[ "${FORCE}" -eq 0 ]] && all_present; then
  echo "✓ Certificates already present in ${CERT_DIR} — nothing to do."
  echo "  Use './scripts/generate-certs.sh --force' to regenerate."
  exit 0
fi

if [[ "${FORCE}" -eq 1 ]]; then
  echo "--force given: removing existing certificates in ${CERT_DIR}"
  rm -rf "${CERT_DIR}"
fi

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

echo "==> Generating ZTAC mTLS PKI in ${CERT_DIR}"

echo "  [1/4] Certificate Authority (CA)"
openssl genrsa -out ca-key.pem 4096 2>/dev/null
openssl req -x509 -new -nodes \
  -key ca-key.pem \
  -sha256 \
  -days "${CA_VALIDITY_DAYS}" \
  -out ca.pem \
  -subj "/C=GB/O=ZTAC/OU=Security/CN=ZTAC Root CA"

issue_cert() {
  local name="$1" cn="$2" san="$3" eku="$4"

  openssl genrsa -out "${name}-key.pem" 2048 2>/dev/null

  cat > "${name}-ext.cnf" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = ${eku}
subjectAltName = ${san}
EOF

  openssl req -new \
    -key "${name}-key.pem" \
    -out "${name}.csr" \
    -subj "/C=GB/O=ZTAC/OU=Security/CN=${cn}"

  openssl x509 -req \
    -in "${name}.csr" \
    -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "${name}.pem" \
    -days "${LEAF_VALIDITY_DAYS}" \
    -sha256 \
    -extfile "${name}-ext.cnf" 2>/dev/null

  rm -f "${name}.csr" "${name}-ext.cnf"
}

echo "  [2/4] Envoy server certificate (CN=envoy)"
issue_cert "server" "envoy" "DNS:envoy,DNS:localhost,IP:127.0.0.1" "serverAuth"

echo "  [3/4] API-gateway client certificate (CN=api-gateway)"
issue_cert "client" "api-gateway" "DNS:api-gateway" "clientAuth"

echo "  [4/4] Protected-service client certificate (CN=protected-service)"
issue_cert "protected-client" "protected-service" "DNS:protected-service" "clientAuth"

chmod 600 ./*-key.pem
chmod 644 ./*.pem 2>/dev/null || true
rm -f ca.srl

echo ""
echo "✓ PKI generated. Files in ${CERT_DIR}:"
for f in "${EXPECTED_FILES[@]}"; do
  printf "    %-26s %s\n" "${f}" "$( [[ -f ${f} ]] && echo OK || echo MISSING )"
done

echo ""
echo "Verifying the trust chain:"
openssl verify -CAfile ca.pem server.pem
openssl verify -CAfile ca.pem client.pem
openssl verify -CAfile ca.pem protected-client.pem
