#!/usr/bin/env bash
set -euo pipefail

# Subject DN for all certs
SUBJ="/C=US/ST=State/L=City/O=Organization/CN=localhost"
DAYS=365

########################################
# 1) ECDSA: prime256v1, secp384r1, secp521r1
########################################
declare -A ECDSA_CURVES=(
  [prime256v1]=sha256
  [secp384r1]=sha384
  [secp521r1]=sha512
)

for curve in "${!ECDSA_CURVES[@]}"; do
  digest=${ECDSA_CURVES[$curve]}
  key="ecdsa_${curve}.key"
  crt="ecdsa_${curve}.crt"

  echo "Generating ECDSA/$curve ($digest)…"
  openssl ecparam -name "$curve" -genkey -noout -out "$key"
  openssl req -new -x509 -"$digest" \
    -key "$key" \
    -out "$crt" \
    -days "$DAYS" \
    -subj "$SUBJ"
done

########################################
# 2) RSA-PSS with RSA key + PSS padding (rsaPss_rsae_sha{256,384,512})
########################################
for digest in sha256 sha384 sha512; do
  # saltlen = digest length in bytes
  case "$digest" in
    sha256) saltlen=32 ;;
    sha384) saltlen=48 ;;
    sha512) saltlen=64 ;;
  esac

  key="rsa_pss_rsae_${digest}.key"
  crt="rsa_pss_rsae_${digest}.crt"
  csr="rsa_pss_rsae_${digest}.csr"

  echo "Generating RSA-PSS-RSAE ($digest, saltlen=${saltlen})…"
  # 1) regular RSA key
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key"

  # 2) CSR (plain PKCS#1 SHA-based)
  openssl req -new -key "$key" -out "$csr" -subj "$SUBJ"

  # 3) self-sign CSR using PSS padding
  openssl x509 -req -"$digest" \
    -in "$csr" \
    -signkey "$key" \
    -out "$crt" \
    -days "$DAYS" \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:"$saltlen"

  rm -f "$csr"
done

########################################
# 3) RSA-PSS key & RSASSA-PSS algorithm OID (rsaPss_pss_sha{256,384,512})
########################################
for digest in sha256 sha384 sha512; do
  key="rsa_pss_pss_${digest}.key"
  crt="rsa_pss_pss_${digest}.crt"

  echo "Generating RSA-PSS-PSS key & cert ($digest)…"
  # genpkey -algorithm RSA-PSS emits a PSS-type key;
  # req -x509 will sign with RSASSA-PSS OID
  openssl genpkey \
    -algorithm RSA-PSS \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "$key"

  openssl req -new -x509 -"$digest" \
    -key "$key" \
    -out "$crt" \
    -days "$DAYS" \
    -subj "$SUBJ"
done

########################################
# 4) Ed25519 & Ed448
########################################
for alg in ed25519 ed448; do
  key="${alg}.key"
  crt="${alg}.crt"

  echo "Generating $alg key & cert…"
  openssl genpkey -algorithm "$alg" -out "$key"
  openssl req -new -x509 \
    -key "$key" \
    -out "$crt" \
    -days "$DAYS" \
    -subj "$SUBJ"
done

echo "All done. You now have:"
ls -1 *.key *.crt
