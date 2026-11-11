#!/usr/bin/env bash
# Live smoke runs (contract §8.1): IMAGE started with start-dev, the realm
# built from core's flow tree (src/test/resources/smoke-realm.json)
# imported, /hub-data mounted from a temp dir, the authentication debug log
# on; then signin.py drives it. PYTHON = an interpreter with playwright
# installed (the x509 phase needs only the standard library).
#
#   run.sh          the passkey / password sign-in (Playwright, a CDP virtual authenticator)
#   run.sh x509     "x509 kinds": a test internal CA (root, a YubiKey CA, a
#                   browser CA, made with openssl here), their CRLs served as
#                   http://vault:8200/v1/pki_{int,file}/crl[/delta] from the
#                   host, Keycloak with core's x509 options (the traefik lookup,
#                   the proxy settings, the truststore directory, the CRL cache
#                   time); each leaf posted in Traefik's header.
#
# The admin password is random and only in the environment.
set -euo pipefail
IMAGE=${IMAGE:?image}
PYTHON=${PYTHON:-python3}
MODE=${1:-signin}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
umask 022
HUB_DATA=$(mktemp -d)
chmod 755 "$HUB_DATA"
export HUB_DATA KC_CONTAINER=kc-signin-smoke KC_URL=http://localhost:18080
KC_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 24)
export KC_BOOTSTRAP_ADMIN_PASSWORD KC_BOOTSTRAP_ADMIN_USERNAME=smoke
PKI=""
cleanup() { [ -n "${SMOKE_KEEP:-}" ] && return; docker rm -f "$KC_CONTAINER" >/dev/null 2>&1 || true; rm -rf "$HUB_DATA" ${PKI:+"$PKI"}; }
trap cleanup EXIT

# A CA in dir $1: key, self-signed (no $3) or signed by CA dir $3, subject $2.
make_ca() {
  local dir=$1 subject=$2 parent=${3:-}
  mkdir -p "$dir"
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/key.pem"
  printf 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$dir/ext.cnf"
  if [ -z "$parent" ]; then
    openssl req -new -x509 -key "$dir/key.pem" -subj "$subject" -days 2 -sha256 \
      -addext 'basicConstraints=critical,CA:true' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$dir/cert.pem"
  else
    openssl req -new -key "$dir/key.pem" -subj "$subject" -out "$dir/req.pem"
    openssl x509 -req -in "$dir/req.pem" -CA "$parent/cert.pem" -CAkey "$parent/key.pem" -CAcreateserial \
      -days 2 -sha256 -extfile "$dir/ext.cnf" -out "$dir/cert.pem" 2>/dev/null
  fi
  : > "$dir/index.txt"
  echo 01 > "$dir/crlnumber"
  printf '[ca]\ndefault_ca=d\n[d]\ndatabase=%s/index.txt\ncrlnumber=%s/crlnumber\ndefault_md=sha256\ndefault_crl_days=1\n' "$dir" "$dir" > "$dir/ca.cnf"
}

# A client leaf for username $2 from CA dir $1, into $3 (PEM).
make_leaf() {
  local ca=$1 cn=$2 out=$3
  openssl ecparam -name prime256v1 -genkey -noout -out "$out.key"
  openssl req -new -key "$out.key" -subj "/CN=$cn" -out "$out.req"
  printf 'basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nauthorityKeyIdentifier=keyid\n' > "$out.ext"
  openssl x509 -req -in "$out.req" -CA "$ca/cert.pem" -CAkey "$ca/key.pem" -CAcreateserial \
    -days 1 -sha256 -extfile "$out.ext" -out "$out" 2>/dev/null
  rm -f "$out.key" "$out.req" "$out.ext"
}

extra=()
if [ "$MODE" = x509 ]; then
  PKI=$(mktemp -d)
  chmod 755 "$PKI"
  make_ca "$PKI/root" "/CN=smoke.example Root CA"
  make_ca "$PKI/int" "/CN=smoke.example YubiKey Certificate CA" "$PKI/root"
  make_ca "$PKI/file" "/CN=smoke.example Browser Certificate CA" "$PKI/root"
  for ca in int file; do
    openssl ca -gencrl -config "$PKI/$ca/ca.cnf" -keyfile "$PKI/$ca/key.pem" -cert "$PKI/$ca/cert.pem" -out "$PKI/$ca/crl.pem" 2>/dev/null
    openssl crl -in "$PKI/$ca/crl.pem" -outform DER -out "$PKI/$ca/crl.der"
  done
  mkdir -p "$PKI/truststore" "$PKI/leaves"
  cat "$PKI/root/cert.pem" "$PKI/int/cert.pem" "$PKI/file/cert.pem" > "$PKI/truststore/portcullis-ca-chain.pem"
  cp "$PKI/int/cert.pem" "$PKI/truststore/portcullis-yubikey-ca.pem"
  cp "$PKI/file/cert.pem" "$PKI/truststore/portcullis-browser-ca.pem"
  chmod 644 "$PKI"/truststore/*
  make_leaf "$PKI/int" alice "$PKI/leaves/yubikey.pem"
  make_leaf "$PKI/file" alice "$PKI/leaves/browser.pem"
  # Only the CA certificates and CRLs leave this script; the CA keys are deleted now.
  rm -f "$PKI"/*/key.pem
  export SMOKE_PKI=$PKI
  # Core's keycloak command (docker-compose.yml): the traefik lookup, proxy
  # headers trusted only from the proxy's address (here: the bridge's
  # gateway, where the published port's connections come from), the
  # truststore directory and the CRL cache time.
  trusted=${SMOKE_PROXY_TRUSTED:-$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')}
  extra=(--add-host=vault:host-gateway
    -v "$PKI/truststore:/opt/keycloak/conf/truststores/portcullis:ro")
  kc_args=(--proxy-headers=xforwarded "--proxy-trusted-addresses=$trusted"
    --spi-x509cert-lookup--provider=traefik
    --truststore-paths=/opt/keycloak/conf/truststores/portcullis
    --spi-crl-storage--infinispan--cache-time=60)
  echo "x509 kinds: proxy headers trusted from $trusted"
else
  kc_args=()
fi

docker rm -f "$KC_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$KC_CONTAINER" -p 127.0.0.1:18080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME -e KC_BOOTSTRAP_ADMIN_PASSWORD \
  -v "$root/src/test/resources/smoke-realm.json:/opt/keycloak/data/import/portcullis.json:ro" \
  -v "$HUB_DATA:/hub-data:ro" \
  ${extra[@]+"${extra[@]}"} \
  "$IMAGE" start-dev --import-realm --log-level=INFO,org.keycloak.authentication:debug ${kc_args[@]+"${kc_args[@]}"} >/dev/null
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null "$KC_URL/realms/portcullis/.well-known/openid-configuration" 2>/dev/null; then break; fi
  sleep 2
done
if ! curl -fsS -o /dev/null "$KC_URL/realms/portcullis/.well-known/openid-configuration"; then
  docker logs "$KC_CONTAINER" 2>&1 | tail -80
  echo "::error::Keycloak didn't import the smoke realm"
  exit 1
fi
rc=0
if [ "$MODE" = x509 ]; then
  "$PYTHON" "$here/signin.py" x509 || rc=$?
else
  "$PYTHON" "$here/signin.py" || rc=$?
fi
if [ "$rc" != 0 ] && [ -z "${SMOKE_KEEP:-}" ]; then
  docker logs "$KC_CONTAINER" 2>&1 | grep -E "portcullis|ERROR|WARN|Selections when trying|invoke authenticator|x509|X509|certificate" | tail -150
fi
exit "$rc"
