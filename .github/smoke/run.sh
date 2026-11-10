#!/usr/bin/env bash
# Live sign-in smoke run (contract §8.1): IMAGE started with start-dev, the
# realm built from core's flow tree (src/test/resources/smoke-realm.json)
# imported, /hub-data mounted from a temp dir, the authentication debug log
# on; then signin.py drives it with Playwright Chromium and a CDP virtual
# authenticator. PYTHON = an interpreter with playwright installed.
# The admin password is random and only in the environment.
set -euo pipefail
IMAGE=${IMAGE:?image}
PYTHON=${PYTHON:-python3}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
umask 022
HUB_DATA=$(mktemp -d)
chmod 755 "$HUB_DATA"
export HUB_DATA KC_CONTAINER=kc-signin-smoke KC_URL=http://localhost:18080
KC_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 24)
export KC_BOOTSTRAP_ADMIN_PASSWORD KC_BOOTSTRAP_ADMIN_USERNAME=smoke
docker rm -f "$KC_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$KC_CONTAINER" -p 127.0.0.1:18080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME -e KC_BOOTSTRAP_ADMIN_PASSWORD \
  -v "$root/src/test/resources/smoke-realm.json:/opt/keycloak/data/import/portcullis.json:ro" \
  -v "$HUB_DATA:/hub-data:ro" \
  "$IMAGE" start-dev --import-realm --log-level=INFO,org.keycloak.authentication:debug >/dev/null
cleanup() { docker rm -f "$KC_CONTAINER" >/dev/null 2>&1 || true; rm -rf "$HUB_DATA"; }
trap cleanup EXIT
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
"$PYTHON" "$here/signin.py" || rc=$?
if [ "$rc" != 0 ]; then
  docker logs "$KC_CONTAINER" 2>&1 | grep -E "portcullis|ERROR|WARN|Selections when trying|invoke authenticator" | tail -120
fi
exit "$rc"
