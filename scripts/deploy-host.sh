#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:-/opt/hyper-idp}"
ENV_FILE="${2:-/tmp/hyper-idp.env}"
TLS_DOMAIN="${TLS_DOMAIN:-wavey.io}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "missing env file: ${ENV_FILE}" >&2
  exit 1
fi

if [[ -f "${HOME}/.cargo/env" ]]; then
  # rustup installs cargo outside the default root PATH
  # on the standalone Arch host.
  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"
fi

cd "${APP_DIR}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" cargo build --release --bin hyper-idp
install -m 755 target/release/hyper-idp /usr/local/bin/hyper-idp

cert_pem_base64="$(base64 -w 0 "/etc/letsencrypt/live/${TLS_DOMAIN}/fullchain.pem")"
key_pem_base64="$(base64 -w 0 "/etc/letsencrypt/live/${TLS_DOMAIN}/privkey.pem")"

tmp_env="$(mktemp)"
cp "${ENV_FILE}" "${tmp_env}"
printf 'CERT_PEM_BASE64=%s\n' "${cert_pem_base64}" >> "${tmp_env}"
printf 'KEY_PEM_BASE64=%s\n' "${key_pem_base64}" >> "${tmp_env}"

install -d -m 700 /etc/hyper-idp
install -m 600 "${tmp_env}" /etc/hyper-idp/env
rm -f "${tmp_env}" "${ENV_FILE}"

systemctl daemon-reload
systemctl restart hyper-idp
systemctl is-active --quiet hyper-idp
