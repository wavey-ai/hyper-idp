#!/bin/bash
set -e

# Load existing certs from tls-certs
source /Users/jamie/wavey.ai/tls-certs/.env

# Load OIDC config from io/.env
source /Users/jamie/wavey.ai/io/.env

# Map OIDC variables to AUTH0 variables
export AUTH0_DOMAIN="$OIDC_AUDIENCE"
export AUTH0_CLIENT_ID="$OIDC_CLIENT_ID"
export AUTH0_CLIENT_SECRET="$OIDC_CLIENT_SECRET"

# Use the signing cert from tls-certs
export AUTH0_SIGNING_CERT_BASE64="$IDP_PRIVKEY_PEM"

# Cert config
export CERT_PEM_BASE64="$FULLCHAIN_PEM"
export KEY_PEM_BASE64="$PRIVKEY_PEM"

# SSO config
export REDIRECT_URI="https://local.wavey.io:8443/oauth2/callback"
export SSO_PORT=8443

echo "=== SSO Test Setup ==="
echo "Domain: $AUTH0_DOMAIN"
echo "Client ID: $AUTH0_CLIENT_ID"
echo "Redirect URI: $REDIRECT_URI"
echo ""
echo "Make sure local.wavey.io points to 127.0.0.1 in /etc/hosts"
echo ""
echo "URLs to test:"
echo "  Login:    https://local.wavey.io:8443/login"
echo "  Profile:  https://local.wavey.io:8443/profile"
echo "  Users:    https://local.wavey.io:8443/users"
echo "  Validate: https://local.wavey.io:8443/validate"
echo ""

# Check required variables
if [ -z "$AUTH0_CLIENT_SECRET" ]; then
    echo "ERROR: AUTH0_CLIENT_SECRET not set (check OIDC_CLIENT_SECRET in io/.env)"
    exit 1
fi

if [ -z "$AUTH0_SIGNING_CERT_BASE64" ]; then
    echo "ERROR: AUTH0_SIGNING_CERT_BASE64 not set (check IDP_PRIVKEY_PEM in tls-certs/.env)"
    exit 1
fi

cd /Users/jamie/wavey.ai/hyper-idp
cargo run --example test_sso
