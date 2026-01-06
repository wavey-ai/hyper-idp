# Testing SSO

## Quick Start (Local Testing)

### 1. Generate Self-Signed Certs

```bash
# Generate certs for local.wavey.io
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=local.wavey.io" \
  -addext "subjectAltName=DNS:local.wavey.io,DNS:localhost"

# Convert to base64
CERT_PEM_BASE64=$(base64 -i cert.pem)
KEY_PEM_BASE64=$(base64 -i key.pem)
```

### 2. Add to /etc/hosts

```bash
echo "127.0.0.1 local.wavey.io" | sudo tee -a /etc/hosts
```

### 3. Set up Auth0 (or other OAuth provider)

1. Create Auth0 account at https://auth0.com
2. Create a new "Regular Web Application"
3. Configure:
   - Allowed Callback URLs: `https://local.wavey.io:8443/oauth2/callback`
   - Allowed Logout URLs: `https://local.wavey.io:8443`
4. Note down:
   - Domain (e.g., `your-tenant.auth0.com`)
   - Client ID
   - Client Secret
5. Get signing certificate:
   - Go to Applications > Your App > Settings > Show Advanced Settings > Certificates
   - Download the signing certificate and base64 encode it

### 4. Create .env file

```bash
cat > .env << 'EOF'
CERT_PEM_BASE64=<your base64 cert>
KEY_PEM_BASE64=<your base64 key>
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_SIGNING_CERT_BASE64=<base64 encoded signing cert>
REDIRECT_URI=https://local.wavey.io:8443/oauth2/callback
SSO_PORT=8443
EOF
```

### 5. Run SSO Server

```bash
cd /Users/jamie/wavey.ai/hyper-idp
source .env
cargo run --example test_sso
```

### 6. Test in Browser

1. Open: `https://local.wavey.io:8443/login`
2. Accept the self-signed cert warning
3. Log in with Auth0/Google
4. After redirect, check: `https://local.wavey.io:8443/profile`
5. Check active users: `https://local.wavey.io:8443/users`

### 7. Test Auth Polling (separate terminal)

```bash
cd /Users/jamie/wavey.ai/hyper-idp
IDP_URL=https://local.wavey.io:8443 cargo run --example test_auth_polling
```

## Testing with Gatekeeper

```rust
use auth::Auth;
use gatekeeper::Gatekeeper;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Start auth polling
    let auth = Arc::new(Auth::new("https://local.wavey.io:8443".into(), 30));
    auth.clone().start_polling();

    // Create gatekeeper with auth
    let pem_key = std::env::var("GATEKEEPER_KEY").unwrap();
    let gatekeeper = Gatekeeper::with_auth(&pem_key, auth).unwrap();

    // Now gatekeeper.streamkey() will check the allow list
    // gatekeeper.is_user_allowed(user_id) for direct checks
}
```

## Endpoints Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET | Redirects to OAuth provider |
| `/oauth2/callback` | GET | OAuth callback, creates session |
| `/profile` | GET | Returns user info (requires session cookie) |
| `/validate` | GET/POST | Validates session `?session_id=xxx` |
| `/users` | GET | Lists active user IDs (for allow list) |
| `/logout` | GET/POST | Invalidates session |
| `/refresh` | POST | Refreshes access token |

## Troubleshooting

### "Certificate not trusted"
- Add cert to system keychain, or
- Use `curl -k` / browser "proceed anyway"

### "OAuth callback failed"
- Check redirect URI matches exactly in Auth0 config
- Check client_id/client_secret are correct

### "No users in allow list"
- Log in first via `/login`
- Check `/users` endpoint after login
