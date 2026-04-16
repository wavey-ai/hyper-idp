use crate::session::Session;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use http::StatusCode;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openssl::bn::{BigNum, BigNumContext};
use openssl::sha::sha256;
use openssl::x509::X509;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tls_helpers::from_base64_raw;
use tokio::sync::RwLock;
use url::Url;
use xxhash_rust::xxh3::xxh3_64;

const AUTH_CODE_TTL_SECS: u64 = 300;
const CLEANUP_INTERVAL_SECS: u64 = 300;

#[derive(Clone)]
pub struct OidcProviderConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub cookie_domain: String,
    pub token_ttl_secs: u64,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone)]
struct AuthorizationCodeGrant {
    client_id: String,
    redirect_uri: String,
    subject: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    session_expires_at: Instant,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct RefreshGrant {
    client_id: String,
    subject: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
    session_expires_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: usize,
    pub token_type: String,
}

#[derive(Debug)]
pub struct TokenError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: String,
}

impl TokenError {
    pub fn invalid_client(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description: message.into(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description: message.into(),
        }
    }

    pub fn invalid_grant(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_grant",
            description: message.into(),
        }
    }

    pub fn unsupported_grant_type(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "unsupported_grant_type",
            description: message.into(),
        }
    }

    pub fn as_json(&self) -> Value {
        json!({
            "error": self.error,
            "error_description": self.description,
        })
    }
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.description)
    }
}

impl std::error::Error for TokenError {}

#[derive(Debug, Serialize)]
struct LocalTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    iat: usize,
    nbf: usize,
    jti: String,
    email: String,
    email_verified: bool,
    preferred_username: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

#[derive(Clone)]
pub struct OidcProvider {
    config: OidcProviderConfig,
    signing_key_pem: Arc<Vec<u8>>,
    kid: Arc<String>,
    jwks_document: Arc<String>,
    pending_authorizations: Arc<RwLock<HashMap<String, AuthorizationRequest>>>,
    auth_codes: Arc<RwLock<HashMap<String, AuthorizationCodeGrant>>>,
    refresh_grants: Arc<RwLock<HashMap<String, RefreshGrant>>>,
}

impl OidcProvider {
    pub fn new(
        config: OidcProviderConfig,
        cert_pem_base64: &str,
        key_pem_base64: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert_pem = from_base64_raw(cert_pem_base64)?;
        let key_pem = from_base64_raw(key_pem_base64)?;
        let (kid, jwks_document) = build_jwks_document(&cert_pem)?;

        Ok(Self {
            config,
            signing_key_pem: Arc::new(key_pem),
            kid: Arc::new(kid),
            jwks_document: Arc::new(jwks_document),
            pending_authorizations: Arc::new(RwLock::new(HashMap::new())),
            auth_codes: Arc::new(RwLock::new(HashMap::new())),
            refresh_grants: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn config(&self) -> &OidcProviderConfig {
        &self.config
    }

    pub fn discovery_document(&self) -> Value {
        json!({
            "issuer": self.config.issuer_url,
            "authorization_endpoint": format!("{}/authorize", self.config.issuer_url),
            "token_endpoint": format!("{}/oauth/token", self.config.issuer_url),
            "jwks_uri": format!("{}/.well-known/jwks.json", self.config.issuer_url),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": ["openid", "profile", "email"],
            "claims_supported": [
                "aud",
                "email",
                "email_verified",
                "exp",
                "groups",
                "iat",
                "iss",
                "name",
                "nbf",
                "nonce",
                "preferred_username",
                "sub"
            ],
            "code_challenge_methods_supported": ["plain", "S256"],
        })
    }

    pub fn jwks_document(&self) -> &str {
        self.jwks_document.as_str()
    }

    pub fn validate_authorization_request(
        &self,
        client_id: &str,
        redirect_uri: &str,
        response_type: &str,
        scope: &str,
    ) -> Result<(), TokenError> {
        if client_id != self.config.client_id {
            return Err(TokenError::invalid_client("Unknown OIDC client"));
        }

        if response_type != "code" {
            return Err(TokenError::invalid_request(
                "Only authorization code flow is supported",
            ));
        }

        if !scope
            .split(|c: char| c.is_whitespace() || c == ',')
            .any(|part| part == "openid")
        {
            return Err(TokenError::invalid_request(
                "openid scope is required for OIDC authorization requests",
            ));
        }

        self.validate_redirect_uri(redirect_uri)
    }

    pub fn validate_redirect_uri(&self, redirect_uri: &str) -> Result<(), TokenError> {
        let parsed = Url::parse(redirect_uri)
            .map_err(|_| TokenError::invalid_request("Invalid redirect_uri"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| TokenError::invalid_request("redirect_uri must include a host"))?;
        let allowed_host = self.config.cookie_domain.trim_start_matches('.');
        let same_domain = host == allowed_host
            || host.ends_with(&format!(".{allowed_host}"))
            || host == "localhost";
        let secure_scheme = parsed.scheme() == "https" || host == "localhost";
        let callback_path = parsed.path() == "/oidc-callback";

        if same_domain && secure_scheme && callback_path {
            Ok(())
        } else {
            Err(TokenError::invalid_request(
                "redirect_uri must be an /oidc-callback URL under the Wavey domain",
            ))
        }
    }

    pub fn validate_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), TokenError> {
        if client_id != self.config.client_id {
            return Err(TokenError::invalid_client("Unknown OIDC client"));
        }

        if client_secret != self.config.client_secret {
            return Err(TokenError::invalid_client("Invalid OIDC client secret"));
        }

        Ok(())
    }

    pub async fn store_pending_authorization(&self, request: AuthorizationRequest) -> String {
        let state = random_token();
        let mut pending = self.pending_authorizations.write().await;
        pending.insert(state.clone(), request);
        state
    }

    pub async fn take_pending_authorization(
        &self,
        upstream_state: &str,
    ) -> Option<AuthorizationRequest> {
        let mut pending = self.pending_authorizations.write().await;
        pending.remove(upstream_state)
    }

    pub async fn create_authorization_code(
        &self,
        session: &Session,
        request: AuthorizationRequest,
    ) -> String {
        let code = random_token();
        let grant = AuthorizationCodeGrant {
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            subject: session.identity.subject.clone(),
            email: session.identity.email.clone(),
            email_verified: session.identity.email_verified,
            name: session.identity.name.clone(),
            nonce: request.nonce,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            session_expires_at: session.expires_at,
            expires_at: Instant::now() + Duration::from_secs(AUTH_CODE_TTL_SECS),
        };

        let mut auth_codes = self.auth_codes.write().await;
        auth_codes.insert(code.clone(), grant);
        code
    }

    pub async fn exchange_authorization_code(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<OidcTokenResponse, TokenError> {
        self.validate_client_credentials(client_id, client_secret)?;

        let grant = {
            let mut auth_codes = self.auth_codes.write().await;
            auth_codes
                .remove(code)
                .ok_or_else(|| TokenError::invalid_grant("Authorization code not found"))?
        };

        if grant.expires_at <= Instant::now() {
            return Err(TokenError::invalid_grant("Authorization code expired"));
        }

        if grant.client_id != client_id || grant.redirect_uri != redirect_uri {
            return Err(TokenError::invalid_grant(
                "Authorization code does not match request",
            ));
        }

        validate_pkce(
            grant.code_challenge.as_deref(),
            grant.code_challenge_method.as_deref(),
            code_verifier,
        )?;

        let refresh_token = random_token();
        {
            let mut refresh_grants = self.refresh_grants.write().await;
            refresh_grants.insert(
                refresh_token.clone(),
                RefreshGrant {
                    client_id: grant.client_id.clone(),
                    subject: grant.subject.clone(),
                    email: grant.email.clone(),
                    email_verified: grant.email_verified,
                    name: grant.name.clone(),
                    session_expires_at: grant.session_expires_at,
                },
            );
        }

        self.issue_token_response(
            &grant.subject,
            &grant.email,
            grant.email_verified,
            grant.name.as_deref(),
            grant.nonce.as_deref(),
            client_id,
            grant.session_expires_at,
            Some(refresh_token),
        )
    }

    pub async fn exchange_refresh_token(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<OidcTokenResponse, TokenError> {
        self.validate_client_credentials(client_id, client_secret)?;

        let grant = {
            let refresh_grants = self.refresh_grants.read().await;
            refresh_grants
                .get(refresh_token)
                .cloned()
                .ok_or_else(|| TokenError::invalid_grant("Refresh token not found"))?
        };

        if grant.client_id != client_id {
            return Err(TokenError::invalid_grant(
                "Refresh token does not match request",
            ));
        }

        self.issue_token_response(
            &grant.subject,
            &grant.email,
            grant.email_verified,
            grant.name.as_deref(),
            None,
            client_id,
            grant.session_expires_at,
            Some(refresh_token.to_string()),
        )
    }

    pub fn build_code_redirect(
        &self,
        redirect_uri: &str,
        code: &str,
        state: Option<&str>,
    ) -> Result<String, TokenError> {
        let mut url = Url::parse(redirect_uri)
            .map_err(|_| TokenError::invalid_request("Invalid redirect_uri"))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("code", code);
            if let Some(state) = state {
                pairs.append_pair("state", state);
            }
        }
        Ok(url.to_string())
    }

    pub fn build_error_redirect(
        &self,
        redirect_uri: &str,
        error: &str,
        description: &str,
        state: Option<&str>,
    ) -> Result<String, TokenError> {
        let mut url = Url::parse(redirect_uri)
            .map_err(|_| TokenError::invalid_request("Invalid redirect_uri"))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("error", error);
            pairs.append_pair("error_description", description);
            if let Some(state) = state {
                pairs.append_pair("state", state);
            }
        }
        Ok(url.to_string())
    }

    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                self.cleanup_expired().await;
            }
        });
    }

    async fn cleanup_expired(&self) {
        let now = Instant::now();

        {
            let mut auth_codes = self.auth_codes.write().await;
            auth_codes.retain(|_, grant| grant.expires_at > now && grant.session_expires_at > now);
        }

        {
            let mut refresh_grants = self.refresh_grants.write().await;
            refresh_grants.retain(|_, grant| grant.session_expires_at > now);
        }
    }

    fn issue_token_response(
        &self,
        subject: &str,
        email: &str,
        email_verified: bool,
        name: Option<&str>,
        nonce: Option<&str>,
        audience: &str,
        session_expires_at: Instant,
        refresh_token: Option<String>,
    ) -> Result<OidcTokenResponse, TokenError> {
        let now = Instant::now();
        if session_expires_at <= now {
            return Err(TokenError::invalid_grant("Upstream session expired"));
        }

        let remaining = session_expires_at.saturating_duration_since(now).as_secs();
        let expires_in = remaining.min(self.config.token_ttl_secs).max(1);
        let id_token = self
            .mint_token(
                subject,
                email,
                email_verified,
                name,
                nonce,
                audience,
                expires_in,
            )
            .map_err(|e| TokenError::invalid_request(format!("Failed to mint OIDC token: {e}")))?;

        Ok(OidcTokenResponse {
            access_token: id_token.clone(),
            id_token,
            refresh_token,
            expires_in: expires_in as usize,
            token_type: "Bearer".to_string(),
        })
    }

    fn mint_token(
        &self,
        subject: &str,
        email: &str,
        email_verified: bool,
        name: Option<&str>,
        nonce: Option<&str>,
        audience: &str,
        expires_in_secs: u64,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let now = epoch_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.as_ref().clone());

        let claims = LocalTokenClaims {
            iss: self.config.issuer_url.clone(),
            sub: subject.to_string(),
            aud: audience.to_string(),
            exp: (now + expires_in_secs) as usize,
            iat: now as usize,
            nbf: now as usize,
            jti: random_token(),
            email: email.to_string(),
            email_verified,
            preferred_username: email.to_string(),
            groups: self.config.groups.clone(),
            name: name.map(str::to_owned),
            nonce: nonce.map(str::to_owned),
        };

        Ok(jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(self.signing_key_pem.as_slice())?,
        )?)
    }
}

fn build_jwks_document(
    cert_pem: &[u8],
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let cert = X509::from_pem(cert_pem)?;
    let public_key = cert.public_key()?;
    let public_key_pem = public_key.public_key_to_pem()?;
    let kid = format!("{:x}", xxh3_64(&public_key_pem));
    let ec_key = public_key.ec_key()?;
    let group = ec_key.group();
    let point = ec_key.public_key();
    let mut ctx = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    point.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

    let jwks = json!({
        "keys": [{
            "kty": "EC",
            "use": "sig",
            "crv": "P-256",
            "alg": "ES256",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(x.to_vec()),
            "y": URL_SAFE_NO_PAD.encode(y.to_vec()),
            "x5t#S256": URL_SAFE_NO_PAD.encode(sha256(cert.to_der()?.as_slice())),
        }]
    });

    Ok((kid, serde_json::to_string(&jwks)?))
}

fn validate_pkce(
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
    code_verifier: Option<&str>,
) -> Result<(), TokenError> {
    let Some(code_challenge) = code_challenge else {
        return Ok(());
    };

    let verifier =
        code_verifier.ok_or_else(|| TokenError::invalid_grant("Missing PKCE code_verifier"))?;
    let method = code_challenge_method.unwrap_or("plain");

    let expected = match method {
        "plain" => verifier.to_string(),
        "S256" => {
            let digest = Sha256::digest(verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
        _ => {
            return Err(TokenError::invalid_grant(format!(
                "Unsupported PKCE code challenge method: {method}"
            )))
        }
    };

    if expected == code_challenge {
        Ok(())
    } else {
        Err(TokenError::invalid_grant("PKCE verification failed"))
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_basic_credentials(header_value: &str) -> Option<(String, String)> {
    let encoded = header_value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = decoded.split_once(':')?;
    Some((client_id.to_string(), client_secret.to_string()))
}
