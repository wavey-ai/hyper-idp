use crate::claims::{get_user, User};
use crate::oidc::{
    decode_basic_credentials, AuthorizationRequest, OidcProvider, OidcProviderConfig, TokenError,
};
use crate::session::{Session, SessionStore};
use crate::ui;
use bytes::{Buf, Bytes, BytesMut};
use cookie::Cookie;
use h3::server::RequestStream;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::SET_COOKIE;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tls_helpers::{
    certs_from_base64, from_base64_raw, privkey_from_base64, tls_acceptor_from_base64,
};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};
use url::Url;
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;

const LOGIN_PATH: &str = "/login";
const AUTHORIZE_PATH: &str = "/authorize";
const CALLBACK_PATH: &str = "/oauth2/callback";
const TOKEN_PATH: &str = "/oauth/token";
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const JWKS_PATH: &str = "/.well-known/jwks.json";
const INTERNAL_LOGIN_PATH: &str = "/internal/login";
const INTERNAL_AUTHORIZE_PATH: &str = "/internal/authorize";
const INTERNAL_TOKEN_PATH: &str = "/internal/oauth/token";
const INTERNAL_DISCOVERY_PATH: &str = "/internal/.well-known/openid-configuration";
const INTERNAL_JWKS_PATH: &str = "/internal/.well-known/jwks.json";
const LOGOUT_PATH: &str = "/logout";
const PROFILE_PATH: &str = "/profile";
const REFRESH_PATH: &str = "/refresh";
const VALIDATE_PATH: &str = "/validate";
const USERS_PATH: &str = "/users";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoginPolicy {
    Public,
    Internal,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthTokenResponse {
    access_token: String,
    id_token: String,
    refresh_token: Option<String>,
    expires_in: usize,
    token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub user_id: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UsersResponse {
    pub user_ids: Vec<u64>,
}

pub struct IdpCreds {
    pub audience: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub signing_cert: String,
    pub issuer_url: String,
    pub internal_issuer_url: String,
    pub local_client_id: String,
    pub local_client_secret: String,
    pub cookie_domain: String,
    pub local_token_ttl_secs: u64,
    pub local_groups: Vec<String>,
    pub internal_client_id: String,
    pub internal_client_secret: String,
    pub internal_token_ttl_secs: u64,
    pub internal_groups: Vec<String>,
    pub internal_allowed_email_domains: Vec<String>,
}

pub struct IdpServer {
    cert_pem_base64: String,
    privkey_pem_base64: String,
    ssl_port: u16,
    creds: Arc<IdpCreds>,
    sessions: Arc<SessionStore>,
    public_oidc: Arc<OidcProvider>,
    internal_oidc: Arc<OidcProvider>,
}

struct RequestContext {
    creds: Arc<IdpCreds>,
    sessions: Arc<SessionStore>,
    public_oidc: Arc<OidcProvider>,
    internal_oidc: Arc<OidcProvider>,
}

impl IdpServer {
    pub fn new(
        cert_pem_base64: String,
        privkey_pem_base64: String,
        ssl_port: u16,
        creds: IdpCreds,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let sessions = Arc::new(SessionStore::new(3600));
        Arc::clone(&sessions).start_cleanup_task(300);

        let public_oidc = Arc::new(OidcProvider::new(
            OidcProviderConfig {
                issuer_url: creds.issuer_url.clone(),
                client_id: creds.local_client_id.clone(),
                client_secret: creds.local_client_secret.clone(),
                cookie_domain: creds.cookie_domain.clone(),
                token_ttl_secs: creds.local_token_ttl_secs,
                groups: creds.local_groups.clone(),
            },
            &cert_pem_base64,
            &privkey_pem_base64,
        )?);
        Arc::clone(&public_oidc).start_cleanup_task();

        let internal_oidc = Arc::new(OidcProvider::new(
            OidcProviderConfig {
                issuer_url: creds.internal_issuer_url.clone(),
                client_id: creds.internal_client_id.clone(),
                client_secret: creds.internal_client_secret.clone(),
                cookie_domain: creds.cookie_domain.clone(),
                token_ttl_secs: creds.internal_token_ttl_secs,
                groups: creds.internal_groups.clone(),
            },
            &cert_pem_base64,
            &privkey_pem_base64,
        )?);
        Arc::clone(&internal_oidc).start_cleanup_task();

        Ok(Self {
            cert_pem_base64,
            privkey_pem_base64,
            ssl_port,
            creds: Arc::new(creds),
            sessions,
            public_oidc,
            internal_oidc,
        })
    }

    pub async fn start(
        &self,
    ) -> Result<tokio::sync::watch::Sender<()>, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = watch::channel(());

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
        let tls_acceptor =
            tls_acceptor_from_base64(&self.cert_pem_base64, &self.privkey_pem_base64, false, true)?;

        info!("idp server up at https://{}", addr);

        let creds = Arc::clone(&self.creds);
        let sessions = Arc::clone(&self.sessions);
        let public_oidc = Arc::clone(&self.public_oidc);
        let internal_oidc = Arc::clone(&self.internal_oidc);
        let srv_h2 = {
            let mut shutdown_signal = rx.clone();

            let creds = Arc::clone(&creds);
            let sessions = Arc::clone(&sessions);
            let public_oidc = Arc::clone(&public_oidc);
            let internal_oidc = Arc::clone(&internal_oidc);
            async move {
                let incoming = TcpListener::bind(&addr).await.unwrap();
                let ctx = Arc::new(RequestContext {
                    creds: Arc::clone(&creds),
                    sessions: Arc::clone(&sessions),
                    public_oidc: Arc::clone(&public_oidc),
                    internal_oidc: Arc::clone(&internal_oidc),
                });
                let service = service_fn(move |req| handle_request_h2(req, Arc::clone(&ctx)));

                loop {
                    tokio::select! {
                        _ = shutdown_signal.changed() => {
                            break;
                        }
                        result = incoming.accept() => {
                            let (tcp_stream, _remote_addr) = result.unwrap();
                            let tls_acceptor = tls_acceptor.clone();
                            let service = service.clone();

                            tokio::spawn(async move {
                                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                    Ok(tls_stream) => tls_stream,
                                    Err(err) => {
                                        error!("failed to perform tls handshake: {err:#}");
                                        return;
                                    }
                                };
                                if let Err(err) = ConnectionBuilder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls_stream), service)
                                    .await
                                {
                                    error!("failed to serve connection: {err:#}");
                                }
                            });
                        }
                    }
                }
            }
        };

        tokio::spawn(srv_h2);

        {
            let certs = certs_from_base64(&self.cert_pem_base64)?;
            let key = privkey_from_base64(&self.privkey_pem_base64)?;

            let mut tls_config = rustls::ServerConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();

            tls_config.max_early_data_size = u32::MAX;
            tls_config.alpn_protocols = vec![
                b"h3".to_vec(),
                b"h3-32".to_vec(),
                b"h3-31".to_vec(),
                b"h3-30".to_vec(),
                b"h3-29".to_vec(),
            ];

            let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
            let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
            let endpoint = quinn::Endpoint::server(server_config, addr).unwrap();

            let creds = Arc::clone(&self.creds);
            let sessions = Arc::clone(&self.sessions);
            let public_oidc = Arc::clone(&self.public_oidc);
            let internal_oidc = Arc::clone(&self.internal_oidc);
            let srv_h3 = {
                let mut shutdown_signal = rx.clone();

                async move {
                    loop {
                        tokio::select! {
                            _ = shutdown_signal.changed() => {
                                break;
                            }
                            res = endpoint.accept()  => {
                                if let Some(new_conn) = res {
                                    info!("New connection being attempted");
                                    let ctx = Arc::new(RequestContext {
                                        creds: Arc::clone(&creds),
                                        sessions: Arc::clone(&sessions),
                                        public_oidc: Arc::clone(&public_oidc),
                                        internal_oidc: Arc::clone(&internal_oidc),
                                    });
                                    tokio::spawn(async move {
                                        match new_conn.await {
                                            Ok(conn) => {
                                                let mut h3_conn = h3::server::builder()
                                                    .build(h3_quinn::Connection::new(conn))
                                                    .await
                                                    .unwrap();

                                                loop {
                                                    match h3_conn.accept().await {
                                                        Ok(Some((req, stream))) => {
                                                            let ctx = Arc::clone(&ctx);
                                                            tokio::spawn(async move {
                                                                if let Err(err) = handle_connection_h3(req, stream, ctx).await {
                                                                    error!("Failed to handle connection: {err:?}");
                                                                }
                                                            });
                                                        }
                                                        Ok(None) => break,
                                                        Err(err) => {
                                                            error!("error on accept {}", err);
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                error!("accepting connection failed: {:?}", err);
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            };

            tokio::spawn(srv_h3);
        }

        Ok(tx)
    }
}

async fn request_handler(
    method: &Method,
    headers: &http::HeaderMap,
    uri: &http::Uri,
    body: Option<Bytes>,
    ctx: Arc<RequestContext>,
) -> Result<(http::response::Builder, Option<Bytes>), Box<dyn std::error::Error + Send + Sync>> {
    let mut res = http::Response::builder();
    let mut response_body = None;

    match (method, uri.path()) {
        (&Method::GET, "/") | (&Method::GET, "/signin") => {
            res = res
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/html; charset=utf-8");
            response_body = Some(ui::login_page());
        }
        (&Method::GET, LOGIN_PATH) | (&Method::GET, INTERNAL_LOGIN_PATH) => {
            let policy = if uri.path() == INTERNAL_LOGIN_PATH {
                LoginPolicy::Internal
            } else {
                LoginPolicy::Public
            };
            let force_prompt_login = matches!(policy, LoginPolicy::Internal);

            info!(
                policy = login_policy_name(policy),
                "starting upstream login"
            );
            res = res
                .header(
                    SET_COOKIE,
                    login_policy_cookie(policy, &ctx.creds.cookie_domain, 300),
                )
                .header(
                    "location",
                    upstream_login_location(&ctx.creds, None, force_prompt_login)?,
                )
                .status(StatusCode::TEMPORARY_REDIRECT);
        }
        (&Method::GET, path) if path == AUTHORIZE_PATH || path == INTERNAL_AUTHORIZE_PATH => {
            let policy = if path == INTERNAL_AUTHORIZE_PATH {
                LoginPolicy::Internal
            } else {
                LoginPolicy::Public
            };
            let oidc = oidc_for_policy(&ctx, policy);
            let params = query_params(uri);
            let client_id = params.get("client_id").cloned().unwrap_or_default();
            let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
            let response_type = params
                .get("response_type")
                .map(String::as_str)
                .unwrap_or_default();
            let scope = params
                .get("scope")
                .cloned()
                .unwrap_or_else(|| "openid profile email".to_string());
            let requested_state = params.get("state").cloned();
            let auth_request = AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                state: requested_state.clone(),
                nonce: params.get("nonce").cloned(),
                scope: scope.clone(),
                code_challenge: params.get("code_challenge").cloned(),
                code_challenge_method: params.get("code_challenge_method").cloned(),
            };
            let active_session =
                get_active_session_from_request(headers, uri, Arc::clone(&ctx.sessions)).await;
            let has_active_session = active_session.is_some();
            let has_usable_session = active_session
                .as_ref()
                .map(|session| session_matches_policy(&ctx, policy, session))
                .unwrap_or(false);
            let force_prompt_login = has_active_session && !has_usable_session;

            info!(
                policy = login_policy_name(policy),
                client_id = client_id.as_str(),
                redirect_uri = redirect_uri.as_str(),
                has_active_session,
                has_usable_session,
                "received local OIDC authorize request"
            );

            match oidc.validate_authorization_request(
                &client_id,
                &redirect_uri,
                response_type,
                &scope,
            ) {
                Ok(()) => {
                    if let Some(session) = active_session.as_ref().filter(|_| has_usable_session) {
                        info!(
                            policy = login_policy_name(policy),
                            email = session.identity.email.as_str(),
                            "issuing local authorization code"
                        );
                        let code = oidc.create_authorization_code(session, auth_request).await;
                        let location = oidc.build_code_redirect(
                            &redirect_uri,
                            &code,
                            requested_state.as_deref(),
                        )?;
                        res = res
                            .header("location", location)
                            .status(StatusCode::TEMPORARY_REDIRECT);
                    } else if params.get("prompt").map(String::as_str) == Some("none") {
                        let (error_code, description) = if force_prompt_login {
                            ("access_denied", "Only @wavey.ai accounts can sign in here")
                        } else {
                            ("login_required", "An active Wavey IDP session is required")
                        };
                        let location = oidc.build_error_redirect(
                            &redirect_uri,
                            error_code,
                            description,
                            requested_state.as_deref(),
                        )?;
                        res = res
                            .header("location", location)
                            .status(StatusCode::TEMPORARY_REDIRECT);
                    } else {
                        let upstream_state = oidc.store_pending_authorization(auth_request).await;
                        info!(
                            policy = login_policy_name(policy),
                            force_prompt_login, "redirecting authorize request to upstream login"
                        );
                        res = res
                            .header(
                                "location",
                                upstream_login_location(
                                    &ctx.creds,
                                    Some(&upstream_state),
                                    force_prompt_login,
                                )?,
                            )
                            .status(StatusCode::TEMPORARY_REDIRECT);
                    }
                }
                Err(err) => {
                    if oidc.validate_redirect_uri(&redirect_uri).is_ok() {
                        let location = oidc.build_error_redirect(
                            &redirect_uri,
                            err.error,
                            &err.description,
                            requested_state.as_deref(),
                        )?;
                        res = res
                            .header("location", location)
                            .status(StatusCode::TEMPORARY_REDIRECT);
                    } else {
                        res = res.status(err.status);
                        response_body = Some(json_bytes(err.as_json())?);
                    }
                }
            }
        }
        (&Method::GET, CALLBACK_PATH) => {
            let params = query_params(uri);
            let upstream_state = params.get("state").cloned();
            let pending_auth = if let Some(state) = upstream_state.as_deref() {
                take_pending_authorization(&ctx, state).await
            } else {
                None
            };
            let direct_login_policy =
                login_policy_from_request(headers).unwrap_or(LoginPolicy::Public);
            let callback_policy = pending_auth
                .as_ref()
                .map(|(policy, _)| *policy)
                .unwrap_or(direct_login_policy);

            if let Some(error) = params.get("error") {
                let description = params
                    .get("error_description")
                    .cloned()
                    .unwrap_or_else(|| "OIDC login failed".to_string());
                warn!(
                    policy = login_policy_name(callback_policy),
                    error = error,
                    description = description,
                    "upstream login returned an error"
                );
                if let Some((policy, pending_auth)) = pending_auth {
                    let oidc = oidc_for_policy(&ctx, policy);
                    let location = oidc.build_error_redirect(
                        &pending_auth.redirect_uri,
                        error,
                        &description,
                        pending_auth.state.as_deref(),
                    )?;
                    res = res
                        .header(
                            SET_COOKIE,
                            clear_login_policy_cookie(&ctx.creds.cookie_domain),
                        )
                        .header("location", location)
                        .status(StatusCode::TEMPORARY_REDIRECT);
                } else {
                    res = res
                        .header(
                            SET_COOKIE,
                            clear_login_policy_cookie(&ctx.creds.cookie_domain),
                        )
                        .status(StatusCode::BAD_REQUEST);
                    response_body = Some(Bytes::from(description));
                }
            } else {
                let code = params
                    .get("code")
                    .cloned()
                    .ok_or_else(|| "missing authorization code".to_string())?;

                let tokens = exchange_code_for_tokens(code, Arc::clone(&ctx.creds)).await?;
                let signing_cert = from_base64_raw(&ctx.creds.signing_cert)?;
                let user = get_user(&tokens.id_token, &signing_cert, &ctx.creds.client_id)?;
                let identity = user.identity()?;
                let user_email = identity.email.clone();
                let email_verified = identity.email_verified;
                let has_pending_auth = pending_auth.is_some();

                info!(
                    policy = login_policy_name(callback_policy),
                    email = user_email.as_str(),
                    email_verified,
                    has_pending_auth,
                    "upstream login callback succeeded"
                );

                if let Some(policy_error) =
                    login_policy_error(&ctx, callback_policy, &user_email, email_verified)
                {
                    warn!(
                        policy = login_policy_name(callback_policy),
                        email = user_email.as_str(),
                        description = policy_error.as_str(),
                        "rejecting login because callback user does not satisfy policy"
                    );
                    if let Some((policy, pending_auth)) = pending_auth {
                        let oidc = oidc_for_policy(&ctx, policy);
                        let location = oidc.build_error_redirect(
                            &pending_auth.redirect_uri,
                            "access_denied",
                            &policy_error,
                            pending_auth.state.as_deref(),
                        )?;
                        res = res
                            .header(
                                SET_COOKIE,
                                clear_login_policy_cookie(&ctx.creds.cookie_domain),
                            )
                            .header("location", location)
                            .status(StatusCode::TEMPORARY_REDIRECT);
                    } else {
                        res = res
                            .header(
                                SET_COOKIE,
                                clear_login_policy_cookie(&ctx.creds.cookie_domain),
                            )
                            .status(StatusCode::FORBIDDEN)
                            .header(CONTENT_TYPE, "text/html; charset=utf-8");
                        response_body =
                            Some(ui::access_denied_page(Some(&user_email), &policy_error));
                    }
                    return Ok((res, response_body));
                }

                let session_id = format!("{:x}", const_xxh3(tokens.access_token.as_bytes()));
                let session = ctx
                    .sessions
                    .create_session(
                        session_id.clone(),
                        identity,
                        tokens.access_token.clone(),
                        tokens.refresh_token.clone(),
                        tokens.expires_in as u64,
                    )
                    .await;

                let session_cookie = format!(
                    "session_id={}; HttpOnly; Path=/; Secure; SameSite=Lax; Domain={}; Max-Age={}",
                    session_id, ctx.creds.cookie_domain, tokens.expires_in
                );
                let email_cookie = format!(
                    "user_email={}; Path=/; Secure; SameSite=Lax; Domain={}; Max-Age={}",
                    user_email, ctx.creds.cookie_domain, tokens.expires_in
                );
                let access_cookie = format!(
                    "access_token={}; HttpOnly; Path=/; Secure",
                    tokens.access_token
                );
                let id_cookie = format!(
                    "id_token={}; HttpOnly; Path=/; Secure; SameSite=Strict",
                    tokens.id_token
                );

                res = res
                    .header(
                        SET_COOKIE,
                        clear_login_policy_cookie(&ctx.creds.cookie_domain),
                    )
                    .header(SET_COOKIE, session_cookie)
                    .header(SET_COOKIE, email_cookie)
                    .header(SET_COOKIE, access_cookie)
                    .header(SET_COOKIE, id_cookie);

                if let Some((policy, pending_auth)) = pending_auth {
                    let oidc = oidc_for_policy(&ctx, policy);
                    let local_code = oidc
                        .create_authorization_code(&session, pending_auth.clone())
                        .await;
                    let location = oidc.build_code_redirect(
                        &pending_auth.redirect_uri,
                        &local_code,
                        pending_auth.state.as_deref(),
                    )?;
                    res = res
                        .header("location", location)
                        .status(StatusCode::TEMPORARY_REDIRECT);
                } else {
                    res = res
                        .header(CONTENT_TYPE, "text/html; charset=utf-8")
                        .status(StatusCode::OK);
                    response_body = Some(ui::callback_success_page(&user_email));
                }
            }
        }
        (&Method::POST, path) if path == TOKEN_PATH || path == INTERNAL_TOKEN_PATH => {
            let policy = if path == INTERNAL_TOKEN_PATH {
                LoginPolicy::Internal
            } else {
                LoginPolicy::Public
            };
            let oidc = oidc_for_policy(&ctx, policy);
            let params = form_params(body.as_ref())?;
            let grant_type = params
                .get("grant_type")
                .map(String::as_str)
                .unwrap_or("<missing>");
            let (client_id, client_secret) = client_credentials(headers, &params)
                .ok_or_else(|| TokenError::invalid_client("Missing OIDC client credentials"))?;

            info!(
                policy = login_policy_name(policy),
                grant_type,
                client_id = client_id.as_str(),
                "received local OIDC token request"
            );

            let token_response = match params.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    let code = params
                        .get("code")
                        .ok_or_else(|| TokenError::invalid_request("Missing authorization code"))?;
                    let redirect_uri = params
                        .get("redirect_uri")
                        .ok_or_else(|| TokenError::invalid_request("Missing redirect_uri"))?;
                    oidc.exchange_authorization_code(
                        code,
                        &client_id,
                        &client_secret,
                        redirect_uri,
                        params.get("code_verifier").map(String::as_str),
                    )
                    .await
                }
                Some("refresh_token") => {
                    let refresh_token = params
                        .get("refresh_token")
                        .ok_or_else(|| TokenError::invalid_request("Missing refresh_token"))?;
                    oidc.exchange_refresh_token(refresh_token, &client_id, &client_secret)
                        .await
                }
                Some(other) => Err(TokenError::unsupported_grant_type(format!(
                    "Unsupported grant type: {other}"
                ))),
                None => Err(TokenError::invalid_request("Missing grant_type")),
            };

            match token_response {
                Ok(response) => {
                    info!(
                        policy = login_policy_name(policy),
                        grant_type,
                        client_id = client_id.as_str(),
                        "issued local OIDC tokens"
                    );
                    res = res
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json");
                    response_body = Some(json_bytes(response)?);
                }
                Err(err) => {
                    warn!(
                        policy = login_policy_name(policy),
                        grant_type,
                        client_id = client_id.as_str(),
                        error = err.error,
                        description = err.description.as_str(),
                        "local OIDC token request failed"
                    );
                    res = res
                        .status(err.status)
                        .header(CONTENT_TYPE, "application/json");
                    response_body = Some(json_bytes(err.as_json())?);
                }
            }
        }
        (&Method::GET, path) if path == DISCOVERY_PATH || path == INTERNAL_DISCOVERY_PATH => {
            let policy = if path == INTERNAL_DISCOVERY_PATH {
                LoginPolicy::Internal
            } else {
                LoginPolicy::Public
            };
            let oidc = oidc_for_policy(&ctx, policy);
            res = res
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json");
            response_body = Some(json_bytes(oidc.discovery_document())?);
        }
        (&Method::GET, path) if path == JWKS_PATH || path == INTERNAL_JWKS_PATH => {
            let policy = if path == INTERNAL_JWKS_PATH {
                LoginPolicy::Internal
            } else {
                LoginPolicy::Public
            };
            let oidc = oidc_for_policy(&ctx, policy);
            res = res
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json");
            response_body = Some(Bytes::from(oidc.jwks_document().to_string()));
        }
        (&Method::GET, PROFILE_PATH) => match get_claims(headers, Arc::clone(&ctx.creds)) {
            Ok(user) => {
                res = res
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json");
                response_body = Some(json_bytes(user)?);
            }
            Err(e) => {
                error!("JWT decode error: {e}");
                res = res.status(StatusCode::UNAUTHORIZED);
            }
        },
        (&Method::GET, VALIDATE_PATH) | (&Method::POST, VALIDATE_PATH) => {
            let session_id = get_session_id_from_request(headers, uri);
            let response = if let Some(sid) = session_id {
                if let Some(user_id) = ctx.sessions.validate_session(&sid).await {
                    ValidateResponse {
                        valid: true,
                        user_id: Some(user_id),
                    }
                } else {
                    ValidateResponse {
                        valid: false,
                        user_id: None,
                    }
                }
            } else {
                ValidateResponse {
                    valid: false,
                    user_id: None,
                }
            };

            res = res
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json");
            response_body = Some(json_bytes(response)?);
        }
        (&Method::GET, USERS_PATH) => {
            let user_ids = ctx.sessions.get_active_user_ids().await;
            let response = UsersResponse { user_ids };

            res = res
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json");
            response_body = Some(json_bytes(response)?);
        }
        (&Method::POST, LOGOUT_PATH) | (&Method::GET, LOGOUT_PATH) => {
            if let Some(sid) = get_session_id_from_request(headers, uri) {
                ctx.sessions.remove_session(&sid).await;
            }

            let clear_session = format!(
                "session_id=; HttpOnly; Path=/; Secure; SameSite=Strict; Domain={}; Max-Age=0",
                ctx.creds.cookie_domain
            );
            let clear_email = format!(
                "user_email=; Path=/; Secure; SameSite=Strict; Domain={}; Max-Age=0",
                ctx.creds.cookie_domain
            );
            let clear_login_policy = clear_login_policy_cookie(&ctx.creds.cookie_domain);
            let clear_access = "access_token=; HttpOnly; Path=/; Secure; Max-Age=0";
            let clear_id = "id_token=; HttpOnly; Path=/; Secure; SameSite=Strict; Max-Age=0";

            res = res
                .header(SET_COOKIE, clear_session)
                .header(SET_COOKIE, clear_email)
                .header(SET_COOKIE, clear_login_policy)
                .header(SET_COOKIE, clear_access)
                .header(SET_COOKIE, clear_id)
                .status(StatusCode::OK);
        }
        (&Method::POST, REFRESH_PATH) => {
            if let Some(sid) = get_session_id_from_request(headers, uri) {
                if let Some(session) = ctx.sessions.get_session(&sid).await {
                    if let Some(refresh_token) = session.refresh_token {
                        match refresh_access_token(refresh_token, Arc::clone(&ctx.creds)).await {
                            Ok(tokens) => {
                                ctx.sessions
                                    .refresh_session(
                                        &sid,
                                        tokens.access_token.clone(),
                                        tokens.expires_in as u64,
                                    )
                                    .await;

                                let access_cookie = format!(
                                    "access_token={}; HttpOnly; Path=/; Secure",
                                    tokens.access_token
                                );
                                res = res.header(SET_COOKIE, access_cookie).status(StatusCode::OK);
                            }
                            Err(e) => {
                                error!("Token refresh failed: {e}");
                                res = res.status(StatusCode::UNAUTHORIZED);
                            }
                        }
                    } else {
                        res = res.status(StatusCode::BAD_REQUEST);
                    }
                } else {
                    res = res.status(StatusCode::UNAUTHORIZED);
                }
            } else {
                res = res.status(StatusCode::UNAUTHORIZED);
            }
        }
        _ => {
            res = res.status(StatusCode::NOT_FOUND);
        }
    }

    Ok((res, response_body))
}

fn oidc_for_policy(ctx: &RequestContext, policy: LoginPolicy) -> Arc<OidcProvider> {
    match policy {
        LoginPolicy::Public => Arc::clone(&ctx.public_oidc),
        LoginPolicy::Internal => Arc::clone(&ctx.internal_oidc),
    }
}

fn login_policy_name(policy: LoginPolicy) -> &'static str {
    match policy {
        LoginPolicy::Public => "public",
        LoginPolicy::Internal => "internal",
    }
}

fn login_policy_cookie(policy: LoginPolicy, cookie_domain: &str, max_age: usize) -> String {
    format!(
        "login_policy={}; HttpOnly; Path=/; Secure; SameSite=Lax; Domain={}; Max-Age={}",
        login_policy_name(policy),
        cookie_domain,
        max_age
    )
}

fn clear_login_policy_cookie(cookie_domain: &str) -> String {
    format!(
        "login_policy=; HttpOnly; Path=/; Secure; SameSite=Strict; Domain={}; Max-Age=0",
        cookie_domain
    )
}

fn login_policy_from_request(headers: &http::HeaderMap) -> Option<LoginPolicy> {
    let cookies = request_cookies(headers);
    match cookies.get("login_policy").map(String::as_str) {
        Some("internal") => Some(LoginPolicy::Internal),
        Some("public") => Some(LoginPolicy::Public),
        _ => None,
    }
}

fn session_matches_policy(ctx: &RequestContext, policy: LoginPolicy, session: &Session) -> bool {
    login_policy_error(
        ctx,
        policy,
        &session.identity.email,
        session.identity.email_verified,
    )
    .is_none()
}

fn login_policy_error(
    ctx: &RequestContext,
    policy: LoginPolicy,
    email: &str,
    email_verified: bool,
) -> Option<String> {
    match policy {
        LoginPolicy::Public => None,
        LoginPolicy::Internal => {
            if !email_verified {
                Some("Email address must be verified".to_string())
            } else if !is_allowed_email_domain(email, &ctx.creds.internal_allowed_email_domains) {
                Some("Only @wavey.ai accounts can sign in here".to_string())
            } else {
                None
            }
        }
    }
}

async fn take_pending_authorization(
    ctx: &RequestContext,
    state: &str,
) -> Option<(LoginPolicy, AuthorizationRequest)> {
    if let Some(request) = ctx.internal_oidc.take_pending_authorization(state).await {
        return Some((LoginPolicy::Internal, request));
    }

    ctx.public_oidc
        .take_pending_authorization(state)
        .await
        .map(|request| (LoginPolicy::Public, request))
}

fn json_bytes<T: Serialize>(value: T) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Bytes::from(serde_json::to_vec(&value)?))
}

fn query_params(uri: &http::Uri) -> HashMap<String, String> {
    uri.query()
        .and_then(|query| serde_urlencoded::from_str::<Vec<(String, String)>>(query).ok())
        .unwrap_or_default()
        .into_iter()
        .collect()
}

fn form_params(
    body: Option<&Bytes>,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(body) = body {
        if !body.is_empty() {
            let pairs = serde_urlencoded::from_bytes::<Vec<(String, String)>>(body.as_ref())?;
            return Ok(pairs.into_iter().collect());
        }
    }

    Ok(HashMap::new())
}

fn upstream_login_location(
    creds: &IdpCreds,
    state: Option<&str>,
    force_prompt_login: bool,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut url = Url::parse(&format!("https://{}/authorize", creds.audience))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("client_id", &creds.client_id);
        pairs.append_pair("response_type", "code");
        pairs.append_pair("redirect_uri", &creds.redirect_uri);
        pairs.append_pair("scope", "openid profile email offline_access");
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
        if force_prompt_login {
            pairs.append_pair("prompt", "login");
        }
    }
    Ok(url.to_string())
}

fn request_cookies(headers: &http::HeaderMap) -> HashMap<String, String> {
    let mut cookie_string = String::new();
    for header in headers.get_all(http::header::COOKIE) {
        if let Ok(header_value) = header.to_str() {
            if !cookie_string.is_empty() {
                cookie_string.push(';');
            }
            cookie_string.push_str(header_value);
        }
    }

    cookie_string
        .split(';')
        .filter_map(|cookie| Cookie::parse(cookie.trim()).ok())
        .map(|cookie| (cookie.name().to_owned(), cookie.value().to_owned()))
        .collect()
}

fn get_session_id_from_request(headers: &http::HeaderMap, uri: &http::Uri) -> Option<String> {
    let cookies = request_cookies(headers);
    if let Some(session_id) = cookies.get("session_id") {
        return Some(session_id.clone());
    }

    query_params(uri).remove("session_id")
}

async fn get_active_session_from_request(
    headers: &http::HeaderMap,
    uri: &http::Uri,
    sessions: Arc<SessionStore>,
) -> Option<Session> {
    let session_id = get_session_id_from_request(headers, uri)?;
    let session = sessions.get_session(&session_id).await?;
    if session.is_expired() {
        None
    } else {
        Some(session)
    }
}

fn client_credentials(
    headers: &http::HeaderMap,
    params: &HashMap<String, String>,
) -> Option<(String, String)> {
    if let Some(auth_header) = headers.get(http::header::AUTHORIZATION) {
        if let Ok(auth_header) = auth_header.to_str() {
            if let Some(credentials) = decode_basic_credentials(auth_header) {
                return Some(credentials);
            }
        }
    }

    let client_id = params.get("client_id")?;
    let client_secret = params.get("client_secret")?;
    Some((client_id.clone(), client_secret.clone()))
}

fn is_allowed_email_domain(email: &str, allowed_domains: &[String]) -> bool {
    let domain = match email.rsplit_once('@') {
        Some((_, domain)) => domain.to_ascii_lowercase(),
        None => return false,
    };

    allowed_domains
        .iter()
        .any(|allowed| domain == allowed.to_ascii_lowercase())
}

async fn read_h3_body(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<Option<Bytes>, Box<dyn std::error::Error + Send + Sync>> {
    let mut body = BytesMut::new();

    while let Some(chunk) = stream.recv_data().await? {
        let mut chunk = chunk;
        if chunk.remaining() > 0 {
            let len = chunk.remaining();
            body.extend_from_slice(chunk.copy_to_bytes(len).as_ref());
        }
    }

    let _ = stream.recv_trailers().await?;

    if body.is_empty() {
        Ok(None)
    } else {
        Ok(Some(body.freeze()))
    }
}

async fn handle_connection_h3(
    req: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ctx: Arc<RequestContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = read_h3_body(&mut stream).await?;

    match request_handler(req.method(), req.headers(), req.uri(), body, ctx).await {
        Ok((res, body)) => {
            let initial_response = res.body(()).unwrap();
            if let Err(err) = stream.send_response(initial_response).await {
                error!("unable to send response to connection peer: {:?}", err);
            }

            if let Some(body) = body {
                if let Err(err) = stream.send_data(body).await {
                    error!("unable to send body data to connection peer: {:?}", err);
                }
            }
        }
        Err(err) => {
            error!("unable to send response to connection peer: {:?}", err);
        }
    }

    if let Err(err) = stream.finish().await {
        error!("unable to finish stream: {:?}", err);
    }

    Ok(())
}

async fn handle_request_h2(
    req: http::Request<Incoming>,
    ctx: Arc<RequestContext>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = req.into_parts();
    let body = body.collect().await?.to_bytes();
    let request_body = if body.is_empty() { None } else { Some(body) };
    let (res, body) =
        request_handler(&parts.method, &parts.headers, &parts.uri, request_body, ctx).await?;

    if let Some(body) = body {
        Ok(res.body(Full::new(body)).unwrap())
    } else {
        Ok(res.body(Full::new(Bytes::new())).unwrap())
    }
}

async fn exchange_code_for_tokens(
    code: String,
    creds: Arc<IdpCreds>,
) -> Result<AuthTokenResponse, reqwest::Error> {
    let client = Client::new();
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", &creds.client_id),
        ("client_secret", &creds.client_secret),
        ("code", &code),
        ("redirect_uri", &creds.redirect_uri),
    ];

    client
        .post(format!("https://{}/oauth/token", creds.audience))
        .form(&params)
        .send()
        .await?
        .json::<AuthTokenResponse>()
        .await
}

async fn refresh_access_token(
    refresh_token: String,
    creds: Arc<IdpCreds>,
) -> Result<AuthTokenResponse, reqwest::Error> {
    let client = Client::new();
    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", &creds.client_id),
        ("client_secret", &creds.client_secret),
        ("refresh_token", &refresh_token),
    ];

    client
        .post(format!("https://{}/oauth/token", creds.audience))
        .form(&params)
        .send()
        .await?
        .json::<AuthTokenResponse>()
        .await
}

pub fn get_claims(
    headers: &http::HeaderMap,
    creds: Arc<IdpCreds>,
) -> Result<User, Box<dyn std::error::Error + Send + Sync>> {
    let cookies = request_cookies(headers);
    if let Some(token) = cookies.get("id_token") {
        let signing_cert = from_base64_raw(&creds.signing_cert)?;
        get_user(token, &signing_cert, &creds.client_id)
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "id_token not found",
        )) as Box<dyn std::error::Error + Send + Sync>)
    }
}
