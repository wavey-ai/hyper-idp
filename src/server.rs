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
use tracing::{error, info};
use url::Url;
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;

const LOGIN_PATH: &str = "/login";
const AUTHORIZE_PATH: &str = "/authorize";
const CALLBACK_PATH: &str = "/oauth2/callback";
const TOKEN_PATH: &str = "/oauth/token";
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const JWKS_PATH: &str = "/.well-known/jwks.json";
const LOGOUT_PATH: &str = "/logout";
const PROFILE_PATH: &str = "/profile";
const REFRESH_PATH: &str = "/refresh";
const VALIDATE_PATH: &str = "/validate";
const USERS_PATH: &str = "/users";

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
    pub local_client_id: String,
    pub local_client_secret: String,
    pub cookie_domain: String,
    pub local_token_ttl_secs: u64,
    pub local_groups: Vec<String>,
}

pub struct IdpServer {
    cert_pem_base64: String,
    privkey_pem_base64: String,
    ssl_port: u16,
    creds: Arc<IdpCreds>,
    sessions: Arc<SessionStore>,
    oidc: Arc<OidcProvider>,
}

struct RequestContext {
    creds: Arc<IdpCreds>,
    sessions: Arc<SessionStore>,
    oidc: Arc<OidcProvider>,
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

        let oidc = Arc::new(OidcProvider::new(
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
        Arc::clone(&oidc).start_cleanup_task();

        Ok(Self {
            cert_pem_base64,
            privkey_pem_base64,
            ssl_port,
            creds: Arc::new(creds),
            sessions,
            oidc,
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
        let oidc = Arc::clone(&self.oidc);
        let srv_h2 = {
            let mut shutdown_signal = rx.clone();

            let creds = Arc::clone(&creds);
            let sessions = Arc::clone(&sessions);
            let oidc = Arc::clone(&oidc);
            async move {
                let incoming = TcpListener::bind(&addr).await.unwrap();
                let ctx = Arc::new(RequestContext {
                    creds: Arc::clone(&creds),
                    sessions: Arc::clone(&sessions),
                    oidc: Arc::clone(&oidc),
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
            let oidc = Arc::clone(&self.oidc);
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
                                        oidc: Arc::clone(&oidc),
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
        (&Method::GET, LOGIN_PATH) => {
            res = res
                .header("location", upstream_login_location(&ctx.creds, None)?)
                .status(StatusCode::TEMPORARY_REDIRECT);
        }
        (&Method::GET, AUTHORIZE_PATH) => {
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

            match ctx.oidc.validate_authorization_request(
                &client_id,
                &redirect_uri,
                response_type,
                &scope,
            ) {
                Ok(()) => {
                    if let Some(session) =
                        get_active_session_from_request(headers, uri, Arc::clone(&ctx.sessions))
                            .await
                    {
                        let code = ctx
                            .oidc
                            .create_authorization_code(&session, auth_request)
                            .await;
                        let location = ctx.oidc.build_code_redirect(
                            &redirect_uri,
                            &code,
                            requested_state.as_deref(),
                        )?;
                        res = res
                            .header("location", location)
                            .status(StatusCode::TEMPORARY_REDIRECT);
                    } else if params.get("prompt").map(String::as_str) == Some("none") {
                        let location = ctx.oidc.build_error_redirect(
                            &redirect_uri,
                            "login_required",
                            "An active Wavey IDP session is required",
                            requested_state.as_deref(),
                        )?;
                        res = res
                            .header("location", location)
                            .status(StatusCode::TEMPORARY_REDIRECT);
                    } else {
                        let upstream_state =
                            ctx.oidc.store_pending_authorization(auth_request).await;
                        res = res
                            .header(
                                "location",
                                upstream_login_location(&ctx.creds, Some(&upstream_state))?,
                            )
                            .status(StatusCode::TEMPORARY_REDIRECT);
                    }
                }
                Err(err) => {
                    if ctx.oidc.validate_redirect_uri(&redirect_uri).is_ok() {
                        let location = ctx.oidc.build_error_redirect(
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
                ctx.oidc.take_pending_authorization(state).await
            } else {
                None
            };

            if let Some(error) = params.get("error") {
                let description = params
                    .get("error_description")
                    .cloned()
                    .unwrap_or_else(|| "OIDC login failed".to_string());
                if let Some(pending_auth) = pending_auth {
                    let location = ctx.oidc.build_error_redirect(
                        &pending_auth.redirect_uri,
                        error,
                        &description,
                        pending_auth.state.as_deref(),
                    )?;
                    res = res
                        .header("location", location)
                        .status(StatusCode::TEMPORARY_REDIRECT);
                } else {
                    res = res.status(StatusCode::BAD_REQUEST);
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
                    .header(SET_COOKIE, session_cookie)
                    .header(SET_COOKIE, email_cookie)
                    .header(SET_COOKIE, access_cookie)
                    .header(SET_COOKIE, id_cookie);

                if let Some(pending_auth) = pending_auth {
                    let local_code = ctx
                        .oidc
                        .create_authorization_code(&session, pending_auth.clone())
                        .await;
                    let location = ctx.oidc.build_code_redirect(
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
        (&Method::POST, TOKEN_PATH) => {
            let params = form_params(body.as_ref())?;
            let (client_id, client_secret) = client_credentials(headers, &params)
                .ok_or_else(|| TokenError::invalid_client("Missing OIDC client credentials"))?;

            let token_response = match params.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    let code = params
                        .get("code")
                        .ok_or_else(|| TokenError::invalid_request("Missing authorization code"))?;
                    let redirect_uri = params
                        .get("redirect_uri")
                        .ok_or_else(|| TokenError::invalid_request("Missing redirect_uri"))?;
                    ctx.oidc
                        .exchange_authorization_code(
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
                    ctx.oidc
                        .exchange_refresh_token(refresh_token, &client_id, &client_secret)
                        .await
                }
                Some(other) => Err(TokenError::unsupported_grant_type(format!(
                    "Unsupported grant type: {other}"
                ))),
                None => Err(TokenError::invalid_request("Missing grant_type")),
            };

            match token_response {
                Ok(response) => {
                    res = res
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json");
                    response_body = Some(json_bytes(response)?);
                }
                Err(err) => {
                    res = res
                        .status(err.status)
                        .header(CONTENT_TYPE, "application/json");
                    response_body = Some(json_bytes(err.as_json())?);
                }
            }
        }
        (&Method::GET, DISCOVERY_PATH) => {
            res = res
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json");
            response_body = Some(json_bytes(ctx.oidc.discovery_document())?);
        }
        (&Method::GET, JWKS_PATH) => {
            res = res
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json");
            response_body = Some(Bytes::from(ctx.oidc.jwks_document().to_string()));
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
            let clear_access = "access_token=; HttpOnly; Path=/; Secure; Max-Age=0";
            let clear_id = "id_token=; HttpOnly; Path=/; Secure; SameSite=Strict; Max-Age=0";

            res = res
                .header(SET_COOKIE, clear_session)
                .header(SET_COOKIE, clear_email)
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
