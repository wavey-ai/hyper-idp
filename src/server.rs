use crate::claims::decode_jwt;
use bytes::Bytes;
use cookie::Cookie;
use h3::server::RequestStream;
use http::header::{CONTENT_TYPE, COOKIE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::SET_COOKIE;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use pki_types::{CertificateDer, PrivateKeyDer};
use reqwest::Client;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::{fs::File, io, io::BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

const LOGIN_PATH: &str = "/login";
const CALLBACK_PATH: &str = "/oauth2/callback";
const LOGOUT_PATH: &str = "/logout";
const PROFILE_PATH: &str = "/profile";

#[derive(Debug, Serialize, Deserialize)]
struct AuthTokenResponse {
    access_token: String,
    id_token: String,
    expires_in: usize,
    token_type: String,
}

pub struct IdpCreds {
    pub audience: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub signing_cert: Vec<u8>,
}

pub struct IdpServer {
    ssl_port: u16,
    ssl_path: String,
    creds: Arc<IdpCreds>,
}

impl IdpServer {
    pub fn new(ssl_path: String, ssl_port: u16, creds: IdpCreds) -> Self {
        Self {
            ssl_path,
            ssl_port,
            creds: Arc::new(creds),
        }
    }

    pub async fn start(
        &self,
    ) -> Result<tokio::sync::watch::Sender<()>, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = watch::channel(());

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);

        let crt_path = format!("{}/{}", self.ssl_path, "fullchain.pem");
        let key_path = format!("{}/{}", self.ssl_path, "privkey.pem");

        let crt_path = Path::new(&crt_path);
        let key_path = Path::new(&key_path);

        let certs = load_certs(crt_path)?;
        let key = load_keys(key_path)?;

        let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        server_config.alpn_protocols =
            vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        info!("idp server up at https://{}", addr);

        let creds = Arc::clone(&self.creds);
        let srv_h2 = {
            let mut shutdown_signal = rx.clone();

            let creds = Arc::clone(&creds);
            async move {
                let incoming = TcpListener::bind(&addr).await.unwrap();
                let service = service_fn(move |req| handle_request_h2(req, Arc::clone(&creds)));

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
            let certs = Certificate(
                std::fs::read(format!("{}/{}", self.ssl_path, "fullchain.der")).unwrap(),
            );
            let key =
                PrivateKey(std::fs::read(format!("{}/{}", self.ssl_path, "privkey.der")).unwrap());

            let mut tls_config = rustls::ServerConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certs], key)
                .unwrap();

            tls_config.max_early_data_size = u32::MAX;
            let alpn: Vec<Vec<u8>> = vec![
                b"h3".to_vec(),
                b"h3-32".to_vec(),
                b"h3-31".to_vec(),
                b"h3-30".to_vec(),
                b"h3-29".to_vec(),
            ];
            tls_config.alpn_protocols = alpn;

            let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
            let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
            let endpoint = quinn::Endpoint::server(server_config, addr).unwrap();

            let creds = Arc::clone(&self.creds);
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
                                    let creds = Arc::clone(&creds);
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
                                                            let creds = Arc::clone(&creds);
                                                            tokio::spawn(async move {
                                                                if let Err(err) = handle_connection_h3(req, stream, Arc::clone(&creds)).await {
                                                                    error!("Failed to handle connection: {err:?}");
                                                                }
                                                            });
                                                        }
                                                        Ok(None) => {
                                                            break;
                                                        },
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
    creds: Arc<IdpCreds>,
) -> Result<(http::response::Builder, Option<Bytes>), Box<dyn std::error::Error + Send + Sync>> {
    let mut res = http::Response::builder();
    let mut body = None;
    match (method, uri.path()) {
        (&Method::GET, LOGIN_PATH) => {
            let location = format!(
        "https://{}/authorize?client_id={}&response_type=code&redirect_uri={}&scope=openid profile email",
        creds.audience, creds.client_id, creds.redirect_uri);
            res = res
                .header("location", location)
                .status(StatusCode::TEMPORARY_REDIRECT);
        }
        (&Method::GET, CALLBACK_PATH) => {
            let query_pairs = uri
                .query()
                .map(|v| serde_urlencoded::from_str::<Vec<(String, String)>>(v).unwrap())
                .unwrap();
            let code = query_pairs
                .iter()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.clone())
                .unwrap();

            let tokens = exchange_code_for_tokens(code, creds).await.unwrap();

            let access_cookie = format!(
                "access_token={}; HttpOnly; Path=/; Secure",
                tokens.access_token
            );
            let id_cookie = format!("id_token={}; HttpOnly; Path=/; Secure", tokens.id_token);

            res = res
                .header(SET_COOKIE, access_cookie)
                .header(SET_COOKIE, id_cookie)
                .status(StatusCode::OK);
        }
        (&Method::GET, PROFILE_PATH) => {
            let mut cookie_string = String::new();
            for header in headers.get_all(COOKIE) {
                if let Ok(header_value) = header.to_str() {
                    if !cookie_string.is_empty() {
                        cookie_string.push(';');
                    }
                    cookie_string.push_str(header_value);
                }
            }
            let cookies: HashMap<String, String> = cookie_string
                .split(';')
                .filter_map(|c| Cookie::parse(c.trim()).ok())
                .map(|c| (c.name().to_owned(), c.value().to_owned()))
                .collect();

            if let Some(token) = cookies.get("id_token") {
                // aud in the case ot Auth0 is client_id
                match decode_jwt(token, &creds.signing_cert, &creds.client_id) {
                    Ok(claims) => {
                        let json_response = serde_json::to_string(&claims)?;
                        let body_bytes = Bytes::from(json_response);
                        res = res
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json");
                        body = Some(body_bytes);
                    }
                    Err(e) => {
                        error!("JWT decode error: {e}");
                        res = res.status(StatusCode::UNAUTHORIZED);
                    }
                }
            } else {
                res = res.status(StatusCode::UNAUTHORIZED);
            }
        }
        (&Method::GET, LOGOUT_PATH) => {
            res = res.status(StatusCode::NOT_FOUND);
        }
        _ => {
            res = res.status(StatusCode::NOT_FOUND);
        }
    };

    Ok((res, body))
}

async fn handle_connection_h3(
    req: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    creds: Arc<IdpCreds>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match request_handler(req.method(), req.headers(), req.uri(), creds).await {
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
    creds: Arc<IdpCreds>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let (res, body) = request_handler(req.method(), req.headers(), req.uri(), creds).await?;
    if let Some(b) = body {
        Ok(res.body(Full::new(b)).unwrap())
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

    let response = client
        .post(format!("https://{}/oauth/token", creds.audience))
        .form(&params)
        .send()
        .await?
        .json::<AuthTokenResponse>()
        .await?;

    Ok(response)
}

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

fn load_keys(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .next()
        .unwrap()
        .map(Into::into)
}
