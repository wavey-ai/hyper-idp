use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, SET_COOKIE};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use pki_types::{CertificateDer, PrivateKeyDer};
use reqwest::Client;
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::{fs::File, io, io::BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

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
}

pub struct IdpServer {
    ssl_port: u16,
    ssl_path: String,
    creds: Arc<IdpCreds>,
}

impl IdpServer {
    pub fn new(ssl_path: String, ssl_port: u16, creds: Arc<IdpCreds>) -> Self {
        Self {
            ssl_path,
            ssl_port,
            creds,
        }
    }

    pub async fn start(
        &self,
    ) -> Result<tokio::sync::watch::Sender<()>, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = watch::channel(());

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);

        let crt_path = format!("{}/{}", self.ssl_path, "cert.pem");
        let key_path = format!("{}/{}", self.ssl_path, "privkey.pem");

        let crt_path = Path::new(&crt_path);
        let key_path = Path::new(&key_path);

        let certs = load_certs(crt_path).unwrap();
        let key = load_keys(key_path).unwrap();

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
                let service = service_fn(move |req| handle_request(req, Arc::clone(&creds)));

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
                                        eprintln!("failed to perform tls handshake: {err:#}");
                                        return;
                                    }
                                };
                                if let Err(err) = ConnectionBuilder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls_stream), service)
                                    .await
                                {
                                    eprintln!("failed to serve connection: {err:#}");
                                }
                            });
                        }
                    }
                }
            }
        };

        tokio::spawn(srv_h2);

        Ok(tx)
    }
}

async fn handle_request(
    req: http::Request<Incoming>,
    creds: Arc<IdpCreds>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/login") => redirect_to_auth(creds).await,
        (&Method::GET, "/callback") => handle_auth_callback(req, creds).await,
        _ => {
            let mut response: Response<Full<Bytes>> = Response::new(Full::default());
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
    };

    response
}

async fn redirect_to_auth(
    creds: Arc<IdpCreds>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let location = format!(
        "https://{}/authorize?client_id={}&response_type=code&redirect_uri={}&scope=openid profile email",
        creds.audience, creds.client_id, creds.redirect_uri
    );

    let mut response = Response::new(Full::default());
    *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    response
        .headers_mut()
        .insert("location", location.parse().unwrap());

    Ok(response)
}

async fn handle_auth_callback(
    req: http::Request<Incoming>,
    creds: Arc<IdpCreds>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let query_pairs = req
        .uri()
        .query()
        .map(|v| serde_urlencoded::from_str::<Vec<(String, String)>>(v).unwrap())
        .unwrap();
    let code = query_pairs
        .iter()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.clone())
        .unwrap();

    let tokens = exchange_code_for_tokens(code, creds).await.unwrap();

    let mut response = Response::new(Full::default());

    let access_cookie = format!(
        "access_token={}; HttpOnly; Path=/; Secure",
        tokens.access_token
    );
    let access_cookie_header = HeaderValue::from_str(&access_cookie)
        .expect("Failed to create header value from access token cookie string");

    response
        .headers_mut()
        .append(SET_COOKIE, access_cookie_header);

    let id_cookie = format!("id_token={}; HttpOnly; Path=/; Secure", tokens.id_token);
    let id_cookie_header = HeaderValue::from_str(&id_cookie)
        .expect("Failed to create header value from ID token cookie string");

    response.headers_mut().append(SET_COOKIE, id_cookie_header);

    Ok(response)
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

fn add_cors_headers(res: &mut http::Response<()>) {
    res.headers_mut()
        .insert("access-control-allow-origin", "*".parse().unwrap());
    res.headers_mut().insert(
        "access-control-allow-methods",
        "GET, POST, PUT, DELETE, OPTIONS".parse().unwrap(),
    );
    res.headers_mut().insert(
        "access-control-allow-headers",
        "Content-Type".parse().unwrap(),
    );
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
