use hyper_idp::server::{IdpCreds, IdpServer};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    // Load TLS certs from environment (base64 encoded)
    let cert_pem = env::var("CERT_PEM_BASE64").expect("CERT_PEM_BASE64 required");
    let key_pem = env::var("KEY_PEM_BASE64").expect("KEY_PEM_BASE64 required");

    // Load OAuth provider config
    let creds = IdpCreds {
        audience: env::var("OIDC_AUDIENCE").expect("OIDC_AUDIENCE required"),
        client_id: env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID required"),
        client_secret: env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET required"),
        redirect_uri: env::var("REDIRECT_URI").unwrap_or_else(|_| "https://idp.wavey.io/oauth2/callback".into()),
        signing_cert: env::var("SIGNING_CERT_BASE64").unwrap_or_default(),
    };

    let port: u16 = env::var("PORT").unwrap_or_else(|_| "443".into()).parse().unwrap();

    tracing::info!("Starting IDP server on port {}", port);
    tracing::info!("Login URL: https://idp.wavey.io/login");
    tracing::info!("Users URL: https://idp.wavey.io/users");

    let server = IdpServer::new(cert_pem, key_pem, port, creds);
    let shutdown_tx = server.start().await?;

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");
    let _ = shutdown_tx.send(());

    Ok(())
}
