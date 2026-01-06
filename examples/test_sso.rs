use hyper_idp::server::{IdpCreds, IdpServer};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    // Load from environment or .env file
    let cert_pem = env::var("CERT_PEM_BASE64").expect("CERT_PEM_BASE64 required");
    let key_pem = env::var("KEY_PEM_BASE64").expect("KEY_PEM_BASE64 required");

    let creds = IdpCreds {
        // Auth0 example - replace with your values
        audience: env::var("AUTH0_DOMAIN").unwrap_or_else(|_| "your-tenant.auth0.com".into()),
        client_id: env::var("AUTH0_CLIENT_ID").expect("AUTH0_CLIENT_ID required"),
        client_secret: env::var("AUTH0_CLIENT_SECRET").expect("AUTH0_CLIENT_SECRET required"),
        redirect_uri: env::var("REDIRECT_URI").unwrap_or_else(|_| "https://local.wavey.io:8443/oauth2/callback".into()),
        signing_cert: env::var("AUTH0_SIGNING_CERT_BASE64").expect("AUTH0_SIGNING_CERT_BASE64 required"),
    };

    let port = env::var("SSO_PORT").unwrap_or_else(|_| "8443".into()).parse().unwrap();

    println!("Starting SSO server on port {}", port);
    println!("Login URL: https://local.wavey.io:{}/login", port);
    println!("Profile URL: https://local.wavey.io:{}/profile", port);
    println!("Users URL: https://local.wavey.io:{}/users", port);

    let server = IdpServer::new(cert_pem, key_pem, port, creds);
    let shutdown_tx = server.start().await?;

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(());

    Ok(())
}
