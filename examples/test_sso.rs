use hyper_idp::server::{IdpCreds, IdpServer};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let cert_pem = env::var("CERT_PEM_BASE64").expect("CERT_PEM_BASE64 required");
    let key_pem = env::var("KEY_PEM_BASE64").expect("KEY_PEM_BASE64 required");
    let redirect_uri = env::var("REDIRECT_URI")
        .unwrap_or_else(|_| "https://local.wavey.io:8443/oauth2/callback".into());
    let issuer_url =
        env::var("ISSUER_URL").unwrap_or_else(|_| "https://local.wavey.io:8443".into());
    let cookie_domain = env::var("COOKIE_DOMAIN").unwrap_or_else(|_| ".wavey.io".into());
    let local_client_id = env::var("LOCAL_OIDC_CLIENT_ID")
        .or_else(|_| env::var("AUTH0_CLIENT_ID"))
        .expect("LOCAL_OIDC_CLIENT_ID or AUTH0_CLIENT_ID required");
    let local_client_secret = env::var("LOCAL_OIDC_CLIENT_SECRET")
        .or_else(|_| env::var("AUTH0_CLIENT_SECRET"))
        .expect("LOCAL_OIDC_CLIENT_SECRET or AUTH0_CLIENT_SECRET required");

    let creds = IdpCreds {
        audience: env::var("AUTH0_DOMAIN").unwrap_or_else(|_| "your-tenant.auth0.com".into()),
        client_id: env::var("AUTH0_CLIENT_ID").expect("AUTH0_CLIENT_ID required"),
        client_secret: env::var("AUTH0_CLIENT_SECRET").expect("AUTH0_CLIENT_SECRET required"),
        redirect_uri,
        signing_cert: env::var("AUTH0_SIGNING_CERT_BASE64")
            .expect("AUTH0_SIGNING_CERT_BASE64 required"),
        issuer_url: issuer_url.clone(),
        local_client_id,
        local_client_secret,
        cookie_domain,
        local_token_ttl_secs: env::var("LOCAL_OIDC_TOKEN_TTL_SECS")
            .unwrap_or_else(|_| "3600".into())
            .parse()?,
        local_groups: env::var("LOCAL_OIDC_GROUPS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    };

    let port = env::var("SSO_PORT")
        .unwrap_or_else(|_| "8443".into())
        .parse()
        .unwrap();

    println!("Starting SSO server on port {}", port);
    println!("Issuer URL: {}", issuer_url);
    println!("Login URL: {issuer_url}/login");
    println!("Authorize URL: {issuer_url}/authorize");
    println!("Discovery URL: {issuer_url}/.well-known/openid-configuration");

    let server = IdpServer::new(cert_pem, key_pem, port, creds)?;
    let shutdown_tx = server.start().await?;

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(());

    Ok(())
}
