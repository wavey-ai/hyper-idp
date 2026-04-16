use hyper_idp::server::{IdpCreds, IdpServer};
use std::env;
use url::Url;

fn issuer_url_from_redirect_uri(redirect_uri: &str) -> Option<String> {
    let url = Url::parse(redirect_uri).ok()?;
    let scheme = url.scheme();
    let host = url.host_str()?;

    let mut issuer = format!("{scheme}://{host}");
    if let Some(port) = url.port() {
        issuer.push(':');
        issuer.push_str(&port.to_string());
    }

    Some(issuer)
}

fn cookie_domain_from_issuer_url(issuer_url: &str) -> Option<String> {
    let url = Url::parse(issuer_url).ok()?;
    let host = url.host_str()?;

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 3 {
        return Some(format!(".{}", labels[1..].join(".")));
    }

    Some(host.to_string())
}

fn parse_csv_env(value: Option<String>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|raw| {
            raw.split(',')
                .map(str::trim)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|part| !part.is_empty())
        .collect()
}

fn parse_allowed_email_domains(value: Option<String>) -> Vec<String> {
    let domains = parse_csv_env(value);
    if domains.is_empty() {
        return vec!["wavey.ai".to_string()];
    }

    domains
        .into_iter()
        .map(|domain| domain.trim().trim_start_matches('@').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
        .collect()
}

fn internal_issuer_url(issuer_url: &str) -> String {
    format!("{}/internal", issuer_url.trim_end_matches('/'))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    // Load TLS certs from environment (base64 encoded)
    let cert_pem = env::var("CERT_PEM_BASE64").expect("CERT_PEM_BASE64 required");
    let key_pem = env::var("KEY_PEM_BASE64").expect("KEY_PEM_BASE64 required");

    // Load OAuth provider config
    let audience = env::var("OIDC_AUDIENCE").expect("OIDC_AUDIENCE required");
    let client_id = env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID required");
    let client_secret = env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET required");
    let redirect_uri =
        env::var("REDIRECT_URI").unwrap_or_else(|_| "https://idp.wavey.io/oauth2/callback".into());
    let issuer_url = env::var("ISSUER_URL")
        .ok()
        .or_else(|| issuer_url_from_redirect_uri(&redirect_uri))
        .unwrap_or_else(|| "https://idp.wavey.io".into());
    let cookie_domain = env::var("COOKIE_DOMAIN")
        .ok()
        .or_else(|| cookie_domain_from_issuer_url(&issuer_url))
        .unwrap_or_else(|| ".wavey.io".into());
    let local_client_id = env::var("LOCAL_OIDC_CLIENT_ID").unwrap_or(client_id.clone());
    let local_client_secret = env::var("LOCAL_OIDC_CLIENT_SECRET").unwrap_or(client_secret.clone());
    let local_token_ttl_secs = env::var("LOCAL_OIDC_TOKEN_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    let local_groups = parse_csv_env(env::var("LOCAL_OIDC_GROUPS").ok());
    let internal_issuer_url =
        env::var("INTERNAL_ISSUER_URL").unwrap_or_else(|_| internal_issuer_url(&issuer_url));
    let internal_client_id =
        env::var("INTERNAL_OIDC_CLIENT_ID").unwrap_or_else(|_| local_client_id.clone());
    let internal_client_secret =
        env::var("INTERNAL_OIDC_CLIENT_SECRET").unwrap_or_else(|_| local_client_secret.clone());
    let internal_token_ttl_secs = env::var("INTERNAL_OIDC_TOKEN_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(local_token_ttl_secs);
    let internal_groups = {
        let groups = parse_csv_env(env::var("INTERNAL_OIDC_GROUPS").ok());
        if groups.is_empty() {
            local_groups.clone()
        } else {
            groups
        }
    };

    let creds = IdpCreds {
        audience,
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
        redirect_uri,
        signing_cert: env::var("SIGNING_CERT_BASE64").unwrap_or_default(),
        issuer_url: issuer_url.clone(),
        internal_issuer_url: internal_issuer_url.clone(),
        local_client_id,
        local_client_secret,
        cookie_domain,
        local_token_ttl_secs,
        local_groups,
        internal_client_id,
        internal_client_secret,
        internal_token_ttl_secs,
        internal_groups,
        internal_allowed_email_domains: parse_allowed_email_domains(
            env::var("INTERNAL_ALLOWED_EMAIL_DOMAINS")
                .or_else(|_| env::var("ALLOWED_EMAIL_DOMAINS"))
                .ok(),
        ),
    };

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "443".into())
        .parse()
        .unwrap();

    tracing::info!("Starting IDP server on port {}", port);
    tracing::info!("Login URL: {}/login", creds.issuer_url);
    tracing::info!(
        "Public OIDC discovery URL: {}/.well-known/openid-configuration",
        creds.issuer_url
    );
    tracing::info!(
        "Internal OIDC discovery URL: {}/.well-known/openid-configuration",
        creds.internal_issuer_url
    );

    let server = IdpServer::new(cert_pem, key_pem, port, creds)?;
    let shutdown_tx = server.start().await?;

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");
    let _ = shutdown_tx.send(());

    Ok(())
}
