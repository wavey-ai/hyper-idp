use hyper_idp::server::{IdpCreds, IdpServer};
use std::fs;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "hyper-idp")]
struct Command {
    #[structopt(long, default_value = "4433", env = "SSL_PORT")]
    ssl_port: u16,

    #[structopt(long, env = "SSL_CERT_PATH")]
    ssl_cert_path: String,

    #[structopt(long, env = "OIDC_AUDIENCE")]
    oidc_audience: String,

    #[structopt(long, env = "OIDC_CLIENT_ID")]
    oidc_client_id: String,

    #[structopt(long, env = "OIDC_CLIENT_SECRET")]
    oidc_client_secret: String,

    #[structopt(long, env = "OIDC_REDIRECT_URI")]
    oidc_redirect_uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Command::from_args();

    let signing_cert: Vec<u8> =
        fs::read(format!("{}/{}", args.ssl_cert_path, "jwtkey.pem")).unwrap();

    let oidc_creds = IdpCreds {
        audience: args.oidc_audience,
        client_id: args.oidc_client_id,
        client_secret: args.oidc_client_secret,
        redirect_uri: args.oidc_redirect_uri,
        signing_cert,
    };

    let idp_server = IdpServer::new(args.ssl_cert_path.clone(), args.ssl_port, oidc_creds);
    let shutdown_idp = idp_server.start().await?;

    tokio::signal::ctrl_c().await?;

    println!("Shutdown signal received.");

    shutdown_idp.send(());

    Ok(())
}
