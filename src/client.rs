use crate::claims::User;
use http::HeaderMap;
use reqwest::Client;
use std::error::Error;

pub async fn get_profile(
    client: Client,
    headers: &HeaderMap,
    port: u16,
) -> Result<User, Box<dyn Error + Send + Sync>> {
    let url = format!("https://local.wavey.io:{}/profile", port);

    let mut request = client.get(&url);

    for (key, value) in headers.iter() {
        request = request.header(key, value);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Request failed with status: {}", response.status()),
        )));
    }

    let user: User = response.json::<User>().await?;

    Ok(user)
}
