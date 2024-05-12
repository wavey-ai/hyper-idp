use jsonwebtoken::{decode, errors::Result as JwtResult, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    sub: String,
    exp: usize,
    email: String,
    name: String,
    picture: String,
}

pub(crate) fn decode_jwt(token: &str, public_key: &[u8], aud: &str) -> JwtResult<Claims> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[aud]);
    decode::<Claims>(
        token,
        &DecodingKey::from_rsa_pem(public_key).unwrap(),
        &validation,
    )
    .map(|data| data.claims)
}
