use jsonwebtoken::{decode, errors::Result as JwtResult, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    claims: Claims,
    id: u64,
}

impl User {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn email(&self) -> Option<&str> {
        self.claims.email.as_deref()
    }

    pub fn name(&self) -> Option<&str> {
        self.claims.name.as_deref()
    }

    pub fn picture(&self) -> Option<&str> {
        self.claims.picture.as_deref()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: Option<String>,
    exp: Option<usize>,
    email: Option<String>,
    name: Option<String>,
    picture: Option<String>,
}

fn decode_jwt(token: &str, public_key: &[u8], aud: &str) -> JwtResult<Claims> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[aud]);
    decode::<Claims>(token, &DecodingKey::from_rsa_pem(public_key)?, &validation)
        .map(|data| data.claims)
}

pub fn get_user(
    token: &str,
    public_key: &[u8],
    aud: &str,
) -> Result<User, Box<dyn std::error::Error + Send + Sync>> {
    let claims = decode_jwt(token, public_key, aud)?;

    if let Some(email) = &claims.email {
        let id = const_xxh3(email.as_bytes());
        Ok(User { claims, id })
    } else {
        Err("Email is missing in JWT claims".into())
    }
}
