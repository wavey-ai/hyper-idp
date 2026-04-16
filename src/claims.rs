use jsonwebtoken::{decode, errors::Result as JwtResult, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    claims: Claims,
    id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub id: u64,
}

impl User {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn subject(&self) -> Option<&str> {
        self.claims.sub.as_deref()
    }

    pub fn email(&self) -> Option<&str> {
        self.claims.email.as_deref()
    }

    pub fn email_verified(&self) -> bool {
        self.claims.email_verified.unwrap_or(true)
    }

    pub fn name(&self) -> Option<&str> {
        self.claims.name.as_deref()
    }

    pub fn picture(&self) -> Option<&str> {
        self.claims.picture.as_deref()
    }

    pub fn identity(&self) -> Result<UserIdentity, Box<dyn std::error::Error + Send + Sync>> {
        let email = self
            .email()
            .ok_or_else(|| "Email is missing in JWT claims".to_string())?;

        Ok(UserIdentity {
            subject: self
                .subject()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("wavey:{}", self.id)),
            email: email.to_string(),
            email_verified: self.email_verified(),
            name: self.name().map(str::to_owned),
            picture: self.picture().map(str::to_owned),
            id: self.id,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: Option<String>,
    exp: Option<usize>,
    email: Option<String>,
    email_verified: Option<bool>,
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
