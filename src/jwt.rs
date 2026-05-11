use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
}

#[derive(Debug)]
pub enum JwtError {
    MissingKey,
    Invalid(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKey => write!(f, "no JWT key configured"),
            Self::Invalid(msg) => write!(f, "invalid token: {msg}"),
        }
    }
}

/// Validate a JWT using HS256 (secret) or RS256 (PEM public key).
/// Exactly one of `secret` / `public_key` must be Some.
pub fn validate(
    token: &str,
    secret: Option<&str>,
    public_key: Option<&str>,
) -> Result<Claims, JwtError> {
    let (key, alg) = match (secret, public_key) {
        (Some(s), _) => (
            DecodingKey::from_secret(s.as_bytes()),
            Algorithm::HS256,
        ),
        (None, Some(pem)) => {
            let pem_bytes = pem.replace("\\n", "\n");
            let key = DecodingKey::from_rsa_pem(pem_bytes.as_bytes())
                .map_err(|e| JwtError::Invalid(e.to_string()))?;
            (key, Algorithm::RS256)
        }
        (None, None) => return Err(JwtError::MissingKey),
    };

    let mut validation = Validation::new(alg);
    validation.validate_exp = true;
    validation.leeway = 0; // no grace period — edge security must be strict

    let data = decode::<Claims>(token, &key, &validation)
        .map_err(|e| JwtError::Invalid(e.to_string()))?;

    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn make_hs256_token(secret: &str, sub: &str, exp_offset: i64) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = if exp_offset >= 0 {
            now + exp_offset as u64
        } else {
            now.saturating_sub((-exp_offset) as u64)
        };
        let claims = Claims { sub: sub.to_string(), exp, iat: Some(now) };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap()
    }

    #[test]
    fn valid_hs256_token_accepted() {
        let token = make_hs256_token("my-secret", "user-1", 3600);
        let claims = validate(&token, Some("my-secret"), None);
        assert!(claims.is_ok());
        assert_eq!(claims.unwrap().sub, "user-1");
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = make_hs256_token("correct", "user-1", 3600);
        let result = validate(&token, Some("wrong"), None);
        assert!(result.is_err());
    }

    #[test]
    fn missing_key_returns_error() {
        let result = validate("any.token.here", None, None);
        assert!(matches!(result, Err(JwtError::MissingKey)));
    }

    #[test]
    fn malformed_token_rejected() {
        let result = validate("not.a.jwt", Some("secret"), None);
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let token = make_hs256_token("secret", "user-2", -10);
        let result = validate(&token, Some("secret"), None);
        assert!(result.is_err(), "expired token must be rejected");
    }

    #[test]
    fn claims_sub_is_preserved() {
        let token = make_hs256_token("s", "alice@example.com", 3600);
        let claims = validate(&token, Some("s"), None).unwrap();
        assert_eq!(claims.sub, "alice@example.com");
    }

    #[test]
    fn token_without_iat_accepted() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = Claims { sub: "no-iat".to_string(), exp: now + 3600, iat: None };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"key"),
        )
        .unwrap();
        let result = validate(&token, Some("key"), None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "no-iat");
    }

    #[test]
    fn hs256_preferred_over_rs256_when_both_provided() {
        let token = make_hs256_token("hs-secret", "user-3", 3600);
        // When both keys are supplied, HS256 (secret) wins per the validate() contract
        let result = validate(&token, Some("hs-secret"), Some("not-a-pem"));
        assert!(result.is_ok(), "HS256 must be tried first when secret is present");
    }
}
