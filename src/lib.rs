use worker::*;

mod jwt;
mod rate_limit;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.path() == "/health" {
        return Response::ok("OK");
    }

    let ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".to_string());

    // Per-IP rate limiting via KV
    if let Ok(kv) = env.kv("RATE_LIMIT") {
        let max: u32 = env
            .var("RATE_LIMIT_MAX")
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(60);
        let window: u64 = env
            .var("RATE_LIMIT_WINDOW")
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(60);

        match rate_limit::check(&kv, &ip, max, window).await {
            Ok(false) => {
                return Response::error("Too Many Requests", 429);
            }
            Err(e) => {
                console_error!("rate_limit error: {e}");
                // fail open — don't block on KV errors
            }
            Ok(true) => {}
        }
    }

    // JWT validation on Authorization: Bearer <token>
    let token = match extract_bearer(req.headers()) {
        Some(t) => t,
        None => return Response::error("Unauthorized", 401),
    };

    let secret = env.secret("JWT_SECRET").ok().map(|s| s.to_string());
    let public_key = env.secret("JWT_PUBLIC_KEY").ok().map(|s| s.to_string());

    match jwt::validate(&token, secret.as_deref(), public_key.as_deref()) {
        Ok(claims) => {
            let body = serde_json::json!({ "ok": true, "sub": claims.sub });
            Response::from_json(&body)
        }
        Err(e) => {
            console_error!("jwt error: {e}");
            Response::error("Unauthorized", 401)
        }
    }
}

fn extract_bearer(headers: &Headers) -> Option<String> {
    parse_bearer(headers.get("Authorization").ok().flatten())
}

/// Pure helper — splits "Bearer <token>" from the raw header value.
/// Separated from `extract_bearer` so it can be unit-tested without the worker runtime.
fn parse_bearer(auth: Option<String>) -> Option<String> {
    auth.and_then(|h| h.strip_prefix("Bearer ").map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bearer_returns_none_when_no_header() {
        assert_eq!(parse_bearer(None), None);
    }

    #[test]
    fn parse_bearer_returns_none_for_basic_scheme() {
        assert_eq!(parse_bearer(Some("Basic dXNlcjpwYXNz".into())), None);
    }

    #[test]
    fn parse_bearer_returns_none_for_bearer_prefix_wrong_case() {
        assert_eq!(parse_bearer(Some("bearer my-token".into())), None);
    }

    #[test]
    fn parse_bearer_returns_token_for_valid_header() {
        assert_eq!(
            parse_bearer(Some("Bearer my-token-123".into())),
            Some("my-token-123".into())
        );
    }

    #[test]
    fn parse_bearer_preserves_token_with_internal_spaces() {
        // Unusual but shouldn't panic — JWT downstream will reject it
        assert_eq!(
            parse_bearer(Some("Bearer token with spaces".into())),
            Some("token with spaces".into())
        );
    }

    #[test]
    fn parse_bearer_returns_empty_string_for_bare_bearer() {
        // "Bearer " with nothing after — empty token; JWT validation rejects it downstream
        assert_eq!(parse_bearer(Some("Bearer ".into())), Some("".into()));
    }
}
