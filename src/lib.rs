use worker::*;

mod jwt;
mod rate_limit;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
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

    let secret = env
        .secret("JWT_SECRET")
        .ok()
        .map(|s| s.to_string());
    let public_key = env
        .secret("JWT_PUBLIC_KEY")
        .ok()
        .map(|s| s.to_string());

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
    let auth = headers.get("Authorization").ok()??;
    auth.strip_prefix("Bearer ").map(|s| s.to_string())
}
