use worker::kv::KvStore;

/// Returns `true` if the request is allowed, `false` if the limit is exceeded.
/// Uses a sliding counter stored in Cloudflare KV with a TTL equal to `window_secs`.
pub async fn check(
    kv: &KvStore,
    ip: &str,
    max_requests: u32,
    window_secs: u64,
) -> worker::Result<bool> {
    let key = format!("rl:{ip}");

    let current: u32 = kv
        .get(&key)
        .text()
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if current >= max_requests {
        return Ok(false);
    }

    kv.put(&key, (current + 1).to_string())?
        .expiration_ttl(window_secs)
        .execute()
        .await?;

    Ok(true)
}
