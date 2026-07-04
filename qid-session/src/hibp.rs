use sha1::{Digest, Sha1};

const HIBP_API_URL: &str = "https://api.pwnedpasswords.com/range/";

#[derive(Debug, Clone)]
pub struct HibpClient {
    client: reqwest::Client,
}

impl HibpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("qid/0.1")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest Client::builder() should not fail with default settings"),
        }
    }

    pub async fn check_password(&self, password: &str) -> anyhow::Result<bool> {
        let hash = hex::encode(Sha1::digest(password.as_bytes()));
        let (prefix, suffix) = hash.split_at(5);
        let url = format!("{HIBP_API_URL}{prefix}");
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("HIBP API request failed: {e}"))?;
        let body = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("HIBP API response read failed: {e}"))?;
        for line in body.lines() {
            if let Some(found_suffix) = line.split(':').next()
                && found_suffix.eq_ignore_ascii_case(suffix)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Default for HibpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_computation() {
        let hash = hex::encode(Sha1::digest(b"password"));
        assert_eq!(hash, "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
        let (prefix, _suffix) = hash.split_at(5);
        assert_eq!(prefix, "5baa6");
    }
}
