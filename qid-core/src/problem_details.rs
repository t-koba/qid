//! RFC 9457 Problem Details.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
    pub instance: Option<String>,
}

impl ProblemDetails {
    pub fn new(status: u16, title: &str) -> Self {
        Self {
            type_: format!("https://qid.example.com/errors/{status:03}"),
            title: title.to_string(),
            status,
            detail: None,
            instance: None,
        }
    }

    pub fn with_detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_string());
        self
    }

    pub fn with_instance(mut self, instance: &str) -> Self {
        self.instance = Some(instance.to_string());
        self
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_details_serializes() {
        let pd = ProblemDetails::new(400, "Bad Request").with_detail("invalid grant");
        let json = pd.to_json();
        assert_eq!(json["status"], 400);
        assert_eq!(json["detail"], "invalid grant");
    }

    #[test]
    fn problem_details_has_type() {
        let pd = ProblemDetails::new(401, "Unauthorized");
        assert!(pd.type_.contains("/errors/"));
    }
}
