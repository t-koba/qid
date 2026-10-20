use super::*;
use http_body_util::BodyExt;

#[tokio::test]
async fn response_omits_next_cursor_for_overflow_zero_count_and_past_end() {
    for (start, count, total) in [(usize::MAX - 1, 200, 200), (0, 0, 1), (10, 1, 5)] {
        let response = Pagination {
            start,
            count,
            secret: "test-secret".to_string(),
            fingerprint: "filter".to_string(),
        }
        .response(total, Vec::new());
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect list response")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse list response");
        assert_eq!(body["startIndex"], serde_json::json!(start + 1));
        assert!(
            body.get("nextCursor").is_none(),
            "unexpected cursor for start={start}, count={count}, total={total}"
        );
    }
}
