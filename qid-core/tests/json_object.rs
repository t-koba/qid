use axum::body::Body;
use axum::extract::FromRequest;
use axum::http::Request;
use qid_core::web::JsonObject;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Profile {
    id: Option<String>,
    email: String,
}

fn request(body: &'static str) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(body))
}

#[tokio::test]
async fn a_json_object_body_is_deserialized() {
    let parsed = JsonObject::<Profile>::from_request(
        request(r#"{"id":"given-id","email":"a@example.com"}"#).expect("the request is built"),
        &(),
    )
    .await
    .expect("an object body is accepted");
    assert_eq!(parsed.id.as_deref(), Some("given-id"));
    assert_eq!(parsed.email, "a@example.com");
}

#[tokio::test]
async fn a_json_array_body_is_rejected() {
    let error = JsonObject::<Profile>::from_request(
        request(r#"["chosen-id","a@example.com"]"#).expect("the request is built"),
        &(),
    )
    .await
    .expect_err("an array body is rejected");
    assert_eq!(error.status_code(), 400);
    assert!(
        error.message().contains("must be a JSON object"),
        "unexpected message: {}",
        error.message()
    );
}
