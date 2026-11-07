mod common;

use common::{app, rt};
use serde_json::json;

#[test]
fn apple_form_post_reaches_broker_state_validation_without_cookies() {
    let app = app();
    rt().block_on(async {
        let server = app.server();
        let path = app.path("/broker/apple/endpoint");
        let response = server
            .post(&path)
            .add_header("Origin", "https://appleid.apple.com")
            .form(&[
                ("state", "unknown-state"),
                ("code", "test-code"),
                (
                    "user",
                    r#"{"name":{"firstName":"Ada"},"email":"untrusted@example.com"}"#,
                ),
            ])
            .await;
        // No cookie is required to parse Apple's callback; the server-side
        // transaction, not form profile data, must establish the login.
        let get = server
            .get(&path)
            .add_query_param("state", "unknown-state")
            .add_query_param("code", "test-code")
            .await;
        assert_eq!(
            response.status_code(),
            get.status_code(),
            "{}",
            response.text()
        );
        assert_eq!(
            response.json::<serde_json::Value>(),
            get.json::<serde_json::Value>()
        );
        assert!(response.status_code().is_client_error());
        assert!(!response.headers().contains_key("set-cookie"));
        let missing = server.post(&path).form(&[("code", "test-code")]).await;
        assert!(missing.status_code().is_client_error());
        let wrong_type = server
            .post(&path)
            .json(&json!({"state":"unknown-state", "code":"test-code"}))
            .await;
        assert_eq!(wrong_type.status_code(), 415);
    });
}
