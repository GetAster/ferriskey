mod common;

use common::{ClientSpec, app, introspect, rt};
use ferriskey_api::issuance::{IssueAccessTokenError, IssueAccessTokenInput, TokenConfirmation};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

#[test]
fn trusted_issuance_signs_and_enforces_policy_against_database() {
    rt().block_on(async {
        let app = app();
        let server = app.server();
        let client = app
            .client(ClientSpec::confidential().with_service_account())
            .await;
        let target = app.client(ClientSpec::confidential()).await;
        let user = app.user(&server, "Issuance-Test-Passw0rd!").await;
        sqlx::query("UPDATE clients SET access_token_lifetime_secs = 120 WHERE id = $1")
            .bind(target.id)
            .execute(&app.pool)
            .await
            .unwrap();
        let input = IssueAccessTokenInput {
            base_url: "http://localhost:5555".into(),
            realm_name: app.realm.clone(),
            subject_id: Uuid::parse_str(&user.id).unwrap(),
            client_id: client.client_id.clone(),
            audience: target.client_id.clone(),
            scope: "openid".into(),
            lifetime_seconds: 600,
            confirmation: Some(TokenConfirmation {
                jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            }),
            additional_claims: HashMap::from([(
                "https://example.com/tenant".into(),
                json!("example"),
            )]),
        };
        let issued = app
            .service
            .issue_subject_access_token(input.clone())
            .await
            .unwrap();
        assert_eq!(issued.expires_in, 120);
        assert_eq!(issued.scope, "openid");
        let claims = common::decode_unverified(&issued.access_token);
        assert_eq!(claims["sub"], user.id);
        assert_eq!(claims["aud"], json!([target.client_id]));
        assert_eq!(claims["azp"], client.client_id);
        assert_eq!(claims["scope"], "openid");
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            120
        );
        assert_eq!(
            claims["cnf"]["jkt"],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(claims["https://example.com/tenant"], "example");
        // Introspection verifies the realm signature and expiry through the
        // native token path, independent of the unverified payload checks above.
        let inspected = introspect(&server, app, &client, &issued.access_token).await;
        assert_eq!(inspected["active"], true, "{inspected}");
        let mut invalid = input.clone();
        invalid.scope = "unassigned:admin".into();
        assert!(
            app.service
                .issue_subject_access_token(invalid)
                .await
                .is_err()
        );
        let mut invalid = input.clone();
        invalid
            .additional_claims
            .insert("exp".into(), json!(9999999999_i64));
        assert!(matches!(
            app.service.issue_subject_access_token(invalid).await,
            Err(IssueAccessTokenError::ClaimsCollision(_))
        ));
        app.set_client_enabled(&target, false).await;
        assert!(
            app.service
                .issue_subject_access_token(input.clone())
                .await
                .is_err()
        );
        app.set_client_enabled(&target, true).await;
        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
            .bind(input.subject_id)
            .execute(&app.pool)
            .await
            .unwrap();
        assert!(
            app.service
                .issue_subject_access_token(input.clone())
                .await
                .is_err()
        );
        sqlx::query("UPDATE users SET enabled = true, client_id = $2 WHERE id = $1")
            .bind(input.subject_id)
            .bind(target.id)
            .execute(&app.pool)
            .await
            .unwrap();
        assert!(
            app.service
                .issue_subject_access_token(input.clone())
                .await
                .is_err()
        );
        sqlx::query("UPDATE users SET client_id = $2 WHERE id = $1")
            .bind(input.subject_id)
            .bind(client.id)
            .execute(&app.pool)
            .await
            .unwrap();
        assert!(
            app.service
                .issue_subject_access_token(input.clone())
                .await
                .is_ok()
        );
        let (other_realm, _) = app.create_realm().await;
        let mut invalid = input;
        invalid.realm_name = other_realm;
        assert!(
            app.service
                .issue_subject_access_token(invalid)
                .await
                .is_err()
        );
    });
}
