//! Trusted in-process access-token issuance. This is not a public grant endpoint.

use crate::application::services::ApplicationService;
use crate::domain::client::ports::ClientRepository;
use crate::domain::common::entities::app_errors::CoreError;
use crate::domain::jwt::entities::{ClaimsTyp, JwtClaim};
use crate::domain::realm::entities::RealmScope;
use crate::domain::realm::ports::RealmRepository;
use crate::domain::user::ports::UserRepository;
use chrono::Utc;
use ferriskey_domain::token_lifetime::TokenLifetimes;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum IssueAccessTokenError {
    #[error("Claim '{0}' collides with a protected or mapped claim")]
    ClaimsCollision(String),
    #[error("Confirmation must be a canonical SHA-256 JWK thumbprint")]
    InvalidConfirmation,
    #[error("Token lifetime and configured ceilings must be positive")]
    InvalidLifetime,
    #[error(transparent)]
    Core(#[from] CoreError),
}

/// Sender key binding already verified by the embedding application's proof checks.
#[derive(Clone, Debug)]
pub struct TokenConfirmation {
    pub jkt: String,
}

/// Inputs authorized by a trusted embedding application, not untrusted HTTP input.
#[derive(Clone, Debug)]
pub struct IssueAccessTokenInput {
    /// Canonical public base URL from trusted host configuration.
    pub base_url: String,
    pub realm_name: String,
    pub subject_id: Uuid,
    pub client_id: String,
    /// An enabled client in the same realm, whose protocol mappers shape the token.
    pub audience: String,
    /// Exact granted scopes; defaults are never added by this API.
    pub scope: String,
    pub confirmation: Option<TokenConfirmation>,
    pub additional_claims: HashMap<String, Value>,
    /// Positive requested lifetime, clamped to both clients' configured access-token ceilings.
    pub lifetime_seconds: i64,
}

#[derive(Clone, Debug)]
pub struct IssueAccessTokenOutput {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

// In addition to JwtClaim's fields, protect authentication, authorization and
// delegation statements. Delegated tokens must use the token exchange service.
const PROTECTED_CLAIMS: &[&str] = &[
    "sub",
    "iat",
    "jti",
    "iss",
    "typ",
    "azp",
    "aud",
    "scope",
    "exp",
    "nbf",
    "preferred_username",
    "email",
    "email_verified",
    "client_id",
    "sid",
    "cnf",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "aster_auth",
    "act",
    "may_act",
    "realm_access",
    "resource_access",
    "authorization",
    "roles",
    "groups",
    "at_hash",
    "c_hash",
];

fn normalized_scope(scope: &str) -> Result<String, CoreError> {
    let mut names: Vec<_> = scope.split_whitespace().collect();
    if names.contains(&"offline_access") {
        return Err(CoreError::InvalidScope(
            "Access-token-only issuance cannot grant offline_access".into(),
        ));
    }
    names.sort_unstable();
    names.dedup();
    Ok(names.join(" "))
}

fn merge_claims(
    mut mapped: HashMap<String, Value>,
    additional: HashMap<String, Value>,
    confirmation: Option<TokenConfirmation>,
) -> Result<HashMap<String, Value>, IssueAccessTokenError> {
    for name in additional.keys() {
        if name.is_empty() || PROTECTED_CLAIMS.contains(&name.as_str()) || mapped.contains_key(name)
        {
            return Err(IssueAccessTokenError::ClaimsCollision(name.to_string()));
        }
    }
    // Reserved structural/authentication claims must never enter serde's
    // flattened map. Identity and authorization mapper output remains valid.
    for name in [
        "sub",
        "iat",
        "jti",
        "iss",
        "typ",
        "azp",
        "aud",
        "scope",
        "exp",
        "nbf",
        "client_id",
        "sid",
        "cnf",
        "act",
        "may_act",
        "auth_time",
        "nonce",
        "acr",
        "amr",
        "aster_auth",
    ] {
        if mapped.contains_key(name) {
            return Err(IssueAccessTokenError::ClaimsCollision(name.to_string()));
        }
    }
    mapped.extend(additional);
    if let Some(confirmation) = confirmation {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        if confirmation.jkt.len() != 43
            || !URL_SAFE_NO_PAD
                .decode(&confirmation.jkt)
                .is_ok_and(|bytes| {
                    bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == confirmation.jkt
                })
        {
            return Err(IssueAccessTokenError::InvalidConfirmation);
        }
        mapped.insert("cnf".into(), serde_json::json!({"jkt": confirmation.jkt}));
    }
    Ok(mapped)
}

fn validate_subject(
    realm: &RealmScope,
    user: &crate::domain::user::entities::User,
    client: &crate::domain::client::entities::Client,
    target: &crate::domain::client::entities::Client,
) -> Result<(), CoreError> {
    if user.realm_id != realm.id()
        || client.realm_id != realm.id()
        || target.realm_id != realm.id()
        || !client.enabled
        || !target.enabled
        || !user.enabled
        || user.is_locked(Utc::now())
        || user
            .client_id
            .is_some_and(|id| id != client.id || !client.service_account_enabled)
    {
        return Err(CoreError::UnauthorizedClient(
            "Subject or client is not eligible for token issuance".into(),
        ));
    }
    Ok(())
}

fn effective_lifetime(
    requested: i64,
    requester_ceiling: i64,
    target_ceiling: i64,
) -> Result<i64, IssueAccessTokenError> {
    if requested <= 0 || requester_ceiling <= 0 || target_ceiling <= 0 {
        return Err(IssueAccessTokenError::InvalidLifetime);
    }
    Ok(requested.min(requester_ceiling).min(target_ceiling))
}

impl ApplicationService {
    /// Issue one sessionless access token after the host has authenticated the
    /// subject and authorized its audience, exact scope, extra assertions and
    /// sender-key binding. The host must perform its authority/proof checks on
    /// every call and supply its configured canonical public base URL.
    ///
    /// This API supplies no refresh token or delegation authority. FerrisKey
    /// rechecks realm membership, enabled state, service-account linkage,
    /// configured client scopes and token lifetime bounds before signing.
    pub async fn issue_subject_access_token(
        &self,
        input: IssueAccessTokenInput,
    ) -> Result<IssueAccessTokenOutput, IssueAccessTokenError> {
        let realm = RealmScope::resolve(
            self.realm_service.realm_repository.as_ref(),
            &input.realm_name,
        )
        .await?;
        let client = self
            .client_service
            .client_repository
            .get_by_client_id(input.client_id.clone(), realm.id())
            .await?
            .in_realm(&realm)?
            .into_inner();
        let target = self
            .client_service
            .client_repository
            .get_by_client_id(input.audience.clone(), realm.id())
            .await?
            .in_realm(&realm)?
            .into_inner();
        let user = self
            .user_service
            .user_repository
            .get_by_id(input.subject_id)
            .await?
            .in_realm(&realm)?
            .into_inner();
        validate_subject(&realm, &user, &client, &target)?;
        let settings = self
            .realm_service
            .realm_repository
            .get_realm_settings(realm.id())
            .await?
            .ok_or(CoreError::InternalServerError)?;
        if settings.passwordless_enabled
            && user.client_id.is_none()
            && (!user.email_verified
                || user
                    .email
                    .as_deref()
                    .is_none_or(|email| email.trim().is_empty()))
        {
            return Err(CoreError::Forbidden("Verified contact email is required".into()).into());
        }
        let lifetime = effective_lifetime(
            input.lifetime_seconds,
            TokenLifetimes::resolve(&settings, &client).access_token,
            TokenLifetimes::resolve(&settings, &target).access_token,
        )?;
        let scope = normalized_scope(&input.scope)?;
        self.auth_service
            .resolve_scopes_for_client(client.id, Some(scope.clone()))
            .await?;
        self.auth_service
            .resolve_scopes_for_client(target.id, Some(scope.clone()))
            .await?;
        let mapped = self
            .auth_service
            .exchange_mapped_claims(&realm, &user, &target, Some(scope.clone()))
            .await?;
        let additional_claims = merge_claims(mapped, input.additional_claims, input.confirmation)?;
        let now = Utc::now().timestamp();
        let exp = now.checked_add(lifetime).ok_or(CoreError::InvalidRequest)?;
        let claims = JwtClaim {
            sub: user.id,
            iat: now,
            jti: Uuid::new_v4(),
            iss: format!(
                "{}/realms/{}",
                input.base_url.trim_end_matches('/'),
                realm.name()
            ),
            typ: ClaimsTyp::Bearer,
            azp: client.client_id,
            aud: vec![target.client_id],
            scope: Some(scope.clone()),
            exp: Some(exp),
            preferred_username: None,
            email: None,
            client_id: None,
            sid: None,
            additional_claims,
        };
        let jwt = self
            .auth_service
            .issue_access_token(realm.id(), claims)
            .await?;
        Ok(IssueAccessTokenOutput {
            access_token: jwt.token,
            token_type: "Bearer".into(),
            expires_in: lifetime,
            scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::client::entities::Client;
    use crate::domain::common::services::tests::{
        create_test_realm_with_name, create_test_user_with_realm,
    };
    use serde_json::json;
    #[test]
    fn subject_and_client_eligibility_is_checked_before_signing() {
        let realm = create_test_realm_with_name("issuance");
        let scope = RealmScope::from_realm(realm.clone());
        let user = create_test_user_with_realm(&realm);
        let client = Client::from_realm_and_client_id(realm.id, "requester".into());
        let target = Client::from_realm_and_client_id(realm.id, "target".into());
        assert!(validate_subject(&scope, &user, &client, &target).is_ok());
        let mut disabled = user.clone();
        disabled.enabled = false;
        assert!(validate_subject(&scope, &disabled, &client, &target).is_err());
        let mut locked = user.clone();
        locked.locked_until = Some(Utc::now() + chrono::Duration::minutes(5));
        assert!(validate_subject(&scope, &locked, &client, &target).is_err());
        let mut wrong = user.clone();
        wrong.realm_id = create_test_realm_with_name("other").id;
        assert!(validate_subject(&scope, &wrong, &client, &target).is_err());
        let mut wrong_client = client.clone();
        wrong_client.realm_id = wrong.realm_id;
        assert!(validate_subject(&scope, &user, &wrong_client, &target).is_err());
        let mut wrong_target = target.clone();
        wrong_target.realm_id = wrong.realm_id;
        assert!(validate_subject(&scope, &user, &client, &wrong_target).is_err());
        let mut account = user.clone();
        account.client_id = Some(target.id);
        assert!(validate_subject(&scope, &account, &client, &target).is_err());
        account.client_id = Some(client.id);
        let mut service_client = client.clone();
        service_client.service_account_enabled = false;
        assert!(validate_subject(&scope, &account, &service_client, &target).is_err());
        service_client.service_account_enabled = true;
        assert!(validate_subject(&scope, &account, &service_client, &target).is_ok());
        for requester in [true, false] {
            let mut changed = client.clone();
            changed.enabled = false;
            let result = if requester {
                validate_subject(&scope, &user, &changed, &target)
            } else {
                validate_subject(&scope, &user, &client, &changed)
            };
            assert!(result.is_err());
        }
    }
    #[test]
    fn lifetime_cannot_exceed_either_client_policy() {
        for requested in [-1, 0] {
            assert!(effective_lifetime(requested, 300, 600).is_err());
        }
        assert_eq!(effective_lifetime(301, 600, 300).unwrap(), 300);
        assert_eq!(effective_lifetime(i64::MAX, 300, 600).unwrap(), 300);
        assert_eq!(effective_lifetime(30, 600, 300).unwrap(), 30);
    }
    #[test]
    fn invalid_binding_and_mapper_security_claims_are_rejected() {
        for jkt in [
            "",
            "abc",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            assert!(
                merge_claims(
                    HashMap::new(),
                    HashMap::new(),
                    Some(TokenConfirmation { jkt: jkt.into() })
                )
                .is_err()
            );
        }
        for claim in ["sid", "exp", "act", "cnf"] {
            assert!(
                merge_claims(
                    HashMap::from([(claim.into(), json!("forged"))]),
                    HashMap::new(),
                    None
                )
                .is_err()
            );
        }
        assert!(
            merge_claims(
                HashMap::new(),
                HashMap::from([("https://example.com/tenant".into(), json!("a"))]),
                None
            )
            .is_ok()
        );
    }
    #[test]
    fn unassigned_scope_is_refused_without_expanding_requested_scope() {
        use crate::domain::aegis::entities::ClientScopeSet;
        use crate::domain::authentication::scope::resolve_requested_scope;
        let scopes = ClientScopeSet::default();
        assert!(resolve_requested_scope(&scopes, Some("unassigned:admin")).is_err());
        let exact = normalized_scope("openid").unwrap();
        assert!(resolve_requested_scope(&scopes, Some(&exact)).is_ok());
        assert_eq!(exact, "openid");
    }
    #[test]
    fn exact_scopes_are_normalized_without_defaults() {
        assert_eq!(normalized_scope("read write read").unwrap(), "read write");
        assert_eq!(normalized_scope("").unwrap(), "");
        assert!(normalized_scope("read offline_access").is_err());
    }
    #[test]
    fn additional_claims_cannot_override_security_or_mapped_claims() {
        for name in PROTECTED_CLAIMS.iter().copied().chain([""]) {
            assert!(
                merge_claims(
                    HashMap::new(),
                    HashMap::from([(name.into(), json!("value"))]),
                    None
                )
                .is_err(),
                "{name}"
            );
        }
        assert!(
            merge_claims(
                HashMap::from([("tenant".into(), json!("a"))]),
                HashMap::from([("tenant".into(), json!("b"))]),
                None
            )
            .is_err()
        );
    }
    #[test]
    fn binding_is_explicit_and_custom_claims_are_preserved() {
        let claims = merge_claims(
            HashMap::new(),
            HashMap::from([("tenant".into(), json!("example"))]),
            Some(TokenConfirmation {
                jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            }),
        )
        .unwrap();
        assert_eq!(claims["tenant"], json!("example"));
        assert_eq!(
            claims["cnf"],
            json!({"jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
        );
        assert!(!claims.contains_key("act"));
    }
}
