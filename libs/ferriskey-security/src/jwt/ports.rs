use chrono::{DateTime, Utc};
use ferriskey_domain::realm::{Realm, RealmId, scope::Unscoped};
use uuid::Uuid;

use crate::{
    SecurityError,
    jwt::entities::{AccessToken, Jwt, JwtClaim, JwtKeyPair, RefreshToken},
};

/// Result of an atomic rotate operation.
pub enum RotateOutcome {
    /// The old token was atomically superseded; new token is returned.
    Rotated(RefreshToken),
    /// The conditional UPDATE matched 0 rows — a concurrent rotation already won.
    Conflict,
}

pub trait JwtService: Send + Sync {
    fn generate_token(
        &self,
        claims: JwtClaim,
        realm_id: RealmId,
    ) -> impl Future<Output = Result<Jwt, SecurityError>> + Send;
    fn verify_token(
        &self,
        token: String,
        realm_id: RealmId,
    ) -> impl Future<Output = Result<JwtClaim, SecurityError>> + Send;
    fn verify_refresh_token(
        &self,
        token: String,
        realm_id: RealmId,
    ) -> impl Future<Output = Result<JwtClaim, SecurityError>> + Send;

    fn retrieve_realm_rsa_keys(
        &self,
        realm: &Realm,
    ) -> impl Future<Output = Result<JwtKeyPair, SecurityError>> + Send;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait RefreshTokenRepository: Send + Sync {
    fn create(
        &self,
        jti: Uuid,
        user_id: Uuid,
        expires_at: Option<DateTime<Utc>>,
        session_id: Option<Uuid>,
        resource: Option<String>,
    ) -> impl Future<Output = Result<RefreshToken, SecurityError>> + Send;

    /// Create a new refresh token that belongs to an existing token family.
    fn create_in_family(
        &self,
        jti: Uuid,
        user_id: Uuid,
        family_id: Uuid,
        expires_at: Option<DateTime<Utc>>,
        session_id: Option<Uuid>,
        resource: Option<String>,
    ) -> impl Future<Output = Result<RefreshToken, SecurityError>> + Send;

    fn get_by_jti(
        &self,
        jti: Uuid,
    ) -> impl Future<Output = Result<RefreshToken, SecurityError>> + Send;

    fn revoke_by_jti(&self, jti: Uuid) -> impl Future<Output = Result<(), SecurityError>> + Send;
    fn delete(&self, jti: Uuid) -> impl Future<Output = Result<(), SecurityError>> + Send;

    /// Atomically rotate `old_id` (WHERE status='active') and mint a successor.
    ///
    /// Returns `RotateOutcome::Conflict` when 0 rows were updated, indicating a
    /// concurrent rotation already consumed this token.
    fn rotate(
        &self,
        old_id: Uuid,
        new_jti: Uuid,
        user_id: Uuid,
        family_id: Uuid,
        new_expires_at: Option<DateTime<Utc>>,
    ) -> impl Future<Output = Result<RotateOutcome, SecurityError>> + Send;

    /// Revoke every token that shares the given family_id.
    fn revoke_family(
        &self,
        family_id: Uuid,
    ) -> impl Future<Output = Result<(), SecurityError>> + Send;

    fn revoke_by_session_id(
        &self,
        session_id: Uuid,
    ) -> impl Future<Output = Result<u64, SecurityError>> + Send;

    fn revoke_all_for_user(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<u64, SecurityError>> + Send;

    fn delete_expired(
        &self,
        before: DateTime<Utc>,
        limit: u64,
    ) -> impl Future<Output = Result<u64, SecurityError>> + Send;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait AccessTokenRepository: Send + Sync {
    fn create(
        &self,
        token_hash: String,
        jti: Option<Uuid>,
        user_id: Uuid,
        realm_id: RealmId,
        expires_at: Option<DateTime<Utc>>,
        claims: serde_json::Value,
    ) -> impl Future<Output = Result<AccessToken, SecurityError>> + Send;

    fn get_by_token_hash(
        &self,
        token_hash: String,
    ) -> impl Future<Output = Result<Option<Unscoped<AccessToken>>, SecurityError>> + Send;

    fn revoke_by_token_hash(
        &self,
        token_hash: String,
    ) -> impl Future<Output = Result<(), SecurityError>> + Send;

    fn revoke_by_session_id(
        &self,
        session_id: Uuid,
    ) -> impl Future<Output = Result<u64, SecurityError>> + Send;

    fn revoke_all_for_user(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<u64, SecurityError>> + Send;

    fn delete_expired(
        &self,
        before: DateTime<Utc>,
        limit: u64,
    ) -> impl Future<Output = Result<u64, SecurityError>> + Send;
}

/// What a rotation changed, by `kid`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct KeyRotation {
    /// The key that signs from now on.
    pub active: Uuid,
    /// The key that signed until now and keeps verifying until it is purged
    /// from the JWKS, if the realm had one.
    pub retired: Option<Uuid>,
    /// The staged key, if one is waiting for promotion.
    pub next: Option<Uuid>,
}

/// A realm's signing keys: one `active` key signs, an optional `next` key is
/// published ahead of promotion, and `retired` keys keep verifying (and stay in
/// the JWKS) until every token they could have signed has expired.
pub trait KeyStoreRepository: Send + Sync {
    /// The realm's active signing key, generated on first use.
    fn get_or_generate_key(
        &self,
        realm_id: RealmId,
    ) -> impl Future<Output = Result<JwtKeyPair, SecurityError>> + Send;

    /// The key with this `kid` if it may still verify tokens of the realm:
    /// active, next, or retired and not yet expired. `None` otherwise.
    fn get_verification_key(
        &self,
        realm_id: RealmId,
        kid: Uuid,
    ) -> impl Future<Output = Result<Option<JwtKeyPair>, SecurityError>> + Send;

    /// The keys the JWKS publishes: active, next, and retired keys that can
    /// still verify an unexpired token.
    fn published_keys(
        &self,
        realm_id: RealmId,
    ) -> impl Future<Output = Result<Vec<JwtKeyPair>, SecurityError>> + Send;

    /// Generates the `next` key, of the type the realm setting asks for, unless
    /// one is already staged. Does not change what signs.
    fn stage_next_key(
        &self,
        realm_id: RealmId,
    ) -> impl Future<Output = Result<KeyRotation, SecurityError>> + Send;

    /// Promotes `next` (staging it first when absent) to `active` and retires
    /// the previous active key.
    fn rotate_key(
        &self,
        realm_id: RealmId,
    ) -> impl Future<Output = Result<KeyRotation, SecurityError>> + Send;
}
