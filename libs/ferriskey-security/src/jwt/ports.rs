use chrono::{DateTime, Utc};
use ferriskey_domain::realm::{Realm, RealmId, scope::Unscoped};
use uuid::Uuid;

use crate::{
    SecurityError,
    jwt::{
        RefreshTokenHash,
        entities::{AccessToken, Jwt, JwtClaim, JwtKeyPair, RefreshToken},
    },
};

/// Result of an atomic rotate operation.
#[allow(clippy::large_enum_variant)]
pub enum RotateOutcome {
    /// The old token was atomically superseded; new token is returned.
    Rotated(RefreshToken),
    /// The conditional UPDATE matched 0 rows — a concurrent rotation already won.
    Conflict,
}

pub struct RefreshTokenSuccessor {
    pub jti: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    pub token_hash: Option<RefreshTokenHash>,
}

#[allow(clippy::large_enum_variant)]
pub enum ConsumeOutcome {
    Rotated {
        consumed: RefreshToken,
        successor: RefreshToken,
    },
    NotConsumed,
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
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        jti: Uuid,
        user_id: Uuid,
        expires_at: Option<DateTime<Utc>>,
        session_id: Option<Uuid>,
        resource: Option<String>,
        token_hash: Option<RefreshTokenHash>,
        client_id: Option<String>,
        scope: Option<String>,
    ) -> impl Future<Output = Result<RefreshToken, SecurityError>> + Send;

    /// Create a new refresh token that belongs to an existing token family.
    #[allow(clippy::too_many_arguments)]
    fn create_in_family(
        &self,
        jti: Uuid,
        user_id: Uuid,
        family_id: Uuid,
        expires_at: Option<DateTime<Utc>>,
        session_id: Option<Uuid>,
        resource: Option<String>,
        token_hash: Option<RefreshTokenHash>,
        client_id: Option<String>,
        scope: Option<String>,
    ) -> impl Future<Output = Result<RefreshToken, SecurityError>> + Send;

    fn get_by_jti(
        &self,
        jti: Uuid,
    ) -> impl Future<Output = Result<RefreshToken, SecurityError>> + Send;

    fn revoke_by_jti(&self, jti: Uuid) -> impl Future<Output = Result<(), SecurityError>> + Send;
    fn delete(&self, jti: Uuid) -> impl Future<Output = Result<(), SecurityError>> + Send;

    /// Atomically rotate the row `old_id` in place (WHERE jti = `old_jti` AND status='active'),
    /// keeping the superseded jti and hash as the row's previous token.
    ///
    /// Returns `RotateOutcome::Conflict` when 0 rows were updated, indicating a
    /// concurrent rotation already consumed this token.
    #[allow(clippy::too_many_arguments)]
    fn rotate(
        &self,
        old_id: Uuid,
        old_jti: Uuid,
        new_jti: Uuid,
        user_id: Uuid,
        family_id: Uuid,
        new_expires_at: Option<DateTime<Utc>>,
        token_hash: Option<RefreshTokenHash>,
        client_id: Option<String>,
        scope: Option<String>,
    ) -> impl Future<Output = Result<RotateOutcome, SecurityError>> + Send;

    fn consume_and_rotate(
        &self,
        hash: RefreshTokenHash,
        client_id: &str,
        successor: RefreshTokenSuccessor,
    ) -> impl Future<Output = Result<ConsumeOutcome, SecurityError>> + Send;

    fn get_by_hash(
        &self,
        hash: RefreshTokenHash,
    ) -> impl Future<Output = Result<Option<RefreshToken>, SecurityError>> + Send;

    fn revoke_by_hash(
        &self,
        hash: RefreshTokenHash,
        client_id: &str,
        realm_id: Uuid,
    ) -> impl Future<Output = Result<bool, SecurityError>> + Send;

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
    /// Notes that `client_id` holds tokens issued under `issuer` in the session, which
    /// is what back-channel logout notifies when the session ends. Recording the same
    /// participant again, or one for a session that is gone, changes nothing.
    fn record_session_participant(
        &self,
        realm_id: RealmId,
        session_id: Uuid,
        client_id: String,
        issuer: String,
    ) -> impl Future<Output = Result<(), SecurityError>> + Send;

    fn get_by_token_hash(
        &self,
        token_hash: String,
    ) -> impl Future<Output = Result<Option<Unscoped<AccessToken>>, SecurityError>> + Send;

    /// True when the token was revoked itself, issued before the second all of the
    /// user's tokens were revoked, or issued at or before the second all of its
    /// session's tokens were revoked. `iat` has whole-second resolution, so a token
    /// minted within the user-wide revocation second, before or after, is not caught.
    ///
    /// The cutoff is read from the database clock while `iat` comes from the
    /// issuer's, so a token never stored (client credentials) escapes the cutoff if
    /// its issuer's clock runs ahead of the database's by more than the time between
    /// issuance and revocation. Issuers must keep their clocks synchronised.
    fn is_revoked(
        &self,
        token_hash: String,
        user_id: Uuid,
        session_id: Option<Uuid>,
        issued_at: i64,
    ) -> impl Future<Output = Result<bool, SecurityError>> + Send;

    /// Marks the token revoked, recording it first when it was never persisted.
    fn revoke_by_token_hash(
        &self,
        token_hash: String,
        jti: Option<Uuid>,
        user_id: Uuid,
        realm_id: RealmId,
        expires_at: Option<DateTime<Utc>>,
        claims: serde_json::Value,
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
