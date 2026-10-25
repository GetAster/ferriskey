use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::generate_timestamp;
use crate::realm::RealmId;
use crate::realm::scope::RealmOwned;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TokenExchangePolicy {
    pub id: Uuid,
    pub realm_id: RealmId,
    pub client_id: Uuid,
    pub target_audience: String,
    pub allowed_scopes: Option<Vec<String>>,
    pub allow_impersonation: bool,
    pub allow_delegation: bool,
    /// The client may ask for a `cnf.jkt` confirmation claim on the issued
    /// token (`cnf_jkt`), and may exchange a subject token that carries one.
    #[serde(default)]
    pub allow_requested_cnf: bool,
    /// Together with `allow_delegation`: the client may name an actor it
    /// vouches for (`actor_assertion`) instead of presenting an actor token.
    #[serde(default)]
    pub allow_asserted_actor: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenExchangePolicyDefinition {
    pub target_audience: String,
    pub allowed_scopes: Option<Vec<String>>,
    pub allow_impersonation: bool,
    pub allow_delegation: bool,
    pub allow_requested_cnf: bool,
    pub allow_asserted_actor: bool,
}

impl TokenExchangePolicy {
    pub fn new(
        realm_id: RealmId,
        client_id: Uuid,
        definition: TokenExchangePolicyDefinition,
    ) -> Self {
        let (now, timestamp) = generate_timestamp();

        Self {
            id: Uuid::new_v7(timestamp),
            realm_id,
            client_id,
            target_audience: definition.target_audience,
            allowed_scopes: definition.allowed_scopes,
            allow_impersonation: definition.allow_impersonation,
            allow_delegation: definition.allow_delegation,
            allow_requested_cnf: definition.allow_requested_cnf,
            allow_asserted_actor: definition.allow_asserted_actor,
            created_at: now,
            updated_at: now,
        }
    }
}

impl RealmOwned for TokenExchangePolicy {
    fn realm_id(&self) -> RealmId {
        self.realm_id
    }
}
