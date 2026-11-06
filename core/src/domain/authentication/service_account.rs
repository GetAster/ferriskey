//! Trusted provisioning of a confidential client and its linked service account.

use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct EnsureServiceAccountInput {
    pub realm_name: String,
    /// Stable caller-chosen identifier matching `[a-z0-9-]{1,64}`.
    pub client_id: String,
    /// Display name used only when creating the client.
    pub name: String,
    /// Existing same-realm scopes to assign as optional scopes on creation.
    /// Subsequent calls validate these grants and never restore removed grants.
    pub allowed_scopes: Vec<String>,
    /// Immutable assertions stored on the new subject. Later calls compare
    /// requested keys and refuse missing or differing values without overwriting.
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnsureServiceAccountOutput {
    pub client_id: String,
    pub client_uuid: Uuid,
    pub subject_id: Uuid,
    pub created: bool,
    pub enabled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum EnsureServiceAccountError {
    #[error("Unknown realm")]
    UnknownRealm,
    #[error("Invalid service-account input: {0}")]
    InvalidInput(String),
    #[error("Existing service account is incompatible: {0}")]
    IncompatibleExisting(String),
    #[error("Existing service account lacks requested scopes: {missing:?}")]
    MissingScopes { missing: Vec<String> },
    #[error("Could not store or read service account")]
    Storage,
}

fn validate_input(input: &EnsureServiceAccountInput) -> Result<(), EnsureServiceAccountError> {
    let invalid = |message: &str| EnsureServiceAccountError::InvalidInput(message.into());
    if input.client_id.is_empty()
        || input.client_id.len() > 64
        || !input
            .client_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid("client_id must match [a-z0-9-]{1,64}"));
    }
    if input.name.trim().is_empty() || input.name.chars().count() > 255 {
        return Err(invalid("name must contain 1 to 255 characters"));
    }
    if input.allowed_scopes.iter().any(|scope| {
        scope.is_empty()
            || scope.chars().count() > 255
            || scope.chars().any(char::is_whitespace)
            || scope == "offline_access"
    }) {
        return Err(invalid(
            "scope names must be nonempty and cannot contain whitespace or grant offline_access",
        ));
    }
    if input
        .attributes
        .keys()
        .any(|key| key.is_empty() || key.chars().count() > 255)
    {
        return Err(invalid("attribute keys must contain 1 to 255 characters"));
    }
    Ok(())
}

impl crate::application::services::ApplicationService {
    /// Provision a client/subject atomically for a trusted embedding host.
    /// The caller owns enrollment authority; this API grants no user roles and
    /// never creates realm scopes. Clients have no stored or returned secret.
    /// Later calls never re-enable accounts, restore removed scope mappings,
    /// change display names, or overwrite immutable subject attributes. Existing
    /// clients carrying a secret are incompatible and are never adopted.
    pub async fn ensure_service_account(
        &self,
        input: EnsureServiceAccountInput,
    ) -> Result<EnsureServiceAccountOutput, EnsureServiceAccountError> {
        use crate::entity::{
            client_scope_mappings, client_scopes, clients, realms, user_attributes, users,
        };
        use sea_orm::{
            ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QuerySelect,
            TransactionTrait, sea_query::OnConflict,
        };
        use std::collections::BTreeSet;
        let storage = |_| EnsureServiceAccountError::Storage;
        let incompatible =
            |reason: &str| EnsureServiceAccountError::IncompatibleExisting(reason.into());
        validate_input(&input)?;
        let transaction = self
            .db
            .begin_with_config(Some(sea_orm::IsolationLevel::ReadCommitted), None)
            .await
            .map_err(storage)?;
        let realm = realms::Entity::find()
            .filter(realms::Column::Name.eq(&input.realm_name))
            .one(&transaction)
            .await
            .map_err(storage)?
            .ok_or(EnsureServiceAccountError::UnknownRealm)?;
        let mut scopes = Vec::new();
        for name in input.allowed_scopes.iter().collect::<BTreeSet<_>>() {
            let scope = client_scopes::Entity::find()
                .filter(client_scopes::Column::RealmId.eq(realm.id))
                .filter(client_scopes::Column::Name.eq(name.as_str()))
                .one(&transaction)
                .await
                .map_err(storage)?
                .ok_or_else(|| {
                    EnsureServiceAccountError::InvalidInput(format!(
                        "Unknown scope '{name}' in realm"
                    ))
                })?;
            if scope.protocol != "openid-connect" {
                return Err(EnsureServiceAccountError::InvalidInput(format!(
                    "Scope '{name}' is not an OpenID Connect scope"
                )));
            }
            scopes.push(scope);
        }
        let proposed_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        clients::Entity::insert(clients::ActiveModel {
            id: Set(proposed_id),
            realm_id: Set(realm.id),
            name: Set(input.name.clone()),
            client_id: Set(input.client_id.clone()),
            secret: Set(None),
            enabled: Set(true),
            protocol: Set("openid-connect".into()),
            public_client: Set(false),
            service_account_enabled: Set(true),
            client_type: Set("confidential".into()),
            created_at: Set(now.naive_utc()),
            updated_at: Set(now.naive_utc()),
            direct_access_grants_enabled: Set(Some(false)),
            oauth_device_code_grant_enabled: Set(Some(false)),
            token_exchange_enabled: Set(false),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::columns([clients::Column::ClientId, clients::Column::RealmId])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&transaction)
        .await
        .map_err(storage)?;
        // At READ COMMITTED this statement observes a concurrent winner after
        // ON CONFLICT waited for its commit; the lock serializes later ensures.
        let client = clients::Entity::find()
            .filter(clients::Column::RealmId.eq(realm.id))
            .filter(clients::Column::ClientId.eq(&input.client_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(storage)?
            .ok_or(EnsureServiceAccountError::Storage)?;
        let created = client.id == proposed_id;
        if client.secret.is_some()
            || !client.enabled
            || client.public_client
            || !client.service_account_enabled
            || client.client_type != "confidential"
            || client.protocol != "openid-connect"
        {
            return Err(incompatible(
                "client has a secret, is disabled, or is not a confidential OpenID Connect service-account client",
            ));
        }
        let subject = if created {
            users::ActiveModel {
                id: Set(Uuid::new_v4()),
                realm_id: Set(realm.id),
                client_id: Set(Some(client.id)),
                username: Set(format!("service-account-{}", input.client_id)),
                firstname: Set(Some("Service".into())),
                lastname: Set(Some("Account".into())),
                email: Set(None),
                email_verified: Set(false),
                enabled: Set(true),
                created_at: Set(now.naive_utc()),
                updated_at: Set(now.naive_utc()),
                failed_login_attempts: Set(0),
                locked_until: Set(None),
                locale: Set(None),
                federation_provider_id: Set(None),
            }
            .insert(&transaction)
            .await
            .map_err(|error| {
                if crate::infrastructure::common::is_unique_violation(&error) {
                    incompatible("subject identifier already exists")
                } else {
                    EnsureServiceAccountError::Storage
                }
            })?
        } else {
            users::Entity::find()
                .filter(users::Column::ClientId.eq(client.id))
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(storage)?
                .ok_or_else(|| incompatible("linked service-account subject is missing"))?
        };
        if subject.realm_id != realm.id
            || !subject.enabled
            || subject.locked_until.is_some_and(|until| until > now)
        {
            return Err(incompatible(
                "linked service-account subject is disabled, locked or in another realm",
            ));
        }
        if created {
            for scope in &scopes {
                client_scope_mappings::ActiveModel {
                    client_id: Set(client.id),
                    client_scope_id: Set(scope.id),
                    default_scope_type: Set(
                        ferriskey_aegis::entities::ScopeType::Optional.to_string()
                    ),
                }
                .insert(&transaction)
                .await
                .map_err(storage)?;
            }
            for (key, value) in &input.attributes {
                user_attributes::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    user_id: Set(subject.id),
                    realm_id: Set(realm.id),
                    key: Set(key.clone()),
                    value: Set(value.clone()),
                    created_at: Set(now.into()),
                    updated_at: Set(now.into()),
                }
                .insert(&transaction)
                .await
                .map_err(storage)?;
            }
        } else {
            let mappings = client_scope_mappings::Entity::find()
                .filter(client_scope_mappings::Column::ClientId.eq(client.id))
                .all(&transaction)
                .await
                .map_err(storage)?;
            let missing: Vec<String> = scopes
                .iter()
                .filter(|scope| {
                    !mappings.iter().any(|mapping| {
                        mapping.client_scope_id == scope.id
                            && matches!(
                                ferriskey_aegis::entities::ScopeType::from(
                                    mapping.default_scope_type.clone()
                                ),
                                ferriskey_aegis::entities::ScopeType::Optional
                                    | ferriskey_aegis::entities::ScopeType::Default
                            )
                    })
                })
                .map(|scope| scope.name.clone())
                .collect();
            if !missing.is_empty() {
                return Err(EnsureServiceAccountError::MissingScopes { missing });
            }
            let attributes = user_attributes::Entity::find()
                .filter(user_attributes::Column::UserId.eq(subject.id))
                .all(&transaction)
                .await
                .map_err(storage)?;
            for (key, value) in &input.attributes {
                if !attributes.iter().any(|attribute| {
                    attribute.realm_id == realm.id
                        && attribute.key == *key
                        && attribute.value == *value
                }) {
                    return Err(incompatible(
                        "requested immutable subject attribute is missing or differs",
                    ));
                }
            }
        }
        transaction.commit().await.map_err(storage)?;
        Ok(EnsureServiceAccountOutput {
            client_id: client.client_id,
            client_uuid: client.id,
            subject_id: subject.id,
            created,
            enabled: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(client_id: &str) -> EnsureServiceAccountInput {
        EnsureServiceAccountInput {
            realm_name: "realm".into(),
            client_id: client_id.into(),
            name: "Service account".into(),
            allowed_scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }
    #[test]
    fn caller_identifier_is_bounded_and_canonical() {
        for id in ["a", "node-123", &"a".repeat(64)] {
            assert!(validate_input(&input(id)).is_ok());
        }
        for id in [
            "",
            "Node",
            "under_score",
            "with space",
            "é",
            &"a".repeat(65),
        ] {
            assert!(validate_input(&input(id)).is_err());
        }
    }
    #[test]
    fn invalid_scope_or_attribute_rejects_whole_request() {
        for scope in ["", "read write", "offline_access"] {
            let mut request = input("node");
            request.allowed_scopes.push(scope.into());
            assert!(validate_input(&request).is_err());
        }
        let mut request = input("node");
        request.attributes.insert("".into(), "value".into());
        assert!(validate_input(&request).is_err());
    }
}
