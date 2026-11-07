use chrono::{DateTime, TimeZone, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DbBackend, EntityTrait, QueryFilter, Statement, TransactionTrait,
};
use tracing::error;
use uuid::Uuid;

use crate::{
    domain::{
        common::{entities::app_errors::CoreError, generate_uuid_v7},
        crypto::HashResult,
        trident::{entities::MagicLink, ports::MagicLinkRepository},
    },
    entity::magic_links::{
        ActiveModel as MagicLinkActiveModel, Column as MagicLinkColumn, Entity as MagicLinkEntity,
        Model as MagicLinkModel,
    },
};

#[derive(Debug, Clone)]
pub struct PostgresMagicLinkRepository {
    pub db: DatabaseConnection,
}

impl PostgresMagicLinkRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl From<MagicLinkModel> for MagicLink {
    fn from(model: MagicLinkModel) -> Self {
        let created_at = Utc.from_utc_datetime(&model.created_at);
        let expires_at = Utc.from_utc_datetime(&model.expires_at);

        MagicLink {
            id: model.id,
            user_id: model.user_id,
            realm_id: model.realm_id,
            magic_token_id: model.token_id,
            magic_token_hash: model.token,
            created_at,
            expires_at,
            auth_session_code: model.auth_session_code,
        }
    }
}

impl MagicLinkRepository for PostgresMagicLinkRepository {
    async fn create_magic_link(
        &self,
        user_id: Uuid,
        realm_id: Uuid,
        token_id: Uuid,
        magic_token_hash: &HashResult,
        expires_at: DateTime<Utc>,
        auth_session_code: Option<Uuid>,
        email: String,
        provider_link: Option<crate::domain::abyss::identity_provider::broker::ProviderLinkIntent>,
    ) -> Result<(), CoreError> {
        // Extract token
        let magic_token_hash = &magic_token_hash.hash;
        if magic_token_hash.is_empty() {
            return Err(CoreError::InvalidMagicLink);
        }

        let active_model: MagicLinkActiveModel = MagicLinkActiveModel {
            id: Set(generate_uuid_v7()),
            user_id: Set(user_id),
            realm_id: Set(realm_id),
            token_id: Set(token_id),
            token: Set(magic_token_hash.to_string()),
            created_at: Set(Utc::now().naive_utc()),
            expires_at: Set(expires_at.naive_utc()),
            auth_session_code: Set(auth_session_code),
            email: Set(Some(email)),
            provider_link: Set(provider_link
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| CoreError::InvalidRequest)?),
        };

        active_model.insert(&self.db).await.map_err(|e| {
            error!("Failed to create magic link: {}", e);
            CoreError::InternalServerError
        })?;

        Ok(())
    }

    async fn get_by_token_id(&self, token_id: Uuid) -> Result<Option<MagicLink>, CoreError> {
        if token_id.is_nil() {
            return Err(CoreError::InvalidMagicLink);
        }

        let magic_link = MagicLinkEntity::find()
            .filter(MagicLinkColumn::TokenId.eq(token_id))
            .one(&self.db)
            .await
            .map_err(|e| {
                error!("Failed to get magic link by token_id: {}", e);
                CoreError::InternalServerError
            })?;

        Ok(magic_link.map(|ml| ml.into()))
    }

    async fn delete_by_token_id(&self, token_id: Uuid) -> Result<(), CoreError> {
        if token_id.is_nil() {
            return Err(CoreError::InvalidMagicLink);
        }

        MagicLinkEntity::delete_many()
            .filter(MagicLinkColumn::TokenId.eq(token_id))
            .exec(&self.db)
            .await
            .map_err(|e| {
                error!("Failed to delete magic link by token_id: {}", e);
                CoreError::InternalServerError
            })?;

        Ok(())
    }

    async fn consume(&self, token_id: Uuid) -> Result<bool, CoreError> {
        let tx = self
            .db
            .begin()
            .await
            .map_err(|_| CoreError::InternalServerError)?;
        // Use the same lock order as decline: session before token. The read
        // grants no authority; all values and expiry are checked after deletion.
        tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT a.id FROM auth_sessions a JOIN magic_links m ON m.auth_session_code = a.id WHERE m.token_id = $1 FOR UPDATE OF a",
            [token_id.into()])).await.map_err(|_| CoreError::InternalServerError)?;
        let rows = MagicLinkEntity::delete_many()
            .filter(MagicLinkColumn::TokenId.eq(token_id))
            .filter(MagicLinkColumn::ExpiresAt.gt(Utc::now().naive_utc()))
            .exec_with_returning(&tx)
            .await
            .map_err(|_| CoreError::InternalServerError)?;
        let Some(link) = rows.into_iter().next() else {
            return Ok(false);
        };
        let Some(email) = link.email else {
            return Ok(false);
        };
        if let Some(session_id) = link.auth_session_code {
            let session = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
                "SELECT id FROM auth_sessions WHERE id=$1 AND realm_id=$2 AND expires_at>now() AND authenticated=false AND code IS NULL AND (user_id IS NULL OR user_id=$3)",
                [session_id.into(), link.realm_id.into(), link.user_id.into()]))
                .await.map_err(|_| CoreError::InternalServerError)?;
            if session.is_none() {
                return Ok(false);
            }
        }
        if let Some(raw_intent) = link.provider_link {
            let intent: crate::domain::abyss::identity_provider::broker::ProviderLinkIntent =
                serde_json::from_value(raw_intent).map_err(|_| CoreError::InvalidMagicLink)?;
            if intent.user_id != link.user_id || intent.email != email {
                return Ok(false);
            }
            let Some(session_id) = link.auth_session_code else {
                return Ok(false);
            };
            // Lock all authority-bearing rows until the link write commits.
            let valid = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
                "SELECT u.id FROM users u JOIN auth_sessions a ON a.id = $1 AND a.realm_id = u.realm_id JOIN identity_providers p ON p.id = $2 AND p.realm_id = u.realm_id WHERE u.id = $3 AND u.realm_id = $4 AND u.email = $5 AND u.enabled = true AND (u.locked_until IS NULL OR u.locked_until <= now()) AND a.expires_at > now() AND a.authenticated = false AND a.code IS NULL AND a.user_id IS NULL AND p.enabled = true AND p.link_only = false FOR UPDATE OF u, a, p",
                [session_id.into(), intent.provider_id.into(), link.user_id.into(), link.realm_id.into(), email.clone().into()]))
                .await.map_err(|_| CoreError::InternalServerError)?;
            if valid.is_none() {
                return Ok(false);
            }
            let inserted = tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "INSERT INTO identity_provider_links (id, user_id, identity_provider_id, identity_provider_user_id, identity_provider_username, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,now(),now()) ON CONFLICT DO NOTHING",
                [generate_uuid_v7().into(), link.user_id.into(), intent.provider_id.into(), intent.external_id.into(), email.clone().into()]))
                .await.map_err(|_| CoreError::InternalServerError)?;
            if inserted.rows_affected() != 1 {
                return Ok(false);
            }
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE users SET firstname=COALESCE(firstname,$2), lastname=COALESCE(lastname,$3) WHERE id=$1",
                [link.user_id.into(), intent.given_name.into(), intent.family_name.into()]))
                .await.map_err(|_| CoreError::InternalServerError)?;
        }
        if let Some(session_id) = link.auth_session_code {
            tx.execute(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE auth_sessions SET user_id=$2 WHERE id=$1",
                [session_id.into(), link.user_id.into()],
            ))
            .await
            .map_err(|_| CoreError::InternalServerError)?;
        }
        {
            let changed = tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE users SET email_verified = true WHERE id = $1 AND email = $2 AND enabled = true",
                [link.user_id.into(), email.into()])).await.map_err(|_| CoreError::InternalServerError)?;
            if changed.rows_affected() != 1 {
                return Ok(false);
            }
        }
        tx.commit()
            .await
            .map_err(|_| CoreError::InternalServerError)?;
        Ok(true)
    }

    async fn decline_provider_link(
        &self,
        realm_id: Uuid,
        session_code: Uuid,
    ) -> Result<(), CoreError> {
        let tx = self
            .db
            .begin()
            .await
            .map_err(|_| CoreError::InternalServerError)?;
        // Lock the same session as redemption. A race has exactly one winner.
        let live = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT id FROM auth_sessions WHERE id = $1 AND realm_id = $2 AND authenticated = false AND code IS NULL AND user_id IS NULL FOR UPDATE",
            [session_code.into(), realm_id.into()])).await.map_err(|_| CoreError::InternalServerError)?;
        if live.is_some() {
            let removed = tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "DELETE FROM magic_links WHERE auth_session_code = $1 AND realm_id = $2 AND provider_link IS NOT NULL",
                [session_code.into(), realm_id.into()])).await.map_err(|_| CoreError::InternalServerError)?;
            if removed.rows_affected() > 0 {
                tx.execute(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "UPDATE auth_sessions SET expires_at = now() WHERE id = $1",
                    [session_code.into()],
                ))
                .await
                .map_err(|_| CoreError::InternalServerError)?;
            }
        }
        tx.commit()
            .await
            .map_err(|_| CoreError::InternalServerError)?;
        Ok(())
    }

    async fn cleanup_expired(&self, realm_id: Uuid) -> Result<(), CoreError> {
        let mut query = MagicLinkEntity::delete_many()
            .filter(MagicLinkColumn::ExpiresAt.lt(Utc::now().naive_utc()));

        query = query.filter(MagicLinkColumn::RealmId.eq(realm_id));

        query.exec(&self.db).await.map_err(|e| {
            error!("Failed to cleanup expired magic links: {}", e);
            CoreError::InternalServerError
        })?;

        Ok(())
    }
}
