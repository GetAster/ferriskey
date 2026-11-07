use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DbBackend, EntityTrait, QueryFilter, Statement, TransactionTrait, sea_query::Expr,
};
use tracing::error;
use uuid::Uuid;

use crate::{
    domain::{
        common::entities::app_errors::CoreError,
        email_verification::{
            entities::EmailVerificationToken,
            ports::{CreateEmailVerificationTokenInput, EmailVerificationTokenRepository},
        },
        realm::entities::{Scoped, Unscoped},
        user::entities::User,
    },
    entity::email_verification_tokens::{
        ActiveModel as EvtActiveModel, Column as EvtColumn, Entity as EvtEntity, Model as EvtModel,
    },
};

#[derive(Debug, Clone)]
pub struct PostgresEmailVerificationTokenRepository {
    pub db: DatabaseConnection,
}

impl PostgresEmailVerificationTokenRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

impl From<EvtModel> for EmailVerificationToken {
    fn from(model: EvtModel) -> Self {
        let created_at: DateTime<Utc> = model.created_at.into();
        let expires_at: DateTime<Utc> = model.expires_at.into();
        let used_at: Option<DateTime<Utc>> = model.used_at.map(|t| t.into());

        EmailVerificationToken {
            id: model.id,
            user_id: model.user_id,
            realm_id: model.realm_id,
            token_hash: model.token_hash,
            email: model.email,
            created_at,
            expires_at,
            used_at,
        }
    }
}

impl EmailVerificationTokenRepository for PostgresEmailVerificationTokenRepository {
    async fn create(
        &self,
        input: CreateEmailVerificationTokenInput,
    ) -> Result<EmailVerificationToken, CoreError> {
        let id = Uuid::new_v4();
        let active_model = EvtActiveModel {
            id: Set(id),
            user_id: Set(input.user_id),
            realm_id: Set(input.realm_id),
            token_hash: Set(input.token_hash),
            email: Set(Some(input.email)),
            expires_at: Set(input.expires_at.fixed_offset()),
            created_at: Set(Utc::now().fixed_offset()),
            used_at: Set(None),
        };

        let model = active_model.insert(&self.db).await.map_err(|e| {
            error!("Failed to create email verification token: {}", e);
            CoreError::InternalServerError
        })?;

        Ok(model.into())
    }

    async fn find_valid_by_hash(
        &self,
        token_hash: &str,
        realm_id: Uuid,
    ) -> Result<Option<Unscoped<EmailVerificationToken>>, CoreError> {
        let now = Utc::now().fixed_offset();
        let model = EvtEntity::find()
            .filter(EvtColumn::TokenHash.eq(token_hash))
            .filter(EvtColumn::RealmId.eq(realm_id))
            .filter(EvtColumn::UsedAt.is_null())
            .filter(EvtColumn::ExpiresAt.gt(now))
            .one(&self.db)
            .await
            .map_err(|e| {
                error!("Failed to find email verification token: {}", e);
                CoreError::InternalServerError
            })?;

        Ok(model.map(|model| Unscoped::new(EmailVerificationToken::from(model))))
    }

    async fn find_by_hash(
        &self,
        token_hash: &str,
        realm_id: Uuid,
    ) -> Result<Option<Unscoped<EmailVerificationToken>>, CoreError> {
        let model = EvtEntity::find()
            .filter(EvtColumn::TokenHash.eq(token_hash))
            .filter(EvtColumn::RealmId.eq(realm_id))
            .one(&self.db)
            .await
            .map_err(|e| {
                error!("Failed to find email verification token by hash: {}", e);
                CoreError::InternalServerError
            })?;

        Ok(model.map(|model| Unscoped::new(EmailVerificationToken::from(model))))
    }

    async fn consume_and_verify(
        &self,
        token: &Scoped<EmailVerificationToken>,
    ) -> Result<bool, CoreError> {
        let record = token.get();
        let Some(email) = record
            .email
            .as_deref()
            .filter(|email| !email.trim().is_empty())
        else {
            return Ok(false);
        };
        let tx = self
            .db
            .begin()
            .await
            .map_err(|_| CoreError::InternalServerError)?;
        let consumed = tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE email_verification_tokens SET used_at = NOW() WHERE id = $1 AND realm_id = $2 AND user_id = $3 AND email = $4 AND token_hash = $5 AND used_at IS NULL AND expires_at > NOW()",
            [record.id.into(), record.realm_id.into(), record.user_id.into(), email.into(), record.token_hash.clone().into()]
        )).await.map_err(|_| CoreError::InternalServerError)?;
        if consumed.rows_affected() != 1 {
            return Ok(false);
        }
        let verified = tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE users SET email_verified = true WHERE id = $1 AND realm_id = $2 AND email = $3 AND enabled = true",
            [record.user_id.into(), record.realm_id.into(), email.into()]
        )).await.map_err(|_| CoreError::InternalServerError)?;
        if verified.rows_affected() != 1 {
            return Ok(false);
        }
        tx.commit()
            .await
            .map_err(|_| CoreError::InternalServerError)?;
        Ok(true)
    }

    async fn mark_used(&self, token: &Scoped<EmailVerificationToken>) -> Result<(), CoreError> {
        EvtEntity::update_many()
            .col_expr(
                EvtColumn::UsedAt,
                Expr::value(Some(Utc::now().fixed_offset())),
            )
            .filter(EvtColumn::Id.eq(token.get().id))
            .filter(EvtColumn::RealmId.eq(token.get().realm_id))
            .exec(&self.db)
            .await
            .map_err(|e| {
                error!("Failed to mark email verification token as used: {}", e);
                CoreError::InternalServerError
            })?;

        Ok(())
    }

    async fn delete_by_user_id(&self, user: &Scoped<User>) -> Result<u64, CoreError> {
        let result = EvtEntity::delete_many()
            .filter(EvtColumn::UserId.eq(user.get().id))
            .filter(EvtColumn::RealmId.eq::<Uuid>(user.get().realm_id.into()))
            .exec(&self.db)
            .await
            .map_err(|e| {
                error!("Failed to delete email verification tokens: {}", e);
                CoreError::InternalServerError
            })?;

        Ok(result.rows_affected)
    }
}
