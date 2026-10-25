use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use ferriskey_security::crypto::secret_cipher::SecretCipher;
use ferriskey_security::jwt::ports::{KeyRotation, KeyStoreRepository};
use sea_orm::{
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    Statement, TransactionTrait,
    sea_query::{Expr, OnConflict},
};
use uuid::Uuid;

use crate::domain::realm::entities::RealmId;
use crate::domain::{
    common::generate_uuid_v7,
    jwt::{
        JwtError,
        entities::{JwtKeyPair, SigningAlgorithm},
    },
};
use crate::entity::{jwt_keys, realm_settings, realms};

pub const PRIVATE_KEY_PURPOSE: &str = "jwt_keys.private_key";

const STATE_NEXT: &str = "next";
const STATE_ACTIVE: &str = "active";
const STATE_RETIRED: &str = "retired";

/// How long an instance trusts a key it has loaded before it asks the database
/// again.
///
/// A rotation made through this instance takes effect at once. On any other
/// instance it takes up to this long for signing to move to the new key, which
/// is harmless: the old key is retired, not deleted, and still verifies. For
/// verification there is no window to wait out: a `kid` this instance has not
/// seen is looked up in the database, so a token signed by a new key is
/// accepted everywhere immediately. The only stale reads are a retired key
/// that stays usable here for up to this long past its expiry, and an
/// unchanged answer for a key whose state changed elsewhere.
pub const KEY_CACHE_TTL: Duration = Duration::from_secs(60);

/// Whether the key belongs to the realm. A key verifies only in its own realm.
fn belongs_to(key: &JwtKeyPair, realm_id: Uuid) -> bool {
    key.realm_id == realm_id
}

struct Loaded<T> {
    value: T,
    loaded_at: Instant,
}

impl<T> Loaded<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            loaded_at: Instant::now(),
        }
    }

    fn fresh(&self, ttl: Duration) -> bool {
        self.loaded_at.elapsed() < ttl
    }
}

/// A key as loaded for verification: usable until `valid_until`, forever when
/// `None` (active and next keys).
#[derive(Clone)]
struct VerificationKey {
    pair: JwtKeyPair,
    valid_until: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct KeyCache {
    /// The active signing key of each realm.
    active: HashMap<Uuid, Loaded<JwtKeyPair>>,
    /// Keys by `kid`, with the realm they belong to.
    by_kid: HashMap<Uuid, Loaded<VerificationKey>>,
}

#[derive(Clone)]
pub struct PostgresKeyStoreRepository {
    pub db: DatabaseConnection,
    keys: Arc<RwLock<KeyCache>>,
    cache_ttl: Duration,
    cipher: SecretCipher,
}

impl fmt::Debug for PostgresKeyStoreRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresKeyStoreRepository")
            .field("db", &self.db)
            .finish_non_exhaustive()
    }
}

impl PostgresKeyStoreRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self::with_cipher(db, SecretCipher::disabled())
    }

    pub fn with_cipher(db: DatabaseConnection, cipher: SecretCipher) -> Self {
        Self {
            db,
            keys: Arc::new(RwLock::new(KeyCache::default())),
            cache_ttl: KEY_CACHE_TTL,
            cipher,
        }
    }

    /// Overrides how long loaded keys are trusted. For tests.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    fn private_key_of(&self, key: &jwt_keys::Model) -> Result<String, JwtError> {
        self.cipher
            .open(PRIVATE_KEY_PURPOSE, &key.id.to_string(), &key.private_key)
            .map_err(|error| JwtError::InvalidKey(error.to_string()))
    }

    fn cached_active(&self, realm_id: Uuid) -> Option<JwtKeyPair> {
        let cache = self.keys.read().ok()?;
        let entry = cache.active.get(&realm_id)?;
        entry.fresh(self.cache_ttl).then(|| entry.value.clone())
    }

    fn remember_active(&self, realm_id: Uuid, key: &JwtKeyPair) {
        if let Ok(mut cache) = self.keys.write() {
            cache.active.insert(realm_id, Loaded::new(key.clone()));
        }
    }

    /// `Some(answer)` when the cache can answer for `kid`, where the answer is
    /// `None` for a key that has expired.
    fn cached_verification_key(&self, realm_id: Uuid, kid: Uuid) -> Option<Option<JwtKeyPair>> {
        let cache = self.keys.read().ok()?;
        let entry = cache.by_kid.get(&kid)?;
        if !entry.fresh(self.cache_ttl) || !belongs_to(&entry.value.pair, realm_id) {
            return None;
        }
        let expired = entry
            .value
            .valid_until
            .is_some_and(|valid_until| valid_until <= Utc::now());

        Some((!expired).then(|| entry.value.pair.clone()))
    }

    fn remember_verification_key(&self, key: VerificationKey) {
        if let Ok(mut cache) = self.keys.write() {
            cache.by_kid.insert(key.pair.id, Loaded::new(key));
        }
    }

    /// Forgets everything held for the realm, after its keys changed here.
    fn forget_realm(&self, realm_id: Uuid) {
        if let Ok(mut cache) = self.keys.write() {
            cache.active.remove(&realm_id);
            cache
                .by_kid
                .retain(|_, entry| !belongs_to(&entry.value.pair, realm_id));
        }
    }

    async fn find_in_state(
        &self,
        realm_id: Uuid,
        state: &str,
    ) -> Result<Option<jwt_keys::Model>, JwtError> {
        jwt_keys::Entity::find()
            .filter(jwt_keys::Column::RealmId.eq(realm_id))
            .filter(jwt_keys::Column::State.eq(state))
            .one(&self.db)
            .await
            .map_err(|_| JwtError::RealmKeyNotFound)
    }

    async fn certificate_common_name(&self, realm_id: Uuid) -> Result<String, JwtError> {
        realms::Entity::find_by_id(realm_id)
            .one(&self.db)
            .await
            .map_err(|e| JwtError::GenerationError(e.to_string()))?
            .map(|realm| realm.name)
            .ok_or(JwtError::RealmKeyNotFound)
    }

    /// The type of key a new realm key should be: what the realm setting
    /// `default_signing_algorithm` asks for. It only applies when a key is
    /// generated; an existing key signs with the algorithm stored on its row.
    async fn algorithm_for_new_key(&self, realm_id: Uuid) -> Result<SigningAlgorithm, JwtError> {
        let setting = realm_settings::Entity::find()
            .filter(realm_settings::Column::RealmId.eq(realm_id))
            .one(&self.db)
            .await
            .map_err(|e| JwtError::GenerationError(e.to_string()))?;

        Ok(SigningAlgorithm::from_realm_setting(
            setting
                .as_ref()
                .and_then(|s| s.default_signing_algorithm.as_deref()),
        ))
    }

    /// How long after retirement a key can still be needed: the longest
    /// lifetime of any token the realm can issue, from the realm settings and
    /// the per-client overrides. A token signed just before retirement is dead
    /// by then, so the key can leave the JWKS and stop verifying.
    async fn token_horizon(&self, realm_id: Uuid) -> Result<chrono::Duration, JwtError> {
        let statement = Statement::from_sql_and_values(
            self.db.get_database_backend(),
            r#"
            SELECT GREATEST(
                COALESCE((SELECT MAX(GREATEST(
                    access_token_lifetime_secs, refresh_token_lifetime_secs,
                    id_token_lifetime_secs, temporary_token_lifetime_secs))
                  FROM realm_settings WHERE realm_id = $1), 0),
                COALESCE((SELECT MAX(GREATEST(
                    COALESCE(access_token_lifetime_secs, 0),
                    COALESCE(refresh_token_lifetime_secs, 0),
                    COALESCE(id_token_lifetime_secs, 0),
                    COALESCE(temporary_token_lifetime_secs, 0)))
                  FROM clients WHERE realm_id = $1), 0)
            )::BIGINT AS horizon
            "#,
            [realm_id.into()],
        );
        let seconds = self
            .db
            .query_one(statement)
            .await
            .map_err(|e| JwtError::GenerationError(e.to_string()))?
            .and_then(|row| row.try_get::<i64>("", "horizon").ok())
            .unwrap_or(0);

        Ok(chrono::Duration::seconds(seconds))
    }

    /// When a retired key stops verifying, as fixed at its retirement.
    fn retired_until(key: &jwt_keys::Model) -> Option<DateTime<Utc>> {
        key.verify_until
            .map(|until| DateTime::<Utc>::from_naive_utc_and_offset(until, Utc))
    }

    async fn insert_key(
        &self,
        realm_id: Uuid,
        state: &str,
        executor: &impl ConnectionTrait,
    ) -> Result<(), JwtError> {
        let common_name = self.certificate_common_name(realm_id).await?;
        let alg = self.algorithm_for_new_key(realm_id).await?;
        let (private_key, public_key) = JwtKeyPair::generate(alg)?;
        let certificate = JwtKeyPair::self_signed_certificate(&private_key, &common_name)?;

        let id = generate_uuid_v7();
        let sealed_private_key = self
            .cipher
            .seal(PRIVATE_KEY_PURPOSE, &id.to_string(), &private_key)
            .map_err(|error| JwtError::GenerationError(error.to_string()))?;

        let new_key = jwt_keys::ActiveModel {
            id: Set(id),
            realm_id: Set(realm_id),
            public_key: Set(public_key),
            private_key: Set(sealed_private_key),
            certificate: Set(Some(certificate)),
            kty: Set(alg.key_type().to_string()),
            alg: Set(alg.as_str().to_string()),
            state: Set(state.to_string()),
            retired_at: Set(None),
            verify_until: Set(None),
            created_at: Set(Utc::now().naive_utc()),
        };

        // A concurrent writer may have created the realm's active or next key
        // first: the partial unique indexes make that insert a no-op.
        jwt_keys::Entity::insert(new_key)
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .exec_without_returning(executor)
            .await
            .map_err(|e| JwtError::GenerationError(e.to_string()))?;

        Ok(())
    }

    async fn generate_active(&self, realm_id: Uuid) -> Result<jwt_keys::Model, JwtError> {
        self.insert_key(realm_id, STATE_ACTIVE, &self.db).await?;

        self.find_in_state(realm_id, STATE_ACTIVE)
            .await?
            .ok_or(JwtError::RealmKeyNotFound)
    }

    async fn backfill_certificate(
        &self,
        key: &jwt_keys::Model,
    ) -> Result<jwt_keys::Model, JwtError> {
        let common_name = self.certificate_common_name(key.realm_id).await?;
        let private_key = self.private_key_of(key)?;
        let certificate = JwtKeyPair::self_signed_certificate(&private_key, &common_name)?;

        jwt_keys::Entity::update_many()
            .col_expr(jwt_keys::Column::Certificate, Expr::value(certificate))
            .filter(jwt_keys::Column::Id.eq(key.id))
            .filter(jwt_keys::Column::Certificate.is_null())
            .exec(&self.db)
            .await
            .map_err(|e| JwtError::GenerationError(e.to_string()))?;

        jwt_keys::Entity::find_by_id(key.id)
            .one(&self.db)
            .await
            .map_err(|_| JwtError::RealmKeyNotFound)?
            .ok_or(JwtError::RealmKeyNotFound)
    }

    fn pair_of(&self, key: &jwt_keys::Model) -> Result<JwtKeyPair, JwtError> {
        let private_key = self.private_key_of(key)?;
        let alg = SigningAlgorithm::parse(&key.alg)?;

        JwtKeyPair::from_pem(
            alg,
            &private_key,
            &key.public_key,
            key.certificate.as_deref().unwrap_or_default(),
            key.realm_id,
            key.id,
        )
    }

    async fn rotation_of(&self, realm_id: Uuid) -> Result<KeyRotation, JwtError> {
        let active = self.find_in_state(realm_id, STATE_ACTIVE).await?;
        let next = self.find_in_state(realm_id, STATE_NEXT).await?;

        Ok(KeyRotation {
            active: active.ok_or(JwtError::RealmKeyNotFound)?.id,
            retired: None,
            next: next.map(|key| key.id),
        })
    }
}

impl KeyStoreRepository for PostgresKeyStoreRepository {
    async fn get_or_generate_key(&self, realm_id: RealmId) -> Result<JwtKeyPair, JwtError> {
        let realm_id: Uuid = realm_id.into();

        if let Some(key) = self.cached_active(realm_id) {
            return Ok(key);
        }

        let key = match self.find_in_state(realm_id, STATE_ACTIVE).await? {
            Some(key) => key,
            None => self.generate_active(realm_id).await?,
        };

        let key = if key.certificate.is_some() {
            key
        } else {
            self.backfill_certificate(&key).await?
        };

        let key_pair = self.pair_of(&key)?;
        self.remember_active(realm_id, &key_pair);
        self.remember_verification_key(VerificationKey {
            pair: key_pair.clone(),
            valid_until: None,
        });

        Ok(key_pair)
    }

    async fn get_verification_key(
        &self,
        realm_id: RealmId,
        kid: Uuid,
    ) -> Result<Option<JwtKeyPair>, JwtError> {
        let realm_id: Uuid = realm_id.into();

        if let Some(answer) = self.cached_verification_key(realm_id, kid) {
            return Ok(answer);
        }

        // Not held, or held too long ago: ask the database, which is also how
        // an instance learns of a key another instance just promoted.
        let Some(key) = jwt_keys::Entity::find_by_id(kid)
            .filter(jwt_keys::Column::RealmId.eq(realm_id))
            .one(&self.db)
            .await
            .map_err(|_| JwtError::RealmKeyNotFound)?
        else {
            return Ok(None);
        };

        let valid_until = match key.state.as_str() {
            STATE_RETIRED => Self::retired_until(&key),
            _ => None,
        };
        let pair = self.pair_of(&key)?;
        self.remember_verification_key(VerificationKey {
            pair: pair.clone(),
            valid_until,
        });

        let expired = valid_until.is_some_and(|valid_until| valid_until <= Utc::now());

        Ok((!expired).then_some(pair))
    }

    async fn published_keys(&self, realm_id: RealmId) -> Result<Vec<JwtKeyPair>, JwtError> {
        // A realm that has never issued a token still publishes its key.
        self.get_or_generate_key(realm_id).await?;
        let realm_id: Uuid = realm_id.into();

        let rows = jwt_keys::Entity::find()
            .filter(jwt_keys::Column::RealmId.eq(realm_id))
            .order_by_asc(jwt_keys::Column::CreatedAt)
            .all(&self.db)
            .await
            .map_err(|_| JwtError::RealmKeyNotFound)?;

        let now = Utc::now();
        let mut published = Vec::with_capacity(rows.len());
        for row in &rows {
            if row.state == STATE_RETIRED
                && Self::retired_until(row).is_none_or(|valid_until| valid_until <= now)
            {
                continue;
            }
            published.push((row.state == STATE_ACTIVE, self.pair_of(row)?));
        }
        // The key that signs first, then the rest in creation order.
        published.sort_by_key(|(active, _)| !*active);

        Ok(published.into_iter().map(|(_, pair)| pair).collect())
    }

    async fn stage_next_key(&self, realm_id: RealmId) -> Result<KeyRotation, JwtError> {
        let realm_id: Uuid = realm_id.into();
        // The realm needs an active key before it can have a next one.
        self.get_or_generate_key(RealmId::new(realm_id)).await?;

        if self.find_in_state(realm_id, STATE_NEXT).await?.is_none() {
            self.insert_key(realm_id, STATE_NEXT, &self.db).await?;
        }
        self.forget_realm(realm_id);

        self.rotation_of(realm_id).await
    }

    async fn rotate_key(&self, realm_id: RealmId) -> Result<KeyRotation, JwtError> {
        let realm_id: Uuid = realm_id.into();
        self.get_or_generate_key(RealmId::new(realm_id)).await?;

        let db_error = |e: sea_orm::DbErr| JwtError::GenerationError(e.to_string());
        // A key stays usable for as long as a token it signed can live, plus
        // the time another instance may keep signing with it from its cache.
        let retired_at = Utc::now();
        let verify_until = retired_at
            + self.token_horizon(realm_id).await?
            + chrono::Duration::from_std(self.cache_ttl).unwrap_or_default();
        let txn = self.db.begin().await.map_err(db_error)?;

        // One rotation at a time per realm.
        txn.execute(Statement::from_sql_and_values(
            txn.get_database_backend(),
            "SELECT id FROM realms WHERE id = $1 FOR UPDATE",
            [realm_id.into()],
        ))
        .await
        .map_err(db_error)?;

        let staged = jwt_keys::Entity::find()
            .filter(jwt_keys::Column::RealmId.eq(realm_id))
            .filter(jwt_keys::Column::State.eq(STATE_NEXT))
            .one(&txn)
            .await
            .map_err(db_error)?;
        if staged.is_none() {
            self.insert_key(realm_id, STATE_NEXT, &txn).await?;
        }
        let next = jwt_keys::Entity::find()
            .filter(jwt_keys::Column::RealmId.eq(realm_id))
            .filter(jwt_keys::Column::State.eq(STATE_NEXT))
            .one(&txn)
            .await
            .map_err(db_error)?
            .ok_or(JwtError::RealmKeyNotFound)?;
        let previous = jwt_keys::Entity::find()
            .filter(jwt_keys::Column::RealmId.eq(realm_id))
            .filter(jwt_keys::Column::State.eq(STATE_ACTIVE))
            .one(&txn)
            .await
            .map_err(db_error)?;

        // Retire first: at most one active key per realm at every instant.
        if let Some(previous) = &previous {
            jwt_keys::Entity::update_many()
                .col_expr(jwt_keys::Column::State, Expr::value(STATE_RETIRED))
                .col_expr(
                    jwt_keys::Column::RetiredAt,
                    Expr::value(retired_at.naive_utc()),
                )
                .col_expr(
                    jwt_keys::Column::VerifyUntil,
                    Expr::value(verify_until.naive_utc()),
                )
                .filter(jwt_keys::Column::Id.eq(previous.id))
                .exec(&txn)
                .await
                .map_err(db_error)?;
        }
        jwt_keys::Entity::update_many()
            .col_expr(jwt_keys::Column::State, Expr::value(STATE_ACTIVE))
            .filter(jwt_keys::Column::Id.eq(next.id))
            .exec(&txn)
            .await
            .map_err(db_error)?;

        txn.commit().await.map_err(db_error)?;
        self.forget_realm(realm_id);

        Ok(KeyRotation {
            active: next.id,
            retired: previous.map(|key| key.id),
            next: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database as SeaOrmDatabase;
    use sqlx::Executor as _;
    use x509_parser::pem::parse_x509_pem;

    struct Fixture {
        repository: PostgresKeyStoreRepository,
        pool: sqlx::PgPool,
    }

    async fn setup() -> Fixture {
        let base_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://ferriskey:ferriskey@localhost:5432/ferriskey".to_string()
        });

        let schema = format!("keystore_repository_test_{}", Uuid::new_v4().simple());

        let admin_pool = sqlx::PgPool::connect(&base_url)
            .await
            .expect("connect admin pool");
        admin_pool
            .execute(sqlx::query(&format!(r#"CREATE SCHEMA "{}""#, schema)))
            .await
            .expect("create test schema");

        let separator = if base_url.contains('?') { '&' } else { '?' };
        let schema_url = format!("{base_url}{separator}options=-c search_path={schema}");
        let pool = sqlx::PgPool::connect(&schema_url)
            .await
            .expect("connect schema pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("run migrations");

        let db = SeaOrmDatabase::connect(&schema_url)
            .await
            .expect("sea-orm connect");

        Fixture {
            repository: PostgresKeyStoreRepository::new(db),
            pool,
        }
    }

    async fn insert_realm(pool: &sqlx::PgPool, name: &str) -> RealmId {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO realms (id, name, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("insert realm");
        RealmId::new(id)
    }

    async fn count_keys(pool: &sqlx::PgPool, realm_id: RealmId) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM jwt_keys WHERE realm_id = $1")
            .bind(Uuid::from(realm_id))
            .fetch_one(pool)
            .await
            .expect("count keys")
    }

    fn common_name_of(certificate_pem: &str) -> String {
        let (_, pem) =
            parse_x509_pem(certificate_pem.as_bytes()).expect("certificate is valid PEM");
        pem.parse_x509()
            .expect("certificate is valid X.509")
            .subject()
            .to_string()
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_realm_key_is_generated_once_with_a_certificate_for_the_realm() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-alpha").await;

        let first = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");

        assert_eq!(common_name_of(&first.certificate), "CN=tenant-alpha");
        assert_eq!(count_keys(&fixture.pool, realm_id).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_realm_key_is_stable_across_calls() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-beta").await;

        let first = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");
        let second = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("read realm key");

        assert_eq!(first.id, second.id);
        assert_eq!(first.private_key, second.private_key);
        assert_eq!(first.certificate, second.certificate);
        assert_eq!(count_keys(&fixture.pool, realm_id).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_key_predating_certificates_is_backfilled_in_place() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-legacy").await;

        let (private_key, public_key) =
            JwtKeyPair::generate(SigningAlgorithm::Rs256).expect("generate legacy key");
        let legacy_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO jwt_keys (id, realm_id, private_key, public_key, created_at) \
             VALUES ($1, $2, $3, $4, NOW())",
        )
        .bind(legacy_id)
        .bind(Uuid::from(realm_id))
        .bind(&private_key)
        .bind(&public_key)
        .execute(&fixture.pool)
        .await
        .expect("insert legacy key");

        let key_pair = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("backfill certificate");

        assert_eq!(key_pair.id, legacy_id);
        assert_eq!(key_pair.private_key, private_key);
        assert_eq!(common_name_of(&key_pair.certificate), "CN=tenant-legacy");
        assert_eq!(count_keys(&fixture.pool, realm_id).await, 1);

        let persisted: Option<String> =
            sqlx::query_scalar("SELECT certificate FROM jwt_keys WHERE id = $1")
                .bind(legacy_id)
                .fetch_one(&fixture.pool)
                .await
                .expect("read back certificate");
        assert_eq!(persisted.as_deref(), Some(key_pair.certificate.as_str()));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn keys_of_two_realms_stay_distinct() {
        let fixture = setup().await;
        let alpha = insert_realm(&fixture.pool, "tenant-one").await;
        let beta = insert_realm(&fixture.pool, "tenant-two").await;

        let alpha_key = fixture
            .repository
            .get_or_generate_key(alpha)
            .await
            .expect("generate key for tenant-one");
        let beta_key = fixture
            .repository
            .get_or_generate_key(beta)
            .await
            .expect("generate key for tenant-two");

        assert_ne!(alpha_key.certificate, beta_key.certificate);
        assert_eq!(common_name_of(&alpha_key.certificate), "CN=tenant-one");
        assert_eq!(common_name_of(&beta_key.certificate), "CN=tenant-two");
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_loaded_key_is_served_from_memory_afterwards() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "cached").await;

        let first = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("first load");
        sqlx::query("DELETE FROM jwt_keys WHERE realm_id = $1")
            .bind(Uuid::from(realm_id))
            .execute(&fixture.pool)
            .await
            .expect("delete the stored key");

        let second = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("second load");

        assert_eq!(second.id, first.id);
        assert_eq!(count_keys(&fixture.pool, realm_id).await, 0);
    }

    const SEALING_KEY: &str = "kid-a:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    fn sealing(db: sea_orm::DatabaseConnection) -> PostgresKeyStoreRepository {
        PostgresKeyStoreRepository::with_cipher(
            db,
            ferriskey_security::crypto::secret_cipher::SecretCipher::from_config(SEALING_KEY)
                .expect("a valid key ring"),
        )
    }

    async fn stored_private_key(pool: &sqlx::PgPool, realm_id: RealmId) -> String {
        sqlx::query_scalar("SELECT private_key FROM jwt_keys WHERE realm_id = $1")
            .bind(Uuid::from(realm_id))
            .fetch_one(pool)
            .await
            .expect("read the stored key")
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn with_a_cipher_the_private_key_is_sealed_at_rest_and_still_usable() {
        let fixture = setup().await;
        let repository = sealing(fixture.repository.db.clone());
        let realm_id = insert_realm(&fixture.pool, "tenant-sealed").await;

        let key_pair = repository
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");

        let stored = stored_private_key(&fixture.pool, realm_id).await;
        assert!(stored.starts_with("fk1:kid-a:"), "{stored}");
        assert!(!stored.contains("PRIVATE KEY"));
        assert!(key_pair.private_key.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_sealed_key_is_read_back_by_another_instance_with_the_same_key() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-shared").await;

        let first = sealing(fixture.repository.db.clone())
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");
        let second = sealing(fixture.repository.db.clone())
            .get_or_generate_key(realm_id)
            .await
            .expect("read the sealed key");

        assert_eq!(first.private_key, second.private_key);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_plaintext_key_is_still_read_when_a_cipher_is_configured() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-plain").await;
        let (private_key, public_key) =
            JwtKeyPair::generate(SigningAlgorithm::Rs256).expect("generate legacy key");
        sqlx::query(
            "INSERT INTO jwt_keys (id, realm_id, private_key, public_key, certificate, created_at) \
             VALUES ($1, $2, $3, $4, $5, NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::from(realm_id))
        .bind(&private_key)
        .bind(&public_key)
        .bind(
            JwtKeyPair::self_signed_certificate(&private_key, "tenant-plain").expect("certificate"),
        )
        .execute(&fixture.pool)
        .await
        .expect("insert legacy key");

        let key_pair = sealing(fixture.repository.db.clone())
            .get_or_generate_key(realm_id)
            .await
            .expect("read the legacy key");

        assert_eq!(key_pair.private_key, private_key);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_sealed_key_is_refused_by_an_instance_without_a_cipher() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-locked").await;
        sealing(fixture.repository.db.clone())
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");

        let unaware = PostgresKeyStoreRepository::new(fixture.repository.db.clone());

        assert!(unaware.get_or_generate_key(realm_id).await.is_err());
    }

    async fn set_signing_algorithm(pool: &sqlx::PgPool, realm_id: RealmId, algorithm: &str) {
        sqlx::query("DELETE FROM realm_settings WHERE realm_id = $1")
            .bind(Uuid::from(realm_id))
            .execute(pool)
            .await
            .expect("clear the realm settings");
        sqlx::query(
            "INSERT INTO realm_settings (id, realm_id, default_signing_algorithm, updated_at) \
             VALUES ($1, $2, $3, NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::from(realm_id))
        .bind(algorithm)
        .execute(pool)
        .await
        .expect("set the realm signing algorithm");
    }

    async fn stored_type(pool: &sqlx::PgPool, realm_id: RealmId) -> (String, String) {
        sqlx::query_as("SELECT kty, alg FROM jwt_keys WHERE realm_id = $1")
            .bind(Uuid::from(realm_id))
            .fetch_one(pool)
            .await
            .expect("read the stored key type")
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_realm_without_a_signing_setting_gets_an_rsa_key() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-default").await;

        let key = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");

        assert_eq!(key.alg, SigningAlgorithm::Rs256);
        assert_eq!(
            stored_type(&fixture.pool, realm_id).await,
            ("RSA".to_string(), "RS256".to_string())
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn an_eddsa_realm_gets_an_ed25519_key_recorded_on_its_row() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-eddsa").await;
        set_signing_algorithm(&fixture.pool, realm_id, "EdDSA").await;

        let key = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");

        assert_eq!(key.alg, SigningAlgorithm::EdDsa);
        assert_eq!(common_name_of(&key.certificate), "CN=tenant-eddsa");
        assert_eq!(
            stored_type(&fixture.pool, realm_id).await,
            ("OKP".to_string(), "EdDSA".to_string())
        );

        let again = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("read realm key");
        assert_eq!(again.id, key.id);
        assert_eq!(again.alg, SigningAlgorithm::EdDsa);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn an_existing_key_keeps_its_algorithm_when_the_setting_changes() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-switch").await;
        set_signing_algorithm(&fixture.pool, realm_id, "RS256").await;

        let first = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");
        set_signing_algorithm(&fixture.pool, realm_id, "EdDSA").await;
        let second = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("read realm key");

        assert_eq!(first.id, second.id);
        assert_eq!(second.alg, SigningAlgorithm::Rs256);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_legacy_setting_value_still_yields_an_rsa_key() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-legacy-setting").await;
        set_signing_algorithm(&fixture.pool, realm_id, "RSA256").await;

        let key = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("generate realm key");

        assert_eq!(key.alg, SigningAlgorithm::Rs256);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_key_row_predating_the_algorithm_column_reads_as_rs256() {
        let fixture = setup().await;
        let realm_id = insert_realm(&fixture.pool, "tenant-prealg").await;

        let (private_key, public_key) =
            JwtKeyPair::generate(SigningAlgorithm::Rs256).expect("generate key");
        sqlx::query(
            "INSERT INTO jwt_keys (id, realm_id, private_key, public_key, created_at) \
             VALUES ($1, $2, $3, $4, NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::from(realm_id))
        .bind(&private_key)
        .bind(&public_key)
        .execute(&fixture.pool)
        .await
        .expect("insert a key without kty or alg");

        let key = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .expect("read realm key");

        assert_eq!(key.alg, SigningAlgorithm::Rs256);
    }

    // ---- rotation ---------------------------------------------------------

    async fn states(pool: &sqlx::PgPool, realm_id: RealmId) -> Vec<(Uuid, String)> {
        sqlx::query_as("SELECT id, state FROM jwt_keys WHERE realm_id = $1 ORDER BY created_at")
            .bind(Uuid::from(realm_id))
            .fetch_all(pool)
            .await
            .expect("read key states")
    }

    fn kids(keys: &[JwtKeyPair]) -> Vec<Uuid> {
        keys.iter().map(|key| key.id).collect()
    }

    /// A repository on the same database that trusts nothing it has loaded.
    fn uncached(fixture: &Fixture) -> PostgresKeyStoreRepository {
        PostgresKeyStoreRepository::new(fixture.repository.db.clone())
            .with_cache_ttl(Duration::ZERO)
    }

    async fn realm_with_settings(fixture: &Fixture, name: &str, algorithm: &str) -> RealmId {
        let realm_id = insert_realm(&fixture.pool, name).await;
        set_signing_algorithm(&fixture.pool, realm_id, algorithm).await;
        realm_id
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn rotation_promotes_a_new_key_and_retires_the_old_one() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "rotating", "RS256").await;
        let first = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();

        let outcome = fixture
            .repository
            .rotate_key(realm_id)
            .await
            .expect("rotate");

        assert_eq!(outcome.retired, Some(first.id));
        assert_ne!(outcome.active, first.id);
        assert_eq!(outcome.next, None);
        let signing = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();
        assert_eq!(signing.id, outcome.active, "the cache is dropped at once");
        let stored = states(&fixture.pool, realm_id).await;
        assert_eq!(
            stored,
            vec![
                (first.id, "retired".to_string()),
                (outcome.active, "active".to_string())
            ]
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_retired_key_keeps_verifying_and_stays_in_the_jwks() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "overlap", "RS256").await;
        let first = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();
        let outcome = fixture.repository.rotate_key(realm_id).await.unwrap();

        let old = fixture
            .repository
            .get_verification_key(realm_id, first.id)
            .await
            .unwrap();
        assert_eq!(old.map(|key| key.id), Some(first.id));
        let published = fixture.repository.published_keys(realm_id).await.unwrap();
        assert_eq!(kids(&published), vec![outcome.active, first.id]);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_retired_key_stops_verifying_once_its_tokens_have_expired() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "expiry", "RS256").await;
        let first = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();
        let outcome = fixture.repository.rotate_key(realm_id).await.unwrap();
        let repository = uncached(&fixture);

        // The window is the longest token lifetime of the realm (a day, for
        // refresh tokens by default) past retirement.
        let verify_until: chrono::NaiveDateTime =
            sqlx::query_scalar("SELECT verify_until FROM jwt_keys WHERE id = $1")
                .bind(first.id)
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        let retired_at: chrono::NaiveDateTime =
            sqlx::query_scalar("SELECT retired_at FROM jwt_keys WHERE id = $1")
                .bind(first.id)
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        let window = (verify_until - retired_at).num_seconds();
        assert!(
            (86_400..=86_400 + 61).contains(&window),
            "the longest default lifetime plus the cache ttl, got {window}s"
        );

        // Just inside the window: still honoured.
        sqlx::query(
            "UPDATE jwt_keys SET verify_until = NOW() + interval '5 seconds' WHERE id = $1",
        )
        .bind(first.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
        assert!(
            repository
                .get_verification_key(realm_id, first.id)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            kids(&repository.published_keys(realm_id).await.unwrap()),
            vec![outcome.active, first.id]
        );

        // Past it: refused, and gone from the JWKS.
        sqlx::query("UPDATE jwt_keys SET verify_until = NOW() - interval '1 second' WHERE id = $1")
            .bind(first.id)
            .execute(&fixture.pool)
            .await
            .unwrap();
        assert!(
            repository
                .get_verification_key(realm_id, first.id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            kids(&repository.published_keys(realm_id).await.unwrap()),
            vec![outcome.active]
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn the_window_follows_client_overrides_and_is_fixed_at_retirement() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "overrides", "RS256").await;
        fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();
        // A client may mint refresh tokens that live a week.
        sqlx::query(
            "INSERT INTO clients (id, realm_id, name, client_id, enabled, protocol, public_client, \
             service_account_enabled, client_type, direct_access_grants_enabled, \
             refresh_token_lifetime_secs, created_at, updated_at) \
             VALUES ($1, $2, 'c', 'c', true, 'openid-connect', false, false, 'confidential', true, \
             604800, NOW(), NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::from(realm_id))
        .execute(&fixture.pool)
        .await
        .expect("insert client");

        let outcome = fixture.repository.rotate_key(realm_id).await.unwrap();
        let retired = outcome.retired.expect("a key was retired");
        let window: i64 = sqlx::query_scalar(
            "SELECT EXTRACT(EPOCH FROM (verify_until - retired_at))::BIGINT FROM jwt_keys WHERE id = $1",
        )
        .bind(retired)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert!((604_800..=604_800 + 61).contains(&window), "{window}s");

        // Lowering lifetimes afterwards does not shorten what was promised.
        sqlx::query("UPDATE clients SET refresh_token_lifetime_secs = 1 WHERE realm_id = $1")
            .bind(Uuid::from(realm_id))
            .execute(&fixture.pool)
            .await
            .unwrap();
        assert!(
            uncached(&fixture)
                .get_verification_key(realm_id, retired)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn staging_publishes_the_next_key_without_changing_what_signs() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "staging", "RS256").await;
        let first = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();

        let staged = fixture.repository.stage_next_key(realm_id).await.unwrap();
        let again = fixture.repository.stage_next_key(realm_id).await.unwrap();

        assert_eq!(staged.active, first.id);
        assert_eq!(staged.next, again.next, "staging twice keeps one next key");
        let next = staged.next.expect("a next key");
        assert_eq!(
            fixture
                .repository
                .get_or_generate_key(realm_id)
                .await
                .unwrap()
                .id,
            first.id
        );
        assert_eq!(
            kids(&fixture.repository.published_keys(realm_id).await.unwrap()),
            vec![first.id, next]
        );
        assert!(
            fixture
                .repository
                .get_verification_key(realm_id, next)
                .await
                .unwrap()
                .is_some()
        );

        let rotated = fixture.repository.rotate_key(realm_id).await.unwrap();
        assert_eq!(rotated.active, next, "rotation promotes the staged key");
        assert_eq!(rotated.retired, Some(first.id));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_realm_moves_from_rs256_to_eddsa_by_rotating() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "migrating", "RS256").await;
        let rsa = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();
        assert_eq!(rsa.alg, SigningAlgorithm::Rs256);

        // Changing the setting alone changes nothing that exists.
        set_signing_algorithm(&fixture.pool, realm_id, "EdDSA").await;
        assert_eq!(
            uncached(&fixture)
                .get_or_generate_key(realm_id)
                .await
                .unwrap()
                .id,
            rsa.id
        );

        let outcome = fixture.repository.rotate_key(realm_id).await.unwrap();
        let signing = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();
        assert_eq!(signing.id, outcome.active);
        assert_eq!(signing.alg, SigningAlgorithm::EdDsa);

        let published = fixture.repository.published_keys(realm_id).await.unwrap();
        let algs: Vec<_> = published.iter().map(|key| key.alg).collect();
        assert_eq!(algs, vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Rs256]);
        // Each key verifies under its own algorithm.
        let old = fixture
            .repository
            .get_verification_key(realm_id, rsa.id)
            .await
            .unwrap()
            .expect("the RSA key still verifies");
        assert_eq!(old.alg, SigningAlgorithm::Rs256);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn an_unknown_kid_or_another_realms_kid_verifies_nothing() {
        let fixture = setup().await;
        let one = realm_with_settings(&fixture, "realm-one", "RS256").await;
        let two = realm_with_settings(&fixture, "realm-two", "RS256").await;
        let key_of_one = fixture.repository.get_or_generate_key(one).await.unwrap();
        fixture.repository.get_or_generate_key(two).await.unwrap();

        assert!(
            fixture
                .repository
                .get_verification_key(one, Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fixture
                .repository
                .get_verification_key(two, key_of_one.id)
                .await
                .unwrap()
                .is_none(),
            "a key verifies only in its own realm"
        );
        // Not even from the cache, once it has been loaded for its own realm.
        fixture
            .repository
            .get_verification_key(one, key_of_one.id)
            .await
            .unwrap();
        assert!(
            fixture
                .repository
                .get_verification_key(two, key_of_one.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn another_instance_verifies_a_new_key_at_once_and_signs_with_it_after_the_ttl() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "two-instances", "RS256").await;
        // Instance B has loaded the realm's key and trusts it for a minute.
        let b = PostgresKeyStoreRepository::new(fixture.repository.db.clone());
        let first = b.get_or_generate_key(realm_id).await.unwrap();

        // Instance A rotates.
        let outcome = fixture.repository.rotate_key(realm_id).await.unwrap();

        // B still signs with the old key, which is retired but valid: the only
        // staleness there is, bounded by the cache ttl.
        assert_eq!(b.get_or_generate_key(realm_id).await.unwrap().id, first.id);
        // B verifies a token signed by the new key straight away, because an
        // unknown kid is looked up rather than refused.
        assert_eq!(
            b.get_verification_key(realm_id, outcome.active)
                .await
                .unwrap()
                .map(|key| key.id),
            Some(outcome.active)
        );
        // And what B signed before it noticed still verifies on A.
        assert!(
            fixture
                .repository
                .get_verification_key(realm_id, first.id)
                .await
                .unwrap()
                .is_some()
        );

        // Once B's ttl is over it signs with the new key too.
        let b_later = PostgresKeyStoreRepository::new(fixture.repository.db.clone())
            .with_cache_ttl(Duration::ZERO);
        assert_eq!(
            b_later.get_or_generate_key(realm_id).await.unwrap().id,
            outcome.active
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn a_realm_has_at_most_one_active_and_one_next_key() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "unique", "RS256").await;
        fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();
        fixture.repository.stage_next_key(realm_id).await.unwrap();

        for state in ["active", "next"] {
            let (private_key, public_key) =
                JwtKeyPair::generate(SigningAlgorithm::Rs256).expect("generate key");
            let duplicate = sqlx::query(
                "INSERT INTO jwt_keys (id, realm_id, private_key, public_key, created_at, state) \
                 VALUES ($1, $2, $3, $4, NOW(), $5)",
            )
            .bind(Uuid::new_v4())
            .bind(Uuid::from(realm_id))
            .bind(&private_key)
            .bind(&public_key)
            .bind(state)
            .execute(&fixture.pool)
            .await;
            assert!(duplicate.is_err(), "a second {state} key must be refused");
        }
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn concurrent_rotations_never_leave_two_active_keys() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "racing", "RS256").await;
        fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();

        let a = fixture.repository.clone();
        let b = fixture.repository.clone();
        let (one, two) = tokio::join!(a.rotate_key(realm_id), b.rotate_key(realm_id));
        one.expect("first rotation");
        two.expect("second rotation");

        let stored = states(&fixture.pool, realm_id).await;
        assert_eq!(
            stored.iter().filter(|(_, state)| state == "active").count(),
            1
        );
        assert_eq!(stored.len(), 3, "two rotations retire two keys");
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-core -- --ignored"]
    async fn rotating_a_realm_without_a_key_creates_its_first() {
        let fixture = setup().await;
        let realm_id = realm_with_settings(&fixture, "fresh", "EdDSA").await;

        let outcome = fixture.repository.rotate_key(realm_id).await.unwrap();

        // The first key is made, then immediately rotated out.
        assert!(outcome.retired.is_some());
        let signing = fixture
            .repository
            .get_or_generate_key(realm_id)
            .await
            .unwrap();
        assert_eq!(signing.id, outcome.active);
        assert_eq!(signing.alg, SigningAlgorithm::EdDsa);
    }
}
