use std::sync::Arc;

use crate::domain::authentication::services::sso_token_hash;
use ferriskey_domain::realm::scope::{RealmScope, Scoped, Unscoped};
use ferriskey_domain::session::ports::UserSessionRepository;
use ferriskey_domain::user::entities::User;
use ferriskey_security::jwt::ports::{AccessTokenRepository, RefreshTokenRepository};
use subtle::ConstantTimeEq;
use tracing::warn;
use uuid::Uuid;

use crate::domain::account_security::ports::OtherSessionsRevocationPort;
use crate::domain::common::entities::app_errors::CoreError;

#[derive(Clone, Debug)]
pub struct OtherSessionsRevocationAdapter<A, R, S>
where
    A: AccessTokenRepository,
    R: RefreshTokenRepository,
    S: UserSessionRepository,
{
    access_token_repository: Arc<A>,
    refresh_token_repository: Arc<R>,
    session_repository: Arc<S>,
}

impl<A, R, S> OtherSessionsRevocationAdapter<A, R, S>
where
    A: AccessTokenRepository,
    R: RefreshTokenRepository,
    S: UserSessionRepository,
{
    pub fn new(
        access_token_repository: Arc<A>,
        refresh_token_repository: Arc<R>,
        session_repository: Arc<S>,
    ) -> Self {
        Self {
            access_token_repository,
            refresh_token_repository,
            session_repository,
        }
    }
}

impl<A, R, S> OtherSessionsRevocationPort for OtherSessionsRevocationAdapter<A, R, S>
where
    A: AccessTokenRepository,
    R: RefreshTokenRepository,
    S: UserSessionRepository,
{
    async fn authenticated_at(
        &self,
        scope: &RealmScope,
        user: &Scoped<User>,
        session_id: Uuid,
        sso_cookie: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, CoreError> {
        let Some(session) = self
            .session_repository
            .find_by_id(session_id)
            .await
            .map_err(|_| CoreError::InternalServerError)?
        else {
            return Ok(None);
        };
        let session = session.in_realm(scope)?;
        let session = session.get();
        if session.id != session_id || session.user_id != user.get().id || session.is_expired() {
            return Ok(None);
        }
        let presented_hash = sso_token_hash(sso_cookie);
        if sso_cookie.is_empty()
            || !session.sso_token_hash.as_deref().is_some_and(|stored| {
                bool::from(stored.as_bytes().ct_eq(presented_hash.as_bytes()))
            })
        {
            return Ok(None);
        }
        Ok(Some(session.authenticated_at))
    }

    async fn revoke_all_sessions_except(
        &self,
        scope: &RealmScope,
        user: &Scoped<User>,
        keep_session_id: Option<Uuid>,
    ) -> Result<(), CoreError> {
        let user_id = user.get().id;
        let realm_id = Uuid::from(scope.id());

        let sessions = self
            .session_repository
            .find_all_by_user_and_realm(user_id, realm_id)
            .await
            .map_err(|e| {
                warn!(%user_id, "failed to list sessions to revoke: {e:?}");
                CoreError::InternalServerError
            })?;

        let mut revoked = 0usize;
        let mut kept = 0usize;

        for session in sessions {
            if Some(session.id) == keep_session_id {
                kept += 1;
                continue;
            }

            let session_id = session.id;
            let scoped = Unscoped::new(session).in_realm(scope)?;

            // Cut the SSO secret first: while it resolves, `/auth` can mint
            // tokens bound to this session that the revocation below would miss.
            if let Err(e) = self.session_repository.clear_sso_token_hash(&scoped).await {
                warn!(%user_id, %session_id, "failed to cut the SSO secret: {e:?}");
                return Err(CoreError::InternalServerError);
            }

            if let Err(e) = self
                .refresh_token_repository
                .revoke_by_session_id(session_id)
                .await
            {
                warn!(%user_id, %session_id, "failed to revoke refresh tokens: {e:?}");
                return Err(CoreError::InternalServerError);
            }

            if let Err(e) = self
                .access_token_repository
                .revoke_by_session_id(session_id)
                .await
            {
                warn!(%user_id, %session_id, "failed to revoke access tokens: {e:?}");
                return Err(CoreError::InternalServerError);
            }

            if let Err(e) = self.session_repository.delete(&scoped).await {
                warn!(
                    %user_id, %session_id,
                    "tokens are revoked but the session row could not be deleted: {e:?}"
                );
            }

            revoked += 1;
        }

        tracing::debug!(%user_id, revoked, kept, "other sessions revoked");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use ferriskey_domain::realm::{Realm, RealmId};
    use ferriskey_domain::session::entities::{SessionError, UserSession};
    use ferriskey_domain::session::ports::MockUserSessionRepository;
    use ferriskey_security::jwt::ports::{MockAccessTokenRepository, MockRefreshTokenRepository};
    use std::sync::Mutex;

    fn session(user_id: Uuid, realm_id: Uuid) -> UserSession {
        UserSession {
            id: Uuid::now_v7(),
            user_id,
            realm_id,
            user_agent: None,
            ip_address: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            last_seen_at: None,
            soft_expiry_duration: None,
            sso_token_hash: None,
            persistent: false,
            authenticated_at: chrono::Utc::now(),
        }
    }

    fn scope_of(realm_id: Uuid) -> RealmScope {
        let mut realm = Realm::new("acme".to_string());
        realm.id = RealmId::new(realm_id);
        RealmScope::from_realm(realm)
    }

    fn scoped_user(user_id: Uuid, realm_id: Uuid, scope: &RealmScope) -> Scoped<User> {
        let mut realm = Realm::new("acme".to_string());
        realm.id = RealmId::new(realm_id);

        let user = User {
            id: user_id,
            realm_id: RealmId::new(realm_id),
            realm: Some(realm),
            username: "alice".to_string(),
            email: None,
            client_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            enabled: true,
            email_verified: true,
            firstname: None,
            lastname: None,
            required_actions: Vec::new(),
            roles: Some(Vec::new()),
            failed_login_attempts: 0,
            locked_until: None,
            locale: None,
            federation_provider_id: None,
        };

        Unscoped::new(user)
            .in_realm(scope)
            .expect("a user of the scoped realm must be accepted")
    }

    #[tokio::test]
    async fn the_kept_session_survives_and_every_other_one_is_dropped() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let scope = scope_of(realm_id);
        let user = scoped_user(user_id, realm_id, &scope);

        let kept = session(user_id, realm_id);
        let doomed_a = session(user_id, realm_id);
        let doomed_b = session(user_id, realm_id);
        let kept_id = kept.id;
        let doomed = [doomed_a.id, doomed_b.id];

        let mut sessions = MockUserSessionRepository::new();
        let all = vec![kept, doomed_a, doomed_b];
        sessions
            .expect_find_all_by_user_and_realm()
            .returning(move |_, _| {
                let all = all.clone();
                Box::pin(async move { Ok(all) })
            });

        let cut = Arc::new(Mutex::new(Vec::new()));
        let cut_recorder = Arc::clone(&cut);
        sessions
            .expect_clear_sso_token_hash()
            .returning(move |session| {
                cut_recorder
                    .lock()
                    .expect("the cut recorder must not be poisoned")
                    .push(session.get().id);
                Box::pin(async move { Ok(()) })
            });

        let deleted = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&deleted);
        sessions.expect_delete().returning(move |session| {
            recorder
                .lock()
                .expect("the delete recorder must not be poisoned")
                .push(session.get().id);
            Box::pin(async move { Ok(()) })
        });

        let mut access = MockAccessTokenRepository::new();
        access
            .expect_revoke_by_session_id()
            .times(2)
            .returning(|_| Box::pin(async { Ok(1) }));

        let mut refresh = MockRefreshTokenRepository::new();
        refresh
            .expect_revoke_by_session_id()
            .times(2)
            .returning(|_| Box::pin(async { Ok(1) }));

        let adapter = OtherSessionsRevocationAdapter::new(
            Arc::new(access),
            Arc::new(refresh),
            Arc::new(sessions),
        );

        adapter
            .revoke_all_sessions_except(&scope, &user, Some(kept_id))
            .await
            .expect("revoking the other sessions must succeed");

        let deleted = deleted
            .lock()
            .expect("the delete recorder must not be poisoned")
            .clone();

        assert_eq!(deleted.len(), 2);
        assert!(!deleted.contains(&kept_id));
        assert!(doomed.iter().all(|id| deleted.contains(id)));

        let cut = cut
            .lock()
            .expect("the cut recorder must not be poisoned")
            .clone();
        assert_eq!(
            cut, deleted,
            "every dropped session must lose its SSO secret"
        );
    }

    #[tokio::test]
    async fn tokens_are_kept_when_the_sso_secret_cannot_be_cut() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let scope = scope_of(realm_id);
        let user = scoped_user(user_id, realm_id, &scope);

        let mut sessions = MockUserSessionRepository::new();
        let all = vec![session(user_id, realm_id)];
        sessions
            .expect_find_all_by_user_and_realm()
            .returning(move |_, _| {
                let all = all.clone();
                Box::pin(async move { Ok(all) })
            });
        sessions
            .expect_clear_sso_token_hash()
            .returning(|_| Box::pin(async { Err(SessionError::UpdateError) }));
        sessions.expect_delete().never();

        let mut access = MockAccessTokenRepository::new();
        access.expect_revoke_by_session_id().never();
        let mut refresh = MockRefreshTokenRepository::new();
        refresh.expect_revoke_by_session_id().never();

        let adapter = OtherSessionsRevocationAdapter::new(
            Arc::new(access),
            Arc::new(refresh),
            Arc::new(sessions),
        );

        assert!(
            adapter
                .revoke_all_sessions_except(&scope, &user, None)
                .await
                .is_err(),
            "a session whose SSO cookie still resolves must not be reported revoked"
        );
    }

    #[tokio::test]
    async fn keeping_nothing_drops_every_session() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let scope = scope_of(realm_id);
        let user = scoped_user(user_id, realm_id, &scope);

        let mut sessions = MockUserSessionRepository::new();
        let all = vec![session(user_id, realm_id), session(user_id, realm_id)];
        sessions
            .expect_find_all_by_user_and_realm()
            .returning(move |_, _| {
                let all = all.clone();
                Box::pin(async move { Ok(all) })
            });
        sessions
            .expect_clear_sso_token_hash()
            .times(2)
            .returning(|_| Box::pin(async { Ok(()) }));
        sessions
            .expect_delete()
            .times(2)
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut access = MockAccessTokenRepository::new();
        access
            .expect_revoke_by_session_id()
            .times(2)
            .returning(|_| Box::pin(async { Ok(1) }));

        let mut refresh = MockRefreshTokenRepository::new();
        refresh
            .expect_revoke_by_session_id()
            .times(2)
            .returning(|_| Box::pin(async { Ok(1) }));

        let adapter = OtherSessionsRevocationAdapter::new(
            Arc::new(access),
            Arc::new(refresh),
            Arc::new(sessions),
        );

        assert!(
            adapter
                .revoke_all_sessions_except(&scope, &user, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_session_of_another_realm_is_refused_rather_than_deleted() {
        let user_id = Uuid::now_v7();
        let realm_id = Uuid::now_v7();
        let scope = scope_of(realm_id);
        let user = scoped_user(user_id, realm_id, &scope);

        let mut sessions = MockUserSessionRepository::new();
        let foreign = vec![session(user_id, Uuid::now_v7())];
        sessions
            .expect_find_all_by_user_and_realm()
            .returning(move |_, _| {
                let foreign = foreign.clone();
                Box::pin(async move { Ok(foreign) })
            });
        sessions.expect_clear_sso_token_hash().never();
        sessions.expect_delete().never();

        let mut access = MockAccessTokenRepository::new();
        access.expect_revoke_by_session_id().never();

        let mut refresh = MockRefreshTokenRepository::new();
        refresh.expect_revoke_by_session_id().never();

        let adapter = OtherSessionsRevocationAdapter::new(
            Arc::new(access),
            Arc::new(refresh),
            Arc::new(sessions),
        );

        let refused = adapter
            .revoke_all_sessions_except(&scope, &user, None)
            .await;

        assert!(matches!(refused, Err(CoreError::NotFound)));
    }
    #[tokio::test]
    async fn recent_authentication_reads_only_the_live_bound_session() {
        for case in [
            "valid",
            "missing",
            "wrong_user",
            "wrong_realm",
            "wrong_session",
            "expired",
            "missing_cookie",
            "wrong_cookie",
            "missing_hash",
        ] {
            let uid = Uuid::now_v7();
            let rid = Uuid::now_v7();
            let scope = scope_of(rid);
            let user = scoped_user(uid, rid, &scope);
            let mut stored = session(uid, rid);
            stored.sso_token_hash = Some(sso_token_hash("browser-session-secret"));
            let wanted = stored.id;
            let authenticated = stored.authenticated_at;
            match case {
                "missing_hash" => stored.sso_token_hash = None,
                "wrong_user" => stored.user_id = Uuid::now_v7(),
                "wrong_realm" => stored.realm_id = Uuid::now_v7(),
                "wrong_session" => stored.id = Uuid::now_v7(),
                "expired" => stored.expires_at = Utc::now() - Duration::seconds(1),
                _ => {}
            }
            let mut sessions = MockUserSessionRepository::new();
            sessions
                .expect_find_by_id()
                .withf(move |sid| *sid == wanted)
                .returning(move |_| {
                    let stored = stored.clone();
                    Box::pin(async move {
                        Ok(if case == "missing" {
                            None
                        } else {
                            Some(Unscoped::new(stored))
                        })
                    })
                });
            let adapter = OtherSessionsRevocationAdapter::new(
                Arc::new(MockAccessTokenRepository::new()),
                Arc::new(MockRefreshTokenRepository::new()),
                Arc::new(sessions),
            );
            let result = adapter
                .authenticated_at(
                    &scope,
                    &user,
                    wanted,
                    match case {
                        "missing_cookie" => "",
                        "wrong_cookie" => "wrong",
                        _ => "browser-session-secret",
                    },
                )
                .await;
            if case == "valid" {
                assert_eq!(result.unwrap(), Some(authenticated));
            } else {
                assert!(
                    result.is_err() || result.unwrap().is_none(),
                    "accepted {case}"
                );
            }
        }
    }
}
