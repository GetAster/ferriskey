use std::sync::Arc;

use tokio::sync::{Notify, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tracing::warn;

use crate::domain::authentication::backchannel_logout::{
    BackchannelLogoutNotifier, BackchannelLogoutService, EndedSession,
};

const QUEUE_CAPACITY: usize = 1024;
const CONCURRENT_DELIVERIES: usize = 16;

/// Hands ended sessions to a background worker. Enqueuing never blocks: when
/// the queue is full the session is dropped with a warning, which costs the
/// clients a logout notice but never costs the user their logout.
#[derive(Debug, Clone)]
pub struct BackchannelLogoutDispatcher {
    sender: Option<mpsc::Sender<EndedSession>>,
}

impl BackchannelLogoutDispatcher {
    /// Starts the worker that delivers logout tokens through `service`.
    pub fn spawn<S>(service: Arc<S>) -> Self
    where
        S: BackchannelLogoutService + 'static,
    {
        let (dispatcher, _worker, _stop) = Self::spawn_managed(service);
        dispatcher
    }

    /// Starts a worker whose lifetime is controlled by the application owner.
    pub fn spawn_managed<S>(service: Arc<S>) -> (Self, JoinHandle<()>, Arc<Notify>)
    where
        S: BackchannelLogoutService + 'static,
    {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let stop = Arc::new(Notify::new());
        let worker = tokio::spawn(deliver_ended_sessions(receiver, service, stop.clone()));
        (
            Self {
                sender: Some(sender),
            },
            worker,
            stop,
        )
    }

    /// A dispatcher that drops everything, for tests and tools that run
    /// without a worker.
    pub fn disabled() -> Self {
        Self { sender: None }
    }
}

impl BackchannelLogoutNotifier for BackchannelLogoutDispatcher {
    fn sessions_ended(&self, sessions: Vec<EndedSession>) {
        let Some(sender) = &self.sender else {
            return;
        };
        for session in sessions {
            let session_id = session.session_id;
            if sender.try_send(session).is_err() {
                warn!(session_id = %session_id, "Back-channel logout queue full, dropping a session");
            }
        }
    }
}

async fn deliver_ended_sessions<S>(
    mut receiver: mpsc::Receiver<EndedSession>,
    service: Arc<S>,
    stop: Arc<Notify>,
) where
    S: BackchannelLogoutService + 'static,
{
    // JoinSet aborts in-flight deliveries when this worker is cancelled.
    let mut deliveries = JoinSet::new();
    let mut accepting = true;
    loop {
        if !accepting && deliveries.is_empty() {
            return;
        }
        tokio::select! {
            _ = stop.notified() => { deliveries.shutdown().await; return; }
            Some(_) = deliveries.join_next(), if !deliveries.is_empty() => {}
            session = receiver.recv(), if accepting && deliveries.len() < CONCURRENT_DELIVERIES => {
                let Some(session) = session else { accepting = false; continue; };
                let service = service.clone();
                deliveries.spawn(async move { service.deliver(session).await; });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::authentication::backchannel_logout::DeliveryReport;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct PendingDelivery {
        started: Notify,
        dropped: Arc<AtomicBool>,
    }
    struct MarkDropped(Arc<AtomicBool>);
    impl Drop for MarkDropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl BackchannelLogoutService for PendingDelivery {
        async fn deliver(&self, _: EndedSession) -> DeliveryReport {
            let _guard = MarkDropped(self.dropped.clone());
            self.started.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn closing_the_sender_keeps_shutdown_selectable_during_delivery() {
        let service = Arc::new(PendingDelivery {
            started: Notify::new(),
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let (dispatcher, worker, stop) =
            BackchannelLogoutDispatcher::spawn_managed(service.clone());
        dispatcher.sessions_ended(vec![EndedSession {
            realm_id: Default::default(),
            session_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            participants: vec![],
        }]);
        service.started.notified().await;
        drop(dispatcher);
        // Let the worker observe the closed source before requesting shutdown.
        tokio::task::yield_now().await;
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(service.dropped.load(Ordering::SeqCst));
    }
}
