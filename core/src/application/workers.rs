//! Ownership of background tasks started by service composition.
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Notify;

use sea_orm::DatabaseConnection;
use sqlx::PgPool;
use tokio::task::JoinHandle;

/// Controls one composed application's workers independently of service clones.
///
/// Stop the listener and finish all requests before calling `shutdown`. Shutdown
/// cancels workers and outstanding deliveries; queued work is not drained. It
/// then closes both application pools, including their service-owned clones.
/// Dropping this owner cancels workers as a setup-failure safety net.
#[derive(Default)]
pub struct ApplicationShutdown {
    tasks: Vec<JoinHandle<()>>,
    pools: Vec<PgPool>,
    dispatchers: Vec<(JoinHandle<()>, Arc<Notify>)>,
}

impl ApplicationShutdown {
    pub(crate) fn set_pools(
        &mut self,
        primary: &DatabaseConnection,
        secondary: &DatabaseConnection,
    ) {
        self.pools = vec![
            primary.get_postgres_connection_pool().clone(),
            secondary.get_postgres_connection_pool().clone(),
        ];
    }

    pub(crate) fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
        self.track(tokio::spawn(task));
    }

    pub(crate) fn track(&mut self, task: JoinHandle<()>) {
        self.tasks.push(task);
    }

    pub(crate) fn track_dispatcher(&mut self, task: JoinHandle<()>, stop: Arc<Notify>) {
        self.dispatchers.push((task, stop));
    }

    pub(crate) fn extend(&mut self, tasks: impl IntoIterator<Item = JoinHandle<()>>) {
        self.tasks.extend(tasks);
    }

    /// Retains the historical detached-worker behavior of the legacy factories.
    pub(crate) fn detach(mut self) {
        self.tasks.clear();
        self.dispatchers.clear();
    }

    /// Cancel and join every owned worker, then close the application's pools.
    pub async fn shutdown(mut self) {
        for task in &self.tasks {
            task.abort();
        }
        for (_, stop) in &self.dispatchers {
            stop.notify_one();
        }
        for (task, _) in &mut self.dispatchers {
            if let Err(error) = task.await {
                tracing::warn!(%error, "application dispatcher failed");
            }
        }
        for task in &mut self.tasks {
            if let Err(error) = task.await {
                if !error.is_cancelled() {
                    tracing::warn!(%error, "application worker failed");
                }
            }
        }
        for pool in &self.pools {
            pool.close().await;
        }
    }
}

impl Drop for ApplicationShutdown {
    fn drop(&mut self) {
        for (task, _) in &self.dispatchers {
            task.abort();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    struct MarkDropped(Arc<AtomicBool>);
    impl Drop for MarkDropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    async fn owner_with_worker() -> (ApplicationShutdown, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = MarkDropped(dropped.clone());
        let (started, ready) = tokio::sync::oneshot::channel();
        let mut owner = ApplicationShutdown::default();
        owner.spawn(async move {
            let _guard = guard;
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        (owner, dropped)
    }

    #[tokio::test]
    async fn shutdown_cancels_and_joins_a_worker_that_never_returns() {
        let (owner, dropped) = owner_with_worker().await;
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown())
            .await
            .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_waits_for_a_dispatchers_child_tasks_to_be_cancelled() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = MarkDropped(dropped.clone());
        let stop = Arc::new(Notify::new());
        let stopping = stop.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let dispatcher = tokio::spawn(async move {
            let mut deliveries = tokio::task::JoinSet::new();
            deliveries.spawn(async move {
                let _guard = guard;
                let _ = started.send(());
                std::future::pending::<()>().await;
            });
            stopping.notified().await;
            deliveries.shutdown().await;
        });
        let mut owner = ApplicationShutdown::default();
        owner.track_dispatcher(dispatcher, stop);
        ready.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown())
            .await
            .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn dropping_the_owner_cancels_workers_after_setup_failure() {
        let (owner, dropped) = owner_with_worker().await;
        drop(owner);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
