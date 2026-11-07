//! Process-local email budgets. A single lock makes each reservation atomic.
//! Recipient keys are global across realms, normalized and hashed before storage.
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const DEFAULT_REALM_EMAILS_PER_HOUR: u32 = 1000;
const HOUR: Duration = Duration::from_secs(3600);
const MINUTE: Duration = Duration::from_secs(60);
const MAX_TRACKED: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailLimit {
    pub dimension: &'static str,
    pub retry_after_seconds: u32,
}
impl EmailLimit {
    fn new(dimension: &'static str, wait: Duration) -> Self {
        Self {
            dimension,
            retry_after_seconds: wait
                .as_secs()
                .saturating_add(u64::from(wait.subsec_nanos() > 0))
                .max(1)
                .min(u32::MAX as u64) as u32,
        }
    }
}
#[derive(Debug, Default)]
struct Windows {
    recipients: HashMap<[u8; 32], VecDeque<Instant>>,
    realms: HashMap<Uuid, VecDeque<Instant>>,
    ips: HashMap<Option<IpAddr>, VecDeque<Instant>>,
}
#[derive(Debug)]
pub struct EmailSendLimits {
    realm_limit: u32,
    max_tracked: usize,
    windows: Mutex<Windows>,
}
impl Default for EmailSendLimits {
    fn default() -> Self {
        Self::new(DEFAULT_REALM_EMAILS_PER_HOUR)
    }
}
pub fn recipient_hash(email: &str) -> [u8; 32] {
    Sha256::digest(email.trim().to_lowercase().as_bytes()).into()
}
pub fn recipient_hash_hex(email: &str) -> String {
    recipient_hash(email)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn ip_key(ip: Option<IpAddr>) -> Option<IpAddr> {
    ip.map(|ip| match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut bytes = v6.octets();
                bytes[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
        },
    })
}
fn prune<K>(table: &mut HashMap<K, VecDeque<Instant>>, now: Instant) {
    table.retain(|_, sends| {
        while sends
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= HOUR)
        {
            sends.pop_front();
        }
        !sends.is_empty()
    });
}
fn wait(sends: Option<&VecDeque<Instant>>, limit: u32, now: Instant) -> Option<Duration> {
    sends
        .filter(|s| s.len() >= limit as usize)
        .and_then(|s| s.front())
        .map(|first| HOUR.saturating_sub(now.saturating_duration_since(*first)))
}
impl EmailSendLimits {
    pub fn new(realm_limit: u32) -> Self {
        Self {
            realm_limit: realm_limit.max(1),
            max_tracked: MAX_TRACKED,
            windows: Mutex::new(Windows::default()),
        }
    }
    /// IP attempts are charged before recipient lookup. Missing IPs share a bucket.
    pub fn check_ip(&self, ip: Option<IpAddr>) -> Result<(), EmailLimit> {
        self.check_ip_at(ip, Instant::now())
    }
    fn check_ip_at(&self, ip: Option<IpAddr>, now: Instant) -> Result<(), EmailLimit> {
        let mut windows = self
            .windows
            .lock()
            .map_err(|_| EmailLimit::new("capacity", HOUR))?;
        prune(&mut windows.ips, now);
        let key = ip_key(ip);
        if let Some(delay) = wait(windows.ips.get(&key), 10, now) {
            return Err(EmailLimit::new("ip", delay));
        }
        if !windows.ips.contains_key(&key) && windows.ips.len() >= self.max_tracked {
            return Err(EmailLimit::new("capacity", HOUR));
        }
        windows.ips.entry(key).or_default().push_back(now);
        Ok(())
    }
    /// Atomically reserve recipient and realm budgets before creating a token or account.
    /// Failures are not refunded: retries must not turn delivery failures into a flood.
    pub fn reserve(&self, realm: Uuid, email: &str) -> Result<(), EmailLimit> {
        self.reserve_at(realm, email, Instant::now())
    }
    fn reserve_at(&self, realm: Uuid, email: &str, now: Instant) -> Result<(), EmailLimit> {
        let mut windows = self
            .windows
            .lock()
            .map_err(|_| EmailLimit::new("capacity", HOUR))?;
        prune(&mut windows.recipients, now);
        prune(&mut windows.realms, now);
        let key = recipient_hash(email);
        if let Some(last) = windows.recipients.get(&key).and_then(|s| s.back()) {
            let elapsed = now.saturating_duration_since(*last);
            if elapsed < MINUTE {
                return Err(EmailLimit::new("recipient", MINUTE - elapsed));
            }
        }
        if let Some(delay) = wait(windows.recipients.get(&key), 5, now) {
            return Err(EmailLimit::new("recipient", delay));
        }
        if let Some(delay) = wait(windows.realms.get(&realm), self.realm_limit, now) {
            return Err(EmailLimit::new("realm", delay));
        }
        if (!windows.recipients.contains_key(&key) && windows.recipients.len() >= self.max_tracked)
            || (!windows.realms.contains_key(&realm) && windows.realms.len() >= self.max_tracked)
        {
            return Err(EmailLimit::new("capacity", HOUR));
        }
        windows.recipients.entry(key).or_default().push_back(now);
        windows.realms.entry(realm).or_default().push_back(now);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipient_windows_are_global_normalized_and_rolling() {
        let limits = EmailSendLimits::default();
        let now = Instant::now();
        for i in 0..5 {
            assert!(
                limits
                    .reserve_at(
                        Uuid::new_v4(),
                        " A@EXAMPLE.COM ",
                        now + Duration::from_secs(i * 60)
                    )
                    .is_ok()
            );
        }
        assert_eq!(
            limits
                .reserve_at(
                    Uuid::new_v4(),
                    "a@example.com",
                    now + Duration::from_secs(300)
                )
                .unwrap_err()
                .dimension,
            "recipient"
        );
        assert!(
            limits
                .reserve_at(Uuid::new_v4(), "a@example.com", now + HOUR)
                .is_ok()
        );
        assert!(
            limits
                .reserve_at(
                    Uuid::new_v4(),
                    "a@example.com",
                    now + HOUR + Duration::from_secs(59)
                )
                .is_err()
        );
    }
    #[test]
    fn denied_recipient_does_not_spend_realm_and_denied_realm_does_not_spend_recipient() {
        let limits = EmailSendLimits::new(2);
        let now = Instant::now();
        let realm = Uuid::new_v4();
        assert!(limits.reserve_at(realm, "a@x", now).is_ok());
        assert!(limits.reserve_at(realm, "a@x", now).is_err());
        assert!(limits.reserve_at(realm, "b@x", now).is_ok());
        assert_eq!(
            limits.reserve_at(realm, "c@x", now).unwrap_err().dimension,
            "realm"
        );
        assert!(limits.reserve_at(Uuid::new_v4(), "c@x", now).is_ok());
    }
    #[test]
    fn ip_hour_and_ipv6_64_and_mapped_ipv4() {
        let limits = EmailSendLimits::default();
        let now = Instant::now();
        for _ in 0..10 {
            assert!(
                limits
                    .check_ip_at(Some("2001:db8:1:2::1".parse().unwrap()), now)
                    .is_ok()
            );
        }
        assert!(
            limits
                .check_ip_at(Some("2001:db8:1:2::2".parse().unwrap()), now)
                .is_err()
        );
        assert!(
            limits
                .check_ip_at(Some("2001:db8:1:3::2".parse().unwrap()), now)
                .is_ok()
        );
        assert!(
            limits
                .check_ip_at(Some("2001:db8:1:2::2".parse().unwrap()), now + HOUR)
                .is_ok()
        );
        assert_eq!(
            ip_key(Some("::ffff:192.0.2.1".parse().unwrap())),
            ip_key(Some("192.0.2.1".parse().unwrap()))
        );
    }
    #[test]
    fn full_table_fails_closed_and_expires() {
        let mut limits = EmailSendLimits::default();
        limits.max_tracked = 1;
        let now = Instant::now();
        let realm = Uuid::new_v4();
        assert!(limits.reserve_at(realm, "a@x", now).is_ok());
        assert_eq!(
            limits.reserve_at(realm, "b@x", now).unwrap_err().dimension,
            "capacity"
        );
        assert!(limits.reserve_at(realm, "b@x", now + HOUR).is_ok());
    }
    #[test]
    fn concurrent_sends_cannot_bypass_recipient_budget() {
        let limits = std::sync::Arc::new(EmailSendLimits::default());
        let realm = Uuid::new_v4();
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let l = limits.clone();
                std::thread::spawn(move || l.reserve(realm, "a@x").is_ok())
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| t.join().ok())
                .filter(|allowed| *allowed)
                .count(),
            1
        );
    }
}
