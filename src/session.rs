use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct Session {
    pub user_id: u64,
    pub email: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub created_at: Instant,
    pub expires_at: Instant,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    user_sessions: Arc<RwLock<HashMap<u64, Vec<String>>>>,
    #[allow(dead_code)]
    session_ttl: Duration,
}

impl SessionStore {
    pub fn new(session_ttl_secs: u64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            session_ttl: Duration::from_secs(session_ttl_secs),
        }
    }

    pub async fn create_session(
        &self,
        session_id: String,
        user_id: u64,
        email: String,
        access_token: String,
        refresh_token: Option<String>,
        expires_in_secs: u64,
    ) -> Session {
        let now = Instant::now();
        let session = Session {
            user_id,
            email,
            access_token,
            refresh_token,
            created_at: now,
            expires_at: now + Duration::from_secs(expires_in_secs),
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session.clone());
        }

        {
            let mut user_sessions = self.user_sessions.write().await;
            user_sessions
                .entry(user_id)
                .or_insert_with(Vec::new)
                .push(session_id);
        }

        session
    }

    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn validate_session(&self, session_id: &str) -> Option<u64> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            if !session.is_expired() {
                return Some(session.user_id);
            }
        }
        None
    }

    pub async fn refresh_session(
        &self,
        session_id: &str,
        new_access_token: String,
        expires_in_secs: u64,
    ) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.access_token = new_access_token;
            session.expires_at = Instant::now() + Duration::from_secs(expires_in_secs);
            return true;
        }
        false
    }

    pub async fn remove_session(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(session_id) {
            let mut user_sessions = self.user_sessions.write().await;
            if let Some(user_sids) = user_sessions.get_mut(&session.user_id) {
                user_sids.retain(|s| s != session_id);
            }
            return true;
        }
        false
    }

    pub async fn remove_user_sessions(&self, user_id: u64) -> usize {
        let mut count = 0;
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;

        if let Some(session_ids) = user_sessions.remove(&user_id) {
            for sid in &session_ids {
                if sessions.remove(sid).is_some() {
                    count += 1;
                }
            }
        }
        count
    }

    pub async fn get_active_user_ids(&self) -> Vec<u64> {
        let sessions = self.sessions.read().await;
        let now = Instant::now();

        sessions
            .values()
            .filter(|s| s.expires_at > now)
            .map(|s| s.user_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;
        let now = Instant::now();

        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.expires_at < now)
            .map(|(k, _)| k.clone())
            .collect();

        let count = expired.len();

        for sid in expired {
            if let Some(session) = sessions.remove(&sid) {
                if let Some(user_sids) = user_sessions.get_mut(&session.user_id) {
                    user_sids.retain(|s| s != &sid);
                }
            }
        }

        count
    }

    pub fn start_cleanup_task(self: Arc<Self>, interval_secs: u64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                let removed = self.cleanup_expired().await;
                if removed > 0 {
                    tracing::info!("Cleaned up {} expired sessions", removed);
                }
            }
        });
    }
}
