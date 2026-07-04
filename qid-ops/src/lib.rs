//! Operational primitives for high availability and recovery.
#![forbid(unsafe_code)]

mod backup;
mod cache;
mod cluster;
mod keyring;

pub use backup::*;
pub use cache::*;
pub use cluster::*;
pub use keyring::*;

use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use ulid::Ulid;

// ---------------------------------------------------------------------------
// Shared utility functions
// ---------------------------------------------------------------------------

pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(input.as_ref()))
}

pub(crate) fn bad_request(message: impl Into<String>) -> QidError {
    QidError::BadRequest {
        message: message.into(),
    }
}

pub(crate) fn internal_error(message: impl Into<String>) -> QidError {
    QidError::Internal {
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// Durable worker queue
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerJob {
    pub id: String,
    pub kind: String,
    pub payload_json: serde_json::Value,
    pub run_after_epoch: u64,
    pub attempts: u32,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimedJob {
    pub job: WorkerJob,
    pub worker_id: String,
    pub visibility_expires_at_epoch: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableWorkerQueue {
    pending: VecDeque<WorkerJob>,
    claimed: BTreeMap<String, ClaimedJob>,
    dead_letter: Vec<WorkerJob>,
}

impl DurableWorkerQueue {
    pub fn enqueue(
        &mut self,
        kind: impl Into<String>,
        payload_json: serde_json::Value,
        run_after_epoch: u64,
        max_attempts: u32,
    ) -> QidResult<String> {
        let kind = kind.into();
        if kind.trim().is_empty() {
            return Err(bad_request("Worker job kind must not be empty"));
        }
        if max_attempts == 0 {
            return Err(bad_request(
                "Worker job max attempts must be greater than zero",
            ));
        }
        let id = Ulid::new().to_string();
        self.pending.push_back(WorkerJob {
            id: id.clone(),
            kind,
            payload_json,
            run_after_epoch,
            attempts: 0,
            max_attempts,
        });
        Ok(id)
    }

    pub fn claim_next(
        &mut self,
        worker_id: impl Into<String>,
        now_epoch: u64,
        visibility_timeout_seconds: u64,
    ) -> QidResult<Option<ClaimedJob>> {
        let worker_id = worker_id.into();
        if worker_id.trim().is_empty() {
            return Err(bad_request("Worker id must not be empty"));
        }
        if visibility_timeout_seconds == 0 {
            return Err(bad_request("Visibility timeout must be greater than zero"));
        }
        self.requeue_expired_claims(now_epoch);

        let Some(index) = self
            .pending
            .iter()
            .position(|job| job.run_after_epoch <= now_epoch)
        else {
            return Ok(None);
        };
        let mut job = self
            .pending
            .remove(index)
            .ok_or_else(|| internal_error("Worker queue index disappeared"))?;
        job.attempts += 1;
        let claimed = ClaimedJob {
            job,
            worker_id,
            visibility_expires_at_epoch: now_epoch + visibility_timeout_seconds,
        };
        self.claimed.insert(claimed.job.id.clone(), claimed.clone());
        Ok(Some(claimed))
    }

    pub fn complete(&mut self, job_id: &str) -> bool {
        self.claimed.remove(job_id).is_some()
    }

    pub fn fail(&mut self, job_id: &str, retry_after_epoch: u64) -> bool {
        let Some(mut claimed) = self.claimed.remove(job_id) else {
            return false;
        };
        if claimed.job.attempts >= claimed.job.max_attempts {
            self.dead_letter.push(claimed.job);
        } else {
            claimed.job.run_after_epoch = retry_after_epoch;
            self.pending.push_back(claimed.job);
        }
        true
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn claimed_len(&self) -> usize {
        self.claimed.len()
    }

    pub fn dead_letter_len(&self) -> usize {
        self.dead_letter.len()
    }

    fn requeue_expired_claims(&mut self, now_epoch: u64) {
        let expired = self
            .claimed
            .iter()
            .filter(|(_, claimed)| claimed.visibility_expires_at_epoch <= now_epoch)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            if let Some(claimed) = self.claimed.remove(&id) {
                if claimed.job.attempts >= claimed.job.max_attempts {
                    self.dead_letter.push(claimed.job);
                } else {
                    self.pending.push_back(claimed.job);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Emergency read-only mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmergencyModeDecision {
    pub read_only: bool,
    pub reason: Option<String>,
    pub allowed_actions: Vec<String>,
    pub denied_actions: Vec<String>,
}

pub fn decide_emergency_mode(
    db_writable: bool,
    quorum_available: bool,
    audit_queue_writable: bool,
) -> EmergencyModeDecision {
    let read_only = !db_writable || !quorum_available || !audit_queue_writable;
    let reason = if !db_writable {
        Some("database_not_writable".to_string())
    } else if !quorum_available {
        Some("cluster_quorum_unavailable".to_string())
    } else if !audit_queue_writable {
        Some("audit_queue_not_writable".to_string())
    } else {
        None
    };
    if read_only {
        EmergencyModeDecision {
            read_only: true,
            reason,
            allowed_actions: vec![
                "health.read".to_string(),
                "configuration.read".to_string(),
                "audit.read".to_string(),
            ],
            denied_actions: vec![
                "token.issue".to_string(),
                "admin.mutate".to_string(),
                "policy.update".to_string(),
            ],
        }
    } else {
        EmergencyModeDecision {
            read_only: false,
            reason: None,
            allowed_actions: vec!["*".to_string()],
            denied_actions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn worker_queue_claims_retries_and_dead_letters_jobs() {
        let mut queue = DurableWorkerQueue::default();
        let job_id = queue
            .enqueue("audit.export", json!({ "realm": "default" }), 100, 2)
            .unwrap();

        assert!(queue.claim_next("worker-1", 99, 30).unwrap().is_none());
        let claimed = queue.claim_next("worker-1", 100, 30).unwrap().unwrap();
        assert_eq!(claimed.job.id, job_id);
        assert_eq!(queue.claimed_len(), 1);

        assert!(queue.fail(&job_id, 120));
        assert_eq!(queue.pending_len(), 1);

        let claimed = queue.claim_next("worker-1", 120, 30).unwrap().unwrap();
        assert_eq!(claimed.job.attempts, 2);
        assert!(queue.fail(&job_id, 150));
        assert_eq!(queue.dead_letter_len(), 1);
    }

    #[test]
    fn emergency_mode_fails_closed_when_audit_queue_is_not_writable() {
        let decision = decide_emergency_mode(true, true, false);

        assert!(decision.read_only);
        assert_eq!(
            decision.reason,
            Some("audit_queue_not_writable".to_string())
        );
        assert!(decision.denied_actions.contains(&"token.issue".to_string()));
    }
}
