//! System Mode session.
//!
//! Thin wrapper over [`PrivilegedClient`]. Unlike the previous `sudo -n`
//! approach, `is_active()` is only ever true when a verified root channel
//! exists — there is no way for the UI to display "System Mode on" while
//! privileged operations silently fail.

use crate::privileged::{PrivilegedClient, Request, Response};
use std::sync::RwLock;

const PROMPT: &str = "LaunchFleet needs administrator access to manage system-level startup items. You will only be asked once per session.";

#[derive(Default)]
pub struct SudoSession {
    client: RwLock<Option<PrivilegedClient>>,
}

impl SudoSession {
    pub fn new() -> Self {
        Self {
            client: RwLock::new(None),
        }
    }

    pub fn is_active(&self) -> bool {
        self.read().as_ref().is_some()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Option<PrivilegedClient>> {
        self.client
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Triggers exactly one native authorization dialog (Touch ID capable) and
    /// verifies the resulting helper really is root.
    pub fn activate(&self) -> Result<(), String> {
        {
            if self.is_active() {
                return Ok(());
            }
        }

        let client = PrivilegedClient::connect(PROMPT)?;

        let mut guard = self
            .client
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(client);
        Ok(())
    }

    /// Send a privileged request. Errors if System Mode is not active.
    pub fn request(&self, req: Request) -> Result<Response, String> {
        let guard = self.read();
        let client = guard.as_ref().ok_or_else(|| {
            "System Mode is not active. Click 'System Mode' first.".to_string()
        })?;
        client.request(req)
    }

    /// Run a request and turn a non-zero exit code into an `Err`. This is the
    /// call site that makes silent privileged failures impossible.
    pub fn request_checked(&self, req: Request) -> Result<Response, String> {
        let resp = self.request(req)?;
        if !resp.ok() {
            return Err(resp.error_text());
        }
        Ok(resp)
    }

    pub fn shutdown(&self) {
        let mut guard = self
            .client
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(client) = guard.take() {
            client.shutdown();
        }
    }
}
