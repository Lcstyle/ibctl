//! Socat port forwarding lifecycle management.
//!
//! Socat bridges external Docker ports to Gateway's localhost-only API port.
//! Owned by the state machine — started only after ConfiguringApi completes.

use super::types::StateMachine;

impl StateMachine {
    /// Start socat to forward external port to Gateway's localhost port.
    /// Called only after configuration is complete — no race condition possible.
    pub(super) fn start_socat(&mut self, api_port: u16, socat_port: u16) {
        // Kill any existing socat first
        self.stop_socat();

        log::info!("Starting socat: 0.0.0.0:{} -> 127.0.0.1:{}", socat_port, api_port);
        match std::process::Command::new("socat")
            .arg(format!("TCP-LISTEN:{},fork,reuseaddr", socat_port))
            .arg(format!("TCP:127.0.0.1:{}", api_port))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => {
                log::info!("socat started (PID {}): port {} -> {}", child.id(), socat_port, api_port);
                self.socat_process = Some(child);
            }
            Err(e) => {
                log::error!("Failed to start socat: {} — clients won't be able to connect externally", e);
            }
        }
    }

    /// Stop socat if running.
    pub(super) fn stop_socat(&mut self) {
        if let Some(ref mut child) = self.socat_process {
            log::info!("Stopping socat (PID {})", child.id());
            let _ = child.kill();
            let _ = child.wait();
            self.socat_process = None;
        }
    }
}

impl Drop for StateMachine {
    fn drop(&mut self) {
        // Reap socat child process to prevent zombies on abnormal exit
        if let Some(ref mut child) = self.socat_process {
            log::debug!("Drop: killing socat (PID {})", child.id());
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
