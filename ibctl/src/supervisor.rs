//! JVM process supervisor for IB Gateway.
//!
//! Responsible for:
//! - Building the classpath by scanning the jars directory
//! - Reading JVM options from the vmoptions file
//! - Constructing the full `java` command line with `-javaagent:`
//! - Spawning, monitoring, and killing the child JVM process

use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};

use tokio::process::{Child, Command};

use thiserror::Error;

use crate::config::{GatewayConfig, GatewayProgram};

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("failed to spawn JVM process: {0}")]
    SpawnFailed(#[from] std::io::Error),
    #[error("JVM process not running")]
    NotRunning,
    #[error("no jars found in {0}")]
    NoJars(String),
    #[error("failed to read vmoptions file '{path}': {source}")]
    VmOptionsFailed {
        path: String,
        source: std::io::Error,
    },
    #[error("Java not found at {0}")]
    JavaNotFound(String),
    #[error("failed to detect gateway version from {0}")]
    VersionDetectionFailed(String),
}

/// JDK 17 module access flags required for Swing introspection.
/// Captured from IBC's ibcstart.sh — these are mandatory for the
/// Java agent to access Swing internals via reflection.
pub const MODULE_ACCESS_FLAGS: &[&str] = &[
    "--add-opens=java.base/java.util=ALL-UNNAMED",
    "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
    "--add-exports=java.base/sun.util=ALL-UNNAMED",
    "--add-exports=java.desktop/com.sun.java.swing.plaf.motif=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt.dnd=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing.event=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing.plaf.basic=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing.table=ALL-UNNAMED",
    "--add-opens=java.desktop/sun.awt=ALL-UNNAMED",
    "--add-exports=java.desktop/sun.awt.X11=ALL-UNNAMED",
    "--add-exports=java.desktop/sun.swing=ALL-UNNAMED",
    "--add-opens=jdk.management/com.sun.management.internal=ALL-UNNAMED",
];

/// The main class for each program type.
const GATEWAY_MAIN_CLASS: &str = "ibgateway.GWClient";
const TWS_MAIN_CLASS: &str = "jclient.LoginFrame";

/// JVM process metadata exposed for dashboard visibility.
#[derive(Debug, Clone, serde::Serialize)]
pub struct JvmInfo {
    pub pid: Option<u32>,
    pub alive: bool,
    pub started_at: Option<u64>,
    pub config_dir: String,
    pub agent_socket: String,
}

/// Supervisor manages the lifecycle of a single IB Gateway/TWS JVM process.
pub struct Supervisor {
    config: GatewayConfig,
    agent_jar_path: PathBuf,
    agent_socket_path: String,
    child: Option<Child>,
    shutdown_timeout_secs: u64,
    launched_at: Option<std::time::Instant>,
    settings_path_resolved: String,
}

impl Supervisor {
    pub fn new(
        config: GatewayConfig,
        agent_jar_path: impl AsRef<Path>,
        agent_socket_path: String,
        shutdown_timeout_secs: u64,
    ) -> Self {
        Self {
            config,
            agent_jar_path: agent_jar_path.as_ref().to_path_buf(),
            agent_socket_path,
            child: None,
            shutdown_timeout_secs,
            launched_at: None,
            settings_path_resolved: String::new(),
        }
    }

    /// Launch the IB Gateway/TWS JVM process with the ibctl agent attached.
    ///
    /// Builds the classpath, reads vmoptions, constructs the full java command
    /// with `-javaagent:`, and spawns the child process.
    ///
    /// If `autorestart_path` is provided, passes `-Drestart=<path>` to the JVM
    /// which tells Gateway to resume the existing session without 2FA (warm restart).
    pub fn launch(&mut self) -> Result<(), SupervisorError> {
        self.launch_with_restart(None)
    }

    /// Launch with optional warm restart session path.
    pub fn launch_with_restart(&mut self, autorestart_path: Option<&str>) -> Result<(), SupervisorError> {
        // Safety check: kill any orphaned Gateway JVMs for this config dir
        // before launching.
        self.kill_orphan_gateways();

        // IBC pattern: rename the install4j launcher script so Gateway can't
        // auto-restart itself outside ibctl's control. Without this, Gateway
        // spawns a nohup'd child on exit that consumes the autorestart token
        // before ibctl can read it. Renaming the script is idempotent.
        self.disable_install4j_launcher();

        let tws_path = Path::new(&self.config.tws_path);
        let version = self.detect_version(tws_path)?;
        let classpath = Self::build_classpath(tws_path, &version)?;

        let settings_path = if self.config.settings_path.is_empty() {
            self.config.tws_path.clone()
        } else {
            self.config.settings_path.clone()
        };

        // Find the java binary
        let java_path = Self::find_java(tws_path)?;

        // Read vmoptions if present — search same candidates as classpath
        let vmoptions_candidates = [
            tws_path.join(&version).join("ibgateway.vmoptions"),
            tws_path.join("ibgateway").join(&version).join("ibgateway.vmoptions"),
        ];
        let vm_opts = vmoptions_candidates
            .iter()
            .find(|p| p.exists())
            .map(|p| Self::read_vmoptions(p))
            .transpose()?
            .unwrap_or_default();

        // Build the command
        let main_class = match self.config.program {
            GatewayProgram::Tws => TWS_MAIN_CLASS,
            GatewayProgram::Gateway => GATEWAY_MAIN_CLASS,
        };

        let javaagent_arg = format!(
            "-javaagent:{}={}",
            self.agent_jar_path.display(),
            self.agent_socket_path
        );

        let heap_arg = format!("-Xmx{}m", self.config.java_heap_mb);

        let mut cmd = Command::new(&java_path);

        // Module access flags (must come before -cp)
        for flag in MODULE_ACCESS_FLAGS {
            cmd.arg(flag);
        }

        // Classpath
        cmd.arg("-cp").arg(&classpath);

        // Agent
        cmd.arg(&javaagent_arg);

        // VM options from file
        for opt in &vm_opts {
            cmd.arg(opt);
        }

        // Heap size
        cmd.arg(&heap_arg);

        // System properties
        cmd.arg(format!("-DjtsConfigDir={}", settings_path));
        cmd.arg("-Dtwslaunch.autoupdate.serviceImpl=com.ib.tws.twslaunch.install4j.Install4jAutoUpdateService");
        cmd.arg("-Dchannel=latest");
        cmd.arg("-Dexe4j.isInstall4j=true");
        cmd.arg("-DinstallType=standalone");

        // Warm restart: pass session token path so Gateway skips 2FA
        if let Some(restart_path) = autorestart_path {
            log::info!("Warm restart: passing -Drestart={}", restart_path);
            cmd.arg(format!("-Drestart={}", restart_path));
        }

        // Main class
        cmd.arg(main_class);

        // Pass agent tick timing via env var (read by IbctlAgent.premain)
        if let Ok(tick) = std::env::var("IBCTL_AGENT_TICK_MS") {
            cmd.env("IBCTL_AGENT_TICK_MS", tick);
        }

        // Let JVM output flow to our stdout/stderr for debugging
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        // RC2 FIX: Create a new process group so kill(-pgid) reaps all
        // children, not just the direct child. Prevents install4j launcher
        // grandchildren from surviving SIGTERM.
        // process_group(0) is the safe equivalent of pre_exec(|| { setsid(); Ok(()) })
        cmd.process_group(0);

        log::info!("Launching JVM: {} {}", java_path, main_class);
        log::debug!("Classpath: {}", classpath);
        log::debug!("Agent: {}", javaagent_arg);

        let child = cmd.spawn()?;
        log::info!("JVM started with PID {:?}", child.id());
        self.child = Some(child);
        self.launched_at = Some(std::time::Instant::now());
        self.settings_path_resolved = settings_path;

        Ok(())
    }

    /// Get JVM metadata for dashboard display.
    pub fn jvm_info(&mut self) -> JvmInfo {
        let alive = self.is_running();
        JvmInfo {
            pid: self.child.as_ref().and_then(|c| c.id()),
            alive,
            started_at: self.launched_at.map(|t| t.elapsed().as_secs()),
            config_dir: self.settings_path_resolved.clone(),
            agent_socket: self.agent_socket_path.clone(),
        }
    }

    /// Wait for the JVM process to exit and return its exit status.
    /// Uses tokio's async child.wait() — yields to the runtime instead of polling.
    pub async fn wait(&mut self) -> Result<ExitStatus, SupervisorError> {
        match self.child.as_mut() {
            Some(child) => Ok(child.wait().await?),
            None => Err(SupervisorError::NotRunning),
        }
    }

    /// Gracefully stop the JVM process: SIGTERM first, then SIGKILL after timeout.
    /// Uses `tokio::time::timeout` + async `child.wait()` instead of busy-wait polling.
    pub async fn kill(&mut self) -> Result<(), SupervisorError> {
        match self.child.as_mut() {
            Some(child) => {
                let pid = child.id();
                log::info!("Sending SIGTERM to JVM (PID {:?})", pid);

                // RC2 FIX: Kill the entire process group (negative PID).
                // This reaps install4j launcher children and any grandchildren,
                // not just the direct child. Prevents orphan JVMs.
                if let Some(pid) = pid {
                    let _ = kill_process_group(pid, nix::sys::signal::Signal::SIGTERM);
                }

                // Wait for graceful exit (configurable via timing.jvm_shutdown_timeout_secs)
                let timeout_dur = std::time::Duration::from_secs(self.shutdown_timeout_secs);
                match tokio::time::timeout(timeout_dur, child.wait()).await {
                    Ok(Ok(_status)) => {
                        log::info!("JVM exited gracefully after SIGTERM");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        log::warn!("Error waiting for JVM after SIGTERM: {}", e);
                        // Fallback to SIGKILL
                        log::warn!("Sending SIGKILL as fallback");
                        child.start_kill().ok();
                        Ok(())
                    }
                    Err(_elapsed) => {
                        // Timeout — process didn't exit within the grace period
                        log::warn!("JVM didn't exit after SIGTERM within {}s — sending SIGKILL", self.shutdown_timeout_secs);
                        child.start_kill().ok();
                        Ok(())
                    }
                }
            }
            None => Err(SupervisorError::NotRunning),
        }
    }

    /// Check if the JVM process is still running.
    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(_)) => false, // Process has exited
                Ok(None) => true,     // Still running
                Err(_) => false,      // Error checking — assume dead
            },
            None => false,
        }
    }

    /// RC3: Kill any orphaned Gateway JVM processes that match our config dir.
    /// Scans /proc for java processes with our -DjtsConfigDir and kills them.
    /// This enforces the invariant: at most one JVM per trading mode.
    fn kill_orphan_gateways(&self) {
        let config_dir = if self.config.settings_path.is_empty() {
            &self.config.tws_path
        } else {
            &self.config.settings_path
        };

        let marker = format!("-DjtsConfigDir={}", config_dir);
        let our_child_pid = self.child.as_ref().and_then(|c| c.id());

        // Scan /proc for java processes with our config dir
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid_str = entry.file_name();
                let pid_str = pid_str.to_string_lossy();
                let pid: i32 = match pid_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Skip our own tracked child
                if our_child_pid == Some(pid as u32) {
                    continue;
                }

                // Read cmdline
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                    let cmdline = cmdline.replace('\0', " ");
                    if cmdline.contains("ibgateway.GWClient") && cmdline.contains(&marker) {
                        log::warn!(
                            "Killing orphan Gateway JVM (PID {}) with config dir {}",
                            pid, config_dir
                        );
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                }
            }
        }
    }

    /// IBC pattern: rename the install4j launcher script so Gateway can't auto-restart
    /// itself via install4j. The script path is `<tws_path>/<version>/ibgateway`.
    /// Renaming is idempotent — safe to call on every launch.
    fn disable_install4j_launcher(&self) {
        let tws_path = Path::new(&self.config.tws_path);

        // Search for the launcher script in known locations
        let candidates = [
            tws_path.join("ibgateway"),
            // Also check under the version directory (e.g., ibgateway/10.45.1b/ibgateway)
        ];

        // Scan for ibgateway launcher under the tws_path tree
        if let Ok(entries) = std::fs::read_dir(tws_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let launcher = path.join("ibgateway");
                    let renamed = path.join("ibgateway.ibctl-disabled");
                    if launcher.exists() && launcher.is_file() && !renamed.exists() {
                        match std::fs::rename(&launcher, &renamed) {
                            Ok(()) => log::info!(
                                "Disabled install4j launcher: {} -> {}",
                                launcher.display(), renamed.display()
                            ),
                            Err(e) => log::warn!(
                                "Failed to rename install4j launcher {}: {}",
                                launcher.display(), e
                            ),
                        }
                    }
                    // Also check one level deeper (ibgateway/10.45.1b/ibgateway)
                    if let Ok(sub_entries) = std::fs::read_dir(&path) {
                        for sub in sub_entries.flatten() {
                            let sub_path = sub.path();
                            if sub_path.is_dir() {
                                let launcher = sub_path.join("ibgateway");
                                let renamed = sub_path.join("ibgateway.ibctl-disabled");
                                if launcher.exists() && launcher.is_file() && !renamed.exists() {
                                    match std::fs::rename(&launcher, &renamed) {
                                        Ok(()) => log::info!(
                                            "Disabled install4j launcher: {} -> {}",
                                            launcher.display(), renamed.display()
                                        ),
                                        Err(e) => log::warn!(
                                            "Failed to rename install4j launcher {}: {}",
                                            launcher.display(), e
                                        ),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also handle direct candidates
        for launcher in &candidates {
            let renamed = launcher.with_extension("ibctl-disabled");
            if launcher.exists() && launcher.is_file() && !renamed.exists() {
                match std::fs::rename(launcher, &renamed) {
                    Ok(()) => log::info!(
                        "Disabled install4j launcher: {} -> {}",
                        launcher.display(), renamed.display()
                    ),
                    Err(e) => log::warn!(
                        "Failed to rename install4j launcher {}: {}",
                        launcher.display(), e
                    ),
                }
            }
        }
    }

    /// Find the `autorestart` session token file written by Gateway before a warm restart.
    /// Returns the subdirectory name (session hash) containing the file.
    /// IBC passes just the subdirectory name via `-Drestart=<hash>`, not the full path.
    /// The file lives at `<settings_path>/<session_hash>/autorestart`.
    pub fn find_autorestart_path(&self) -> Option<String> {
        let settings_dir = if self.config.settings_path.is_empty() {
            &self.config.tws_path
        } else {
            &self.config.settings_path
        };

        let base = Path::new(settings_dir);
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let autorestart = path.join("autorestart");
                    if autorestart.exists() {
                        // Return just the directory name (session hash), not the full path
                        if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                            log::info!("Found autorestart token at {}", autorestart.display());
                            return Some(dir_name.to_string());
                        }
                    }
                }
            }
        }
        None
    }


    /// Build the classpath by scanning the jars directory.
    ///
    /// Collects all `*.jar` files from `{tws_path}/{version}/jars/` and
    /// includes `i4jruntime.jar` from the version directory.
    pub fn build_classpath(tws_path: &Path, version: &str) -> Result<String, SupervisorError> {
        // Try multiple layouts: direct, under ibgateway/, strip ibgateway/ prefix
        let candidates = [
            tws_path.join(version).join("jars"),
            tws_path.join("ibgateway").join(version).join("jars"),
        ];

        let jars_dir = candidates.iter().find(|p| p.exists());
        let jars_dir = match jars_dir {
            Some(d) => d.clone(),
            None => {
                let tried: Vec<_> = candidates.iter().map(|p| p.display().to_string()).collect();
                return Err(SupervisorError::NoJars(tried.join(", ")));
            }
        };

        log::info!("Found jars directory: {}", jars_dir.display());
        let mut jars: Vec<String> = Vec::new();

        // Collect all .jar files in the jars directory
        for entry in std::fs::read_dir(&jars_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jar") {
                jars.push(path.display().to_string());
            }
        }

        if jars.is_empty() {
            return Err(SupervisorError::NoJars(jars_dir.display().to_string()));
        }

        // Add i4jruntime.jar and .install4j/i4jruntime.jar from the version directory
        let version_dir = jars_dir.parent().unwrap_or(tws_path);
        let i4j_candidates = [
            version_dir.join("i4jruntime.jar"),
            version_dir.join(".install4j").join("i4jruntime.jar"),
        ];
        for i4j_path in &i4j_candidates {
            if i4j_path.exists() {
                jars.push(i4j_path.display().to_string());
                break;
            }
        }

        jars.sort(); // Deterministic ordering
        Ok(jars.join(":"))
    }

    /// Read JVM options from a `.vmoptions` file.
    ///
    /// Skips comment lines (starting with `#`) and `-D` property lines,
    /// matching IBC's behavior of letting ibctl control system properties.
    pub fn read_vmoptions(path: &Path) -> Result<Vec<String>, SupervisorError> {
        let contents = std::fs::read_to_string(path).map_err(|e| SupervisorError::VmOptionsFailed {
            path: path.display().to_string(),
            source: e,
        })?;

        let opts: Vec<String> = contents
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .filter(|line| !line.starts_with('#'))   // Skip comments
            .filter(|line| !line.starts_with("-D"))   // Skip -D (we set our own)
            .map(String::from)
            .collect();

        log::debug!("Read {} VM options from {}", opts.len(), path.display());
        Ok(opts)
    }

    /// Detect the Gateway/TWS version from the tws_path directory structure.
    ///
    /// In the gnzsnz Docker image, Gateway lives at `{tws_path}/ibgateway/{version}/`.
    /// The version directory contains a `jars/` subdirectory.
    fn detect_version(&self, tws_path: &Path) -> Result<String, SupervisorError> {
        // If version is explicitly configured, use it
        if !self.config.version.is_empty() {
            return Ok(self.config.version.clone());
        }

        // Look under ibgateway/ for a version directory containing jars/
        let gw_dir = tws_path.join("ibgateway");
        if gw_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&gw_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.join("jars").exists() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            log::info!("Auto-detected gateway version: {}", name);
                            return Ok(format!("ibgateway/{}", name));
                        }
                    }
                }
            }
        }

        // Also check directly under tws_path (TWS layout)
        if let Ok(entries) = std::fs::read_dir(tws_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && path.join("jars").exists() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name != "ibgateway" {
                            log::info!("Auto-detected TWS version: {}", name);
                            return Ok(name.to_string());
                        }
                    }
                }
            }
        }

        Err(SupervisorError::VersionDetectionFailed(
            tws_path.display().to_string(),
        ))
    }

    /// Find the java binary, checking common paths.
    fn find_java(_tws_path: &Path) -> Result<String, SupervisorError> {
        // Check JAVA_PATH env var first
        if let Ok(java_path) = std::env::var("JAVA_PATH") {
            let bin = format!("{}/bin/java", java_path);
            if Path::new(&bin).exists() {
                return Ok(bin);
            }
            let direct = Path::new(&java_path);
            if direct.exists() && direct.is_file() {
                return Ok(java_path);
            }
        }

        // Check common i4j JRE locations within tws_path
        // The gnzsnz Docker image uses: /usr/local/i4j_jres/.../bin/java
        let i4j_base = Path::new("/usr/local/i4j_jres");
        if i4j_base.exists() {
            if let Ok(entries) = std::fs::read_dir(i4j_base) {
                for entry in entries.flatten() {
                    // Look for bin/java inside each i4j JRE directory
                    let java_bin = entry.path().join("bin").join("java");
                    // Also check one level deeper (version subdirectory)
                    if java_bin.exists() {
                        return Ok(java_bin.display().to_string());
                    }
                    if let Ok(sub_entries) = std::fs::read_dir(entry.path()) {
                        for sub in sub_entries.flatten() {
                            let nested = sub.path().join("bin").join("java");
                            if nested.exists() {
                                return Ok(nested.display().to_string());
                            }
                        }
                    }
                }
            }
        }

        // Fall back to common PATH locations (avoids blocking subprocess)
        for candidate in &["/usr/bin/java", "/usr/local/bin/java"] {
            if Path::new(candidate).exists() {
                return Ok(candidate.to_string());
            }
        }

        Err(SupervisorError::JavaNotFound(
            "no java binary found in JAVA_PATH, i4j_jres, or PATH".to_string(),
        ))
    }
}

/// Send a signal to an entire process group.
///
/// Uses `nix::sys::signal::killpg` — the safe wrapper for kill(-pid, signal).
fn kill_process_group(pid: u32, signal: nix::sys::signal::Signal) -> nix::Result<()> {
    nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid as i32), signal)
}
