//! JVM process supervisor for IB Gateway.
//!
//! Responsible for:
//! - Building the classpath by scanning the jars directory
//! - Reading JVM options from the vmoptions file
//! - Constructing the full `java` command line with `-javaagent:`
//! - Spawning, monitoring, and killing the child JVM process

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

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

/// Supervisor manages the lifecycle of a single IB Gateway/TWS JVM process.
pub struct Supervisor {
    config: GatewayConfig,
    agent_jar_path: PathBuf,
    agent_socket_path: String,
    child: Option<Child>,
    shutdown_timeout_secs: u64,
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
        }
    }

    /// Launch the IB Gateway/TWS JVM process with the ibctl agent attached.
    ///
    /// Builds the classpath, reads vmoptions, constructs the full java command
    /// with `-javaagent:`, and spawns the child process.
    pub fn launch(&mut self) -> Result<(), SupervisorError> {
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

        // Main class
        cmd.arg(main_class);

        // Pass agent tick timing via env var (read by IbctlAgent.premain)
        if let Ok(tick) = std::env::var("IBCTL_AGENT_TICK_MS") {
            cmd.env("IBCTL_AGENT_TICK_MS", tick);
        }

        // Let JVM output flow to our stdout/stderr for debugging
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        log::info!("Launching JVM: {} {}", java_path, main_class);
        log::debug!("Classpath: {}", classpath);
        log::debug!("Agent: {}", javaagent_arg);

        let child = cmd.spawn()?;
        log::info!("JVM started with PID {}", child.id());
        self.child = Some(child);

        Ok(())
    }

    /// Wait for the JVM process to exit and return its exit status.
    /// Uses async polling to avoid blocking the tokio runtime.
    pub async fn wait(&mut self) -> Result<ExitStatus, SupervisorError> {
        match self.child.as_mut() {
            Some(child) => loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                    Err(e) => return Err(SupervisorError::SpawnFailed(e)),
                }
            },
            None => Err(SupervisorError::NotRunning),
        }
    }

    /// Gracefully stop the JVM process: SIGTERM first, then SIGKILL after timeout.
    /// Uses async sleep to avoid blocking the tokio runtime.
    pub async fn kill(&mut self) -> Result<(), SupervisorError> {
        match self.child.as_mut() {
            Some(child) => {
                let pid = child.id();
                log::info!("Sending SIGTERM to JVM (PID {})", pid);

                // Send SIGTERM for graceful shutdown
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }

                // Wait for graceful exit (configurable via timing.jvm_shutdown_timeout_secs)
                let iterations = self.shutdown_timeout_secs * 10;
                for _ in 0..iterations {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            log::info!("JVM exited gracefully after SIGTERM");
                            return Ok(());
                        }
                        Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                        Err(e) => {
                            log::warn!("Error checking JVM status: {}", e);
                            break;
                        }
                    }
                }

                // Fallback to SIGKILL
                log::warn!("JVM didn't exit after SIGTERM — sending SIGKILL");
                child.kill()?;
                Ok(())
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
