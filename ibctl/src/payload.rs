//! The Gateway payload: what ibctl needs from a Gateway installation to launch
//! it, and where the installer keeps each piece.
//!
//! The installer (install4j) owns this layout, not ibctl, and it has changed
//! between releases. 10.47 put its Java in a shared `/usr/local/i4j_jres/<id>/<jre>`
//! and recorded that in `.install4j/pref_jre.cfg`; 10.50 bundles it in the
//! install folder's `jre/`. ibctl used to guess one fixed location, so the
//! 10.50.1f image crash-looped in production with "Java not found".
//!
//! This module is the single owner of that knowledge. [`plan_launch`] resolves
//! everything a launch needs, following what the installer itself declares,
//! and both the real launch and `ibctl preflight --payload` go through it, so
//! the check and the launch cannot disagree.

use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::GatewayConfig;
use crate::supervisor::{Supervisor, SupervisorError};

/// Where install4j keeps a shared (not bundled) JRE when installing as root.
pub const SHARED_JRE_ROOT: &str = "/usr/local/i4j_jres";

/// Java on the image's PATH. Only used when the install declares no Java of
/// its own; the Gateway is not built or tested against an arbitrary JDK.
pub const SYSTEM_JAVA: &[&str] = &["/usr/bin/java", "/usr/local/bin/java"];

/// How long `java -version` may take before the payload check gives up.
pub const JAVA_VERSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the Java a launch will use came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaSource {
    /// `JAVA_PATH`, set by an operator.
    Override,
    /// `<install>/jre`, bundled with the Gateway (10.50 and later).
    Bundled,
    /// The shared JRE the installer recorded in `.install4j/pref_jre.cfg` (10.47).
    InstallerRecord,
    /// A JRE found by scanning the shared root, with no record pointing at it.
    SharedScan,
    /// Java on the image's PATH; the install declared none of its own.
    System,
}

impl fmt::Display for JavaSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JavaSource::Override => "JAVA_PATH override",
            JavaSource::Bundled => "bundled with the install",
            JavaSource::InstallerRecord => "recorded by the installer",
            JavaSource::SharedScan => "found in the shared JRE folder",
            JavaSource::System => "system java, not the Gateway's own",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedJava {
    pub path: PathBuf,
    pub source: JavaSource,
}

/// The places [`resolve_java`] looks, injectable so tests need no real JRE.
pub struct JavaSearch<'a> {
    pub install_dir: &'a Path,
    pub override_path: Option<&'a str>,
    pub shared_jre_root: &'a Path,
    pub system_candidates: &'a [&'a str],
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// `path` as the resolved Java if it is runnable; otherwise note it as tried.
fn consider(tried: &mut Vec<String>, path: PathBuf, source: JavaSource) -> Option<ResolvedJava> {
    if is_executable_file(&path) {
        Some(ResolvedJava { path, source })
    } else {
        tried.push(path.display().to_string());
        None
    }
}

/// The JRE directory the installer recorded, if it recorded one.
///
/// `inst_jre.cfg` is deliberately not read: it holds the JRE the installer ran
/// with, a temporary folder deleted when the installer exits.
fn recorded_jre(install_dir: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(install_dir.join(".install4j").join("pref_jre.cfg")).ok()?;
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(PathBuf::from(line))
}

/// Find the Java the Gateway install declares, in this order:
///
/// 1. `JAVA_PATH`, if set. A set override that is not runnable is an error,
///    never a quiet fall-through to some other Java.
/// 2. `<install>/jre/bin/java`, bundled with the install.
/// 3. The shared JRE recorded in `<install>/.install4j/pref_jre.cfg`.
/// 4. A scan of the shared JRE root (`<id>/bin/java` or `<id>/<jre>/bin/java`).
/// 5. Java on the PATH, with a warning.
///
/// The error names every place it looked.
pub fn resolve_java(search: &JavaSearch) -> Result<ResolvedJava, SupervisorError> {
    if let Some(override_path) = search.override_path {
        let as_home = Path::new(override_path).join("bin").join("java");
        for candidate in [as_home, PathBuf::from(override_path)] {
            if is_executable_file(&candidate) {
                return Ok(ResolvedJava { path: candidate, source: JavaSource::Override });
            }
        }
        return Err(SupervisorError::JavaOverrideInvalid(override_path.to_string()));
    }

    let mut tried: Vec<String> = Vec::new();

    if let Some(found) = consider(&mut tried, search.install_dir.join("jre").join("bin").join("java"), JavaSource::Bundled) {
        return Ok(found);
    }

    let record = search.install_dir.join(".install4j").join("pref_jre.cfg");
    match recorded_jre(search.install_dir) {
        Some(jre) => {
            if let Some(found) = consider(&mut tried, jre.join("bin").join("java"), JavaSource::InstallerRecord) {
                return Ok(found);
            }
        }
        None => tried.push(format!("{} (no record)", record.display())),
    }

    let mut scanned: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(search.shared_jre_root) {
        for entry in entries.flatten() {
            let dir = entry.path();
            scanned.push(dir.join("bin").join("java"));
            if let Ok(subs) = std::fs::read_dir(&dir) {
                scanned.extend(subs.flatten().map(|s| s.path().join("bin").join("java")));
            }
        }
    }
    scanned.sort();
    if let Some(found) = scanned.into_iter().find(|p| is_executable_file(p)) {
        log::warn!(
            "Gateway Java found by scanning {} — the install does not record it",
            search.shared_jre_root.display()
        );
        return Ok(ResolvedJava { path: found, source: JavaSource::SharedScan });
    }
    tried.push(format!("{}/**/bin/java", search.shared_jre_root.display()));

    for candidate in search.system_candidates {
        if let Some(found) = consider(&mut tried, PathBuf::from(candidate), JavaSource::System) {
            log::warn!(
                "Gateway Java: falling back to {} — the install in {} declares no Java of its own",
                found.path.display(),
                search.install_dir.display()
            );
            return Ok(found);
        }
    }

    Err(SupervisorError::JavaNotFound(tried.join(", ")))
}

/// Detect the Gateway/TWS version directory, relative to `tws_path`.
///
/// Gateway lives at `{tws_path}/ibgateway/{version}/`; TWS directly under
/// `{tws_path}/{version}/`. A version directory is one that contains `jars/`.
pub fn detect_version(config: &GatewayConfig, tws_path: &Path) -> Result<String, SupervisorError> {
    if !config.version.is_empty() {
        return Ok(config.version.clone());
    }

    let gw_dir = tws_path.join("ibgateway");
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

    Err(SupervisorError::VersionDetectionFailed(tws_path.display().to_string()))
}

/// The install folder for `version`: the first candidate that has `jars/`.
pub fn locate_install(tws_path: &Path, version: &str) -> Result<PathBuf, SupervisorError> {
    let candidates = [tws_path.join(version), tws_path.join("ibgateway").join(version)];
    candidates
        .iter()
        .find(|dir| dir.join("jars").exists())
        .cloned()
        .ok_or_else(|| {
            let tried: Vec<_> = candidates.iter().map(|d| d.join("jars").display().to_string()).collect();
            SupervisorError::NoJars(tried.join(", "))
        })
}

/// Everything a Gateway launch needs, resolved once.
#[derive(Debug)]
pub struct LaunchPlan {
    pub version: String,
    pub install_dir: PathBuf,
    pub classpath: String,
    pub jar_count: usize,
    pub vmoptions_file: Option<PathBuf>,
    pub vm_opts: Vec<String>,
    /// Java options the installer's own launcher passes (`javaOptions` in
    /// `.install4j/i4jparams.conf`) that ibctl's own flags and the vmoptions
    /// file do not already cover. They can carry values that are secrets to
    /// log, so only their count is ever logged.
    pub installer_opts: Vec<String>,
    pub java: ResolvedJava,
}

/// The Java options the installer's own launcher passes to the Gateway: the
/// `javaOptions` variable in `.install4j/i4jparams.conf`. Empty when the install
/// has no such file or variable (the 10.47 layout declares none that matter).
///
/// Gateway 10.48 and later bundle a Java whose XML parser limits are too tight
/// for the Gateway's own settings file; this variable is where the installer
/// relaxes them. Launching without it makes the Gateway report its settings
/// file as missing and start on defaults.
pub fn installer_java_options(install_dir: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(install_dir.join(".install4j").join("i4jparams.conf")) else {
        return Vec::new();
    };
    let Some(name_at) = text.find("name=\"javaOptions\"") else {
        return Vec::new();
    };
    let tag = &text[name_at..];
    let tag = &tag[..tag.find('>').unwrap_or(tag.len())];
    let Some(value_at) = tag.find("value=\"") else {
        return Vec::new();
    };
    let value = &tag[value_at + "value=\"".len()..];
    let value = &value[..value.find('"').unwrap_or(value.len())];
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// What an option sets, so a second option for the same thing can be told from
/// a different one: `-Dname` for a system property, the whole option for a
/// module flag (many `--add-opens` can differ), the part before `=` otherwise.
fn option_key(option: &str) -> &str {
    if let Some(prop) = option.strip_prefix("-D") {
        return &option[..2 + prop.find('=').unwrap_or(prop.len())];
    }
    if option.starts_with("--add-opens=") || option.starts_with("--add-exports=") || option.starts_with("--add-reads=") {
        return option;
    }
    option.split('=').next().unwrap_or(option)
}

/// The declared options that `already` does not set, each setting once. The
/// first value wins, as with the JVM's own `-D` handling.
pub fn options_to_add(already: &[&str], declared: &[String]) -> Vec<String> {
    let mut seen: Vec<&str> = already.iter().map(|o| option_key(o)).collect();
    let mut added = Vec::new();
    for option in declared {
        let key = option_key(option);
        if !seen.contains(&key) {
            seen.push(key);
            added.push(option.clone());
        }
    }
    added
}

/// The XML limits the Gateway's settings parser depends on.
const XML_LIMIT_KEYS: &[&str] = &[
    "jdk.xml.elementAttributeLimit",
    "jdk.xml.maxGeneralEntitySizeLimit",
    "jdk.xml.totalEntitySizeLimit",
];

/// Why a launch with `options` on `java` would hit the Java's own XML limits.
///
/// A Java that sets a limit in its `conf/jaxp.properties` enforces it unless a
/// `-D` option overrides it. The Gateway's settings file exceeds the tightened
/// limits of Java 24 and later, so a launch that leaves them in force makes the
/// Gateway treat its own settings file as missing.
pub fn xml_limit_problem(java: &Path, options: &[&str]) -> Option<String> {
    let java_home = java.parent()?.parent()?;
    let text = std::fs::read_to_string(java_home.join("conf").join("jaxp.properties")).ok()?;
    let unrelaxed: Vec<&str> = XML_LIMIT_KEYS
        .iter()
        .copied()
        .filter(|key| {
            let set_by_java = text.lines().map(str::trim).any(|line| {
                line.strip_prefix(key)
                    .and_then(|rest| rest.trim_start().strip_prefix('='))
                    .is_some_and(|v| !v.trim().is_empty() && v.trim() != "0")
            });
            let overridden = options.iter().any(|o| option_key(o) == format!("-D{key}"));
            set_by_java && !overridden
        })
        .collect();
    if unrelaxed.is_empty() {
        None
    } else {
        Some(format!(
            "{} sets {} and the launch options do not override {}, so the Gateway cannot read its own settings",
            java_home.join("conf").join("jaxp.properties").display(),
            if unrelaxed.len() == 1 { "a limit" } else { "limits" },
            unrelaxed.join(", ")
        ))
    }
}

/// Resolve a launch for `config`, looking for Java in the given places.
pub fn plan_launch_with(
    config: &GatewayConfig,
    java_override: Option<&str>,
    shared_jre_root: &Path,
    system_java: &[&str],
) -> Result<LaunchPlan, SupervisorError> {
    let tws_path = Path::new(&config.tws_path);
    let version = detect_version(config, tws_path)?;
    let install_dir = locate_install(tws_path, &version)?;
    let classpath = Supervisor::build_classpath(tws_path, &version)?;
    let jar_count = classpath.split(':').filter(|s| !s.is_empty()).count();

    let vmoptions_file = install_dir.join("ibgateway.vmoptions");
    let (vmoptions_file, vm_opts) = if vmoptions_file.exists() {
        let opts = Supervisor::read_vmoptions(&vmoptions_file)?;
        (Some(vmoptions_file), opts)
    } else {
        (None, Vec::new())
    };

    let java = resolve_java(&JavaSearch {
        install_dir: &install_dir,
        override_path: java_override,
        shared_jre_root,
        system_candidates: system_java,
    })?;

    let mut already: Vec<&str> = crate::supervisor::MODULE_ACCESS_FLAGS.to_vec();
    already.extend(vm_opts.iter().map(String::as_str));
    let installer_opts = options_to_add(&already, &installer_java_options(&install_dir));

    Ok(LaunchPlan { version, install_dir, classpath, jar_count, vmoptions_file, vm_opts, installer_opts, java })
}

/// Resolve a launch for `config` the way production does: `JAVA_PATH` from
/// the environment, the real shared JRE root, Java on the PATH.
pub fn plan_launch(config: &GatewayConfig) -> Result<LaunchPlan, SupervisorError> {
    let java_override = std::env::var("JAVA_PATH").ok().filter(|v| !v.is_empty());
    plan_launch_with(config, java_override.as_deref(), Path::new(SHARED_JRE_ROOT), SYSTEM_JAVA)
}

/// The outcome of one payload check: what was found, or why it failed.
#[derive(Debug)]
pub struct CheckOutcome {
    pub name: &'static str,
    pub result: Result<String, String>,
}

impl CheckOutcome {
    pub fn passed(&self) -> bool {
        self.result.is_ok()
    }
}

/// Run `java -version`; Ok carries the first line it printed.
pub fn java_runs(java: &Path, timeout: Duration) -> Result<String, String> {
    let mut child = Command::new(java)
        .arg("-version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", java.display()))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} -version did not finish within {:?}", java.display(), timeout));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("waiting for {}: {e}", java.display())),
        }
    }
    let output = child.wait_with_output().map_err(|e| format!("reading {} output: {e}", java.display()))?;
    let text = String::from_utf8_lossy(if output.stderr.is_empty() { &output.stdout } else { &output.stderr }).into_owned();
    // The JVM first announces options taken from the environment
    // ("NOTE: Picked up JDK_JAVA_OPTIONS: ...", "Picked up JAVA_TOOL_OPTIONS: ...");
    // the line worth reporting is the version after them.
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.trim_start_matches("NOTE: ").starts_with("Picked up "))
        .unwrap_or("")
        .to_string();
    if output.status.success() {
        Ok(first)
    } else {
        Err(format!("{} -version exited with {}: {first}", java.display(), output.status))
    }
}

/// Check that this image can launch the Gateway it carries, through the same
/// resolution a real launch uses. Stops after a failed plan, since nothing
/// after it can be checked.
pub fn check_payload(
    plan: Result<LaunchPlan, SupervisorError>,
    agent_jar: &Path,
    java_timeout: Duration,
) -> Vec<CheckOutcome> {
    let plan = match plan {
        Ok(plan) => plan,
        Err(e) => return vec![CheckOutcome { name: "launch plan", result: Err(e.to_string()) }],
    };
    let mut checks = vec![
        CheckOutcome {
            name: "install",
            result: Ok(format!("{} at {}", plan.version, plan.install_dir.display())),
        },
        CheckOutcome { name: "jars", result: Ok(format!("{} on the classpath", plan.jar_count)) },
        CheckOutcome {
            name: "vmoptions",
            result: Ok(match &plan.vmoptions_file {
                Some(file) => format!("{} options from {}", plan.vm_opts.len(), file.display()),
                None => "none (the install has no ibgateway.vmoptions)".to_string(),
            }),
        },
        CheckOutcome {
            name: "java",
            result: Ok(format!("{} ({})", plan.java.path.display(), plan.java.source)),
        },
        CheckOutcome { name: "java runs", result: java_runs(&plan.java.path, java_timeout) },
        CheckOutcome {
            name: "xml limits",
            result: {
                let options: Vec<&str> = plan.vm_opts.iter().chain(&plan.installer_opts).map(String::as_str).collect();
                match xml_limit_problem(&plan.java.path, &options) {
                    Some(problem) => Err(problem),
                    None => Ok(format!("{} options from the installer", plan.installer_opts.len())),
                }
            },
        },
    ];
    checks.push(CheckOutcome {
        name: "agent",
        result: if agent_jar.is_file() {
            Ok(agent_jar.display().to_string())
        } else {
            Err(format!("agent jar missing at {}", agent_jar.display()))
        },
    });
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An executable stand-in for a JRE's `bin/java` under `jre_dir`. It prints
    /// what a real `java -version` prints, then runs `extra` (to fail or hang).
    fn fake_java_with(jre_dir: &Path, extra: &str) -> PathBuf {
        let bin = jre_dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let java = bin.join("java");
        write_script(&java, &format!("#!/bin/sh\necho 'openjdk version \"17.0.16\"' >&2\n{extra}\n"));
        java
    }

    /// Write an executable script and return once it can be launched.
    ///
    /// Tests run on parallel threads that fork constantly. A child forked while
    /// this thread still had the script open for writing keeps that handle
    /// until it execs, and launching a file someone has open for writing fails
    /// with ETXTBSY ("Text file busy"). Our own handle is closed when `write`
    /// returns, so once one launch succeeds no writer can appear again.
    fn write_script(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        for _ in 0..400 {
            match Command::new(path).stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
                Ok(mut child) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                Err(e) if e.raw_os_error() == Some(nix::errno::Errno::ETXTBSY as i32) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("cannot launch {}: {e}", path.display()),
            }
        }
        panic!("{} stayed busy for 2 s", path.display());
    }

    fn fake_java(jre_dir: &Path) -> PathBuf {
        fake_java_with(jre_dir, "")
    }

    /// `<tws>/ibgateway/<version>/` with one jar and a vmoptions file.
    fn install_tree(tws: &Path, version: &str) -> PathBuf {
        let install = tws.join("ibgateway").join(version);
        std::fs::create_dir_all(install.join("jars")).unwrap();
        std::fs::write(install.join("jars").join("jts4launch.jar"), b"").unwrap();
        std::fs::write(install.join("ibgateway.vmoptions"), "# vm\n-Xss1m\n-Dignored=1\n").unwrap();
        install
    }

    fn search<'a>(install: &'a Path, shared: &'a Path, system: &'a [&'a str]) -> JavaSearch<'a> {
        JavaSearch { install_dir: install, override_path: None, shared_jre_root: shared, system_candidates: system }
    }

    fn config_for(tws: &Path) -> GatewayConfig {
        GatewayConfig { tws_path: tws.display().to_string(), ..GatewayConfig::default() }
    }

    // ── resolve_java ────────────────────────────────────────────────────

    /// the 10.50.1f layout.
    #[test]
    fn the_java_bundled_inside_the_install_is_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        let bundled = fake_java(&install.join("jre"));
        let shared = tmp.path().join("i4j_jres");

        let java = resolve_java(&search(&install, &shared, &["/usr/bin/java"])).unwrap();

        assert_eq!(java, ResolvedJava { path: bundled, source: JavaSource::Bundled });
    }

    /// The 10.47.1b layout: a shared JRE the installer recorded in pref_jre.cfg.
    #[test]
    fn the_shared_jre_the_installer_recorded_is_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.47.1b");
        let shared = tmp.path().join("i4j_jres");
        let jre = shared.join("Oda-jK0QgTEmVssfllLP").join("17.0.16.0.101-zulu");
        let recorded = fake_java(&jre);
        std::fs::create_dir_all(install.join(".install4j")).unwrap();
        std::fs::write(install.join(".install4j").join("pref_jre.cfg"), format!("{}\n", jre.display())).unwrap();

        let java = resolve_java(&search(&install, &shared, &[])).unwrap();

        assert_eq!(java, ResolvedJava { path: recorded, source: JavaSource::InstallerRecord });
    }

    #[test]
    fn the_bundled_java_wins_over_a_record_and_the_system_java() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        let bundled = fake_java(&install.join("jre"));
        let other = fake_java(&tmp.path().join("other"));
        std::fs::create_dir_all(install.join(".install4j")).unwrap();
        std::fs::write(install.join(".install4j").join("pref_jre.cfg"), tmp.path().join("other").display().to_string()).unwrap();
        let system = other.display().to_string();

        let java = resolve_java(&search(&install, tmp.path(), &[system.as_str()])).unwrap();

        assert_eq!(java.path, bundled);
    }

    #[test]
    fn a_runnable_override_wins_as_a_home_or_as_the_binary() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        fake_java(&install.join("jre"));
        let home = tmp.path().join("custom-jdk");
        let binary = fake_java(&home);
        let home_str = home.display().to_string();
        let binary_str = binary.display().to_string();

        for given in [home_str.as_str(), binary_str.as_str()] {
            let java = resolve_java(&JavaSearch { override_path: Some(given), ..search(&install, tmp.path(), &[]) }).unwrap();
            assert_eq!(java, ResolvedJava { path: binary.clone(), source: JavaSource::Override }, "JAVA_PATH={given}");
        }
    }

    /// An operator who sets JAVA_PATH wrongly must hear about it, not have the
    /// Gateway quietly start on some other Java.
    #[test]
    fn a_set_override_that_does_not_run_is_an_error_not_a_fall_through() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        fake_java(&install.join("jre"));

        let err = resolve_java(&JavaSearch { override_path: Some("/nonexistent/jdk"), ..search(&install, tmp.path(), &[]) })
            .unwrap_err();

        assert!(matches!(err, SupervisorError::JavaOverrideInvalid(ref p) if p == "/nonexistent/jdk"), "{err}");
    }

    #[test]
    fn the_not_found_error_names_every_place_it_looked() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        let shared = tmp.path().join("i4j_jres");

        let err = resolve_java(&search(&install, &shared, &["/nonexistent/java"])).unwrap_err().to_string();

        for place in [
            install.join("jre/bin/java").display().to_string(),
            install.join(".install4j/pref_jre.cfg").display().to_string(),
            shared.display().to_string(),
            "/nonexistent/java".to_string(),
        ] {
            assert!(err.contains(&place), "error does not mention {place}: {err}");
        }
    }

    #[test]
    fn a_java_that_is_not_executable_is_not_used() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        let bundled = fake_java(&install.join("jre"));
        std::fs::set_permissions(&bundled, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = resolve_java(&search(&install, tmp.path(), &[])).unwrap_err();

        assert!(matches!(err, SupervisorError::JavaNotFound(_)), "{err}");
    }

    /// The old mirror-image layout: a shared JRE with no record pointing at it.
    #[test]
    fn an_unrecorded_shared_jre_is_still_found_by_scanning() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.45.1b");
        let shared = tmp.path().join("i4j_jres");
        let scanned = fake_java(&shared.join("abc").join("17.0.10-zulu"));

        let java = resolve_java(&search(&install, &shared, &[])).unwrap();

        assert_eq!(java, ResolvedJava { path: scanned, source: JavaSource::SharedScan });
    }

    #[test]
    fn system_java_is_only_the_last_resort() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        let system = fake_java(&tmp.path().join("usr"));
        let system_str = system.display().to_string();

        let java = resolve_java(&search(&install, &tmp.path().join("none"), &[system_str.as_str()])).unwrap();

        assert_eq!(java, ResolvedJava { path: system, source: JavaSource::System });
    }

    // ── plan_launch ─────────────────────────────────────────────────────

    #[test]
    fn a_plan_for_the_10_50_layout_has_its_jars_vmoptions_and_bundled_java() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        let bundled = fake_java(&install.join("jre"));

        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]).unwrap();

        assert_eq!(plan.version, "ibgateway/10.50.1f");
        assert_eq!(plan.install_dir, install);
        assert_eq!(plan.jar_count, 1);
        assert_eq!(plan.vm_opts, vec!["-Xss1m".to_string()], "comments and -D lines are dropped");
        assert_eq!(plan.java.path, bundled);
    }

    #[test]
    fn a_configured_version_is_found_under_ibgateway() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        fake_java(&install.join("jre"));
        let config = GatewayConfig { version: "10.50.1f".into(), ..config_for(tmp.path()) };

        let plan = plan_launch_with(&config, None, &tmp.path().join("none"), &[]).unwrap();

        assert_eq!(plan.install_dir, install);
    }

    #[test]
    fn a_plan_with_no_install_says_where_it_looked() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = GatewayConfig { version: "10.99.1a".into(), ..config_for(tmp.path()) };

        let err = plan_launch_with(&config, None, &tmp.path().join("none"), &[]).unwrap_err().to_string();

        assert!(err.contains("ibgateway/10.99.1a/jars"), "{err}");
    }

    // ── check_payload ───────────────────────────────────────────────────

    fn agent_jar(dir: &Path) -> PathBuf {
        let jar = dir.join("ibctl-agent.jar");
        std::fs::write(&jar, b"").unwrap();
        jar
    }

    fn failed(checks: &[CheckOutcome]) -> Vec<(&'static str, String)> {
        checks.iter().filter_map(|c| c.result.as_ref().err().map(|e| (c.name, e.clone()))).collect()
    }

    #[test]
    fn a_complete_payload_passes_every_check() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        fake_java(&install.join("jre"));
        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]);

        let checks = check_payload(plan, &agent_jar(tmp.path()), Duration::from_secs(10));

        assert_eq!(failed(&checks), vec![]);
        let runs = checks.iter().find(|c| c.name == "java runs").unwrap();
        assert_eq!(runs.result.as_deref(), Ok("openjdk version \"17.0.16\""));
    }

    /// The JVM announces options it picked up from the environment before the
    /// version; the image sets JDK_JAVA_OPTIONS, so that line came first.
    #[test]
    fn java_runs_reports_the_version_not_the_picked_up_options_notes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let java = bin.join("java");
        write_script(
            &java,
            "#!/bin/sh\n\
             echo 'NOTE: Picked up JDK_JAVA_OPTIONS: -Djava.net.preferIPv4Stack=true' >&2\n\
             echo 'Picked up JAVA_TOOL_OPTIONS: -Xss1m' >&2\n\
             echo 'openjdk version \"25.0.2\" 2026-01-20' >&2\n",
        );

        let runs = java_runs(&java, Duration::from_secs(10));

        assert_eq!(runs.as_deref(), Ok("openjdk version \"25.0.2\" 2026-01-20"));
    }

    /// The exact production failure: no Java anywhere the install declares.
    #[test]
    fn a_payload_with_no_java_fails_with_the_reason() {
        let tmp = tempfile::TempDir::new().unwrap();
        install_tree(tmp.path(), "10.50.1f");
        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]);

        let checks = check_payload(plan, &agent_jar(tmp.path()), Duration::from_secs(10));

        let failures = failed(&checks);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].0, "launch plan");
        assert!(failures[0].1.contains("jre/bin/java"), "{}", failures[0].1);
    }

    #[test]
    fn a_java_that_cannot_run_fails_the_payload() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        fake_java_with(&install.join("jre"), "exit 3");
        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]);

        let checks = check_payload(plan, &agent_jar(tmp.path()), Duration::from_secs(10));

        let failures = failed(&checks);
        assert_eq!(failures.iter().map(|f| f.0).collect::<Vec<_>>(), vec!["java runs"]);
        assert!(failures[0].1.contains("exited with"), "{}", failures[0].1);
    }

    #[test]
    fn a_java_that_hangs_fails_the_payload_instead_of_hanging_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        fake_java_with(&install.join("jre"), "exec sleep 30");
        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]);

        let checks = check_payload(plan, &agent_jar(tmp.path()), Duration::from_millis(200));

        let failures = failed(&checks);
        assert_eq!(failures.iter().map(|f| f.0).collect::<Vec<_>>(), vec!["java runs"]);
        assert!(failures[0].1.contains("did not finish"), "{}", failures[0].1);
    }

    #[test]
    fn a_missing_agent_jar_fails_the_payload() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        fake_java(&install.join("jre"));
        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]);

        let checks = check_payload(plan, &tmp.path().join("missing.jar"), Duration::from_secs(10));

        assert_eq!(failed(&checks).iter().map(|f| f.0).collect::<Vec<_>>(), vec!["agent"]);
    }

    // ── the installer's own Java options ────────────────────────────────

    const I4J_PARAMS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<config>
    <variable name="winDigest" value="SHA-2" />
    <variable name="javaOptions" value="--enable-native-access=ALL-UNNAMED,javafx.graphics --add-opens=java.base/java.util=ALL-UNNAMED --add-exports=javafx.web/com.sun.webkit=ALL-UNNAMED -Djdk.xml.elementAttributeLimit=10000 -Djdk.xml.maxGeneralEntitySizeLimit=0 -Djdk.xml.totalEntitySizeLimit=0 -DjxBrowserKey=test-key" />
</config>
"#;

    fn write_i4j_params(install: &Path, body: &str) {
        std::fs::create_dir_all(install.join(".install4j")).unwrap();
        std::fs::write(install.join(".install4j").join("i4jparams.conf"), body).unwrap();
    }

    /// The Gateway reads its own settings with XML limits that its bundled Java
    /// tightens; the installer's launcher relaxes them through this variable.
    #[test]
    fn the_java_options_the_installer_declares_are_read_from_its_params_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        write_i4j_params(&install, I4J_PARAMS);

        let opts = installer_java_options(&install);

        assert_eq!(opts.len(), 7, "{opts:?}");
        assert_eq!(opts[0], "--enable-native-access=ALL-UNNAMED,javafx.graphics");
        assert!(opts.contains(&"-Djdk.xml.elementAttributeLimit=10000".to_string()));
        assert!(opts.contains(&"-Djdk.xml.totalEntitySizeLimit=0".to_string()));
        assert!(opts.contains(&"-DjxBrowserKey=test-key".to_string()));
    }

    #[test]
    fn xml_escapes_in_the_declared_options_are_decoded() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        write_i4j_params(&install, r#"<variable name="javaOptions" value="-Dsome.path=&quot;a&amp;b&quot;" />"#);

        assert_eq!(installer_java_options(&install), vec![r#"-Dsome.path="a&b""#.to_string()]);
    }

    #[test]
    fn an_install_without_a_params_file_or_the_variable_declares_no_options() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.47.1b");
        assert!(installer_java_options(&install).is_empty(), "no params file");

        write_i4j_params(&install, r#"<variable name="winDigest" value="SHA-2" />"#);
        assert!(installer_java_options(&install).is_empty(), "no javaOptions variable");

        write_i4j_params(&install, r#"<variable name="javaOptions" value="" />"#);
        assert!(installer_java_options(&install).is_empty(), "empty javaOptions");
    }

    #[test]
    fn only_options_not_already_passed_are_added() {
        let declared: Vec<String> = [
            "--add-opens=java.base/java.util=ALL-UNNAMED", // already passed, exact
            "--add-exports=javafx.web/com.sun.webkit=ALL-UNNAMED", // new
            "-Djdk.xml.elementAttributeLimit=10000",       // new
            "-Dchannel=beta",                              // same property as one already passed
            "-Djdk.xml.elementAttributeLimit=50",          // repeats a declared one
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let already = ["--add-opens=java.base/java.util=ALL-UNNAMED", "-Dchannel=latest"];

        let added = options_to_add(&already, &declared);

        assert_eq!(
            added,
            vec![
                "--add-exports=javafx.web/com.sun.webkit=ALL-UNNAMED".to_string(),
                "-Djdk.xml.elementAttributeLimit=10000".to_string(),
            ]
        );
    }

    #[test]
    fn the_launch_plan_carries_what_the_installer_declares_beyond_ibctls_own_flags() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        fake_java(&install.join("jre"));
        write_i4j_params(&install, I4J_PARAMS);

        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]).unwrap();

        // java.base/java.util is one of ibctl's own flags already.
        assert!(!plan.installer_opts.iter().any(|o| o.starts_with("--add-opens=java.base/java.util=")));
        assert!(plan.installer_opts.contains(&"-Djdk.xml.maxGeneralEntitySizeLimit=0".to_string()));
        assert!(plan.installer_opts.contains(&"--add-exports=javafx.web/com.sun.webkit=ALL-UNNAMED".to_string()));
    }

    // ── the XML limits check ────────────────────────────────────────────

    fn jre_with_jaxp(jre: &Path, jaxp: &str) {
        fake_java(jre);
        std::fs::create_dir_all(jre.join("conf")).unwrap();
        std::fs::write(jre.join("conf").join("jaxp.properties"), jaxp).unwrap();
    }

    const STRICT_JAXP: &str = "# defaults\njdk.xml.elementAttributeLimit=200\njdk.xml.totalEntitySizeLimit=100000\njdk.xml.maxGeneralEntitySizeLimit=100000\n";

    #[test]
    fn a_java_with_strict_xml_limits_and_no_relaxing_options_fails_the_payload() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        jre_with_jaxp(&install.join("jre"), STRICT_JAXP);
        // The installer declares nothing, so nothing relaxes the limits.
        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]);

        let checks = check_payload(plan, &agent_jar(tmp.path()), Duration::from_secs(10));

        let failures = failed(&checks);
        assert_eq!(failures.iter().map(|f| f.0).collect::<Vec<_>>(), vec!["xml limits"]);
        assert!(failures[0].1.contains("jdk.xml.elementAttributeLimit"), "{}", failures[0].1);
    }

    #[test]
    fn strict_xml_limits_pass_when_the_launch_options_relax_them() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.50.1f");
        jre_with_jaxp(&install.join("jre"), STRICT_JAXP);
        write_i4j_params(&install, I4J_PARAMS);
        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]);

        let checks = check_payload(plan, &agent_jar(tmp.path()), Duration::from_secs(10));

        assert!(failed(&checks).is_empty(), "{:?}", failed(&checks));
    }

    #[test]
    fn a_java_that_sets_no_xml_limits_needs_no_relaxing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = install_tree(tmp.path(), "10.47.1b");
        jre_with_jaxp(&install.join("jre"), "# nothing set\n");
        let plan = plan_launch_with(&config_for(tmp.path()), None, &tmp.path().join("none"), &[]);

        let checks = check_payload(plan, &agent_jar(tmp.path()), Duration::from_secs(10));

        assert!(failed(&checks).is_empty(), "{:?}", failed(&checks));
    }
}
