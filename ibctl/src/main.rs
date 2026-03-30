//! ibctl — IBC replacement for automated IB Gateway/TWS login and session management.
//!
//! Launches IB Gateway with a Java agent for Swing UI automation, manages the login
//! flow (credentials, 2FA, session conflicts, popups), and provides an IBC-compatible
//! TCP command server for external tooling.

mod agent_client;
mod cold_restart;
mod command_server;
mod config;
mod handlers;
mod signals;
mod state_machine;
mod supervisor;
mod totp;

use std::process::ExitCode;

use config::Config;

fn main() -> ExitCode {
    // Parse CLI args (minimal, no clap dependency)
    let args: Vec<String> = std::env::args().collect();
    let config_path = parse_config_arg(&args);

    // Load configuration (defaults -> TOML file -> env vars)
    let config = match Config::load(config_path.as_deref()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            return ExitCode::from(1);
        }
    };

    // Set env vars BEFORE starting tokio runtime (std::env::set_var is UB in
    // multi-threaded context — SEC-04 fix)
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", format!("ibctl={}", config.logging.level));
    }
    std::env::set_var("IBCTL_AGENT_TICK_MS", config.timing.agent_tick_ms.to_string());

    // Initialize logging
    env_logger::init();

    log::info!("ibctl v{} starting", env!("CARGO_PKG_VERSION"));

    // Validate config
    if let Err(e) = config.validate() {
        log::error!("Configuration validation failed: {}", e);
        return ExitCode::from(1);
    }

    // Build the tokio runtime and run the async main
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    match rt.block_on(async_main(config)) {
        Ok(()) => {
            log::info!("ibctl exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            log::error!("ibctl exiting with error: {}", e);
            ExitCode::from(1)
        }
    }
}

/// Async entry point: sets up all components and runs the state machine.
async fn async_main(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // Set up signal handling (SIGTERM, SIGINT -> channel)
    let signal_rx = signals::setup_signal_handler()?;

    // Create the agent client (HTTP+JSON over Unix domain socket)
    let agent_client = agent_client::AgentClient::new(&config.agent.socket_path);

    // Create the JVM supervisor
    // TODO: Determine the actual agent jar path (alongside the ibctl binary or configured)
    let agent_jar_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("ibctl-agent.jar")))
        .unwrap_or_else(|| std::path::PathBuf::from("ibctl-agent.jar"));

    let supervisor = supervisor::Supervisor::new(
        config.gateway.clone(),
        &agent_jar_path,
        config.agent.socket_path.clone(),
        config.timing.jvm_shutdown_timeout_secs,
    );

    // Create the dialog handler registry with all built-in handlers
    let handler_registry = handlers::DialogHandlerRegistry::with_defaults(&config);

    // Start the TCP command server (IBC-compatible + JSON queries for dashboard)
    let (command_tx, command_rx) = tokio::sync::mpsc::channel(32);
    let (query_tx, query_rx) = tokio::sync::mpsc::channel(32);
    if config.command_server.enabled {
        let cmd_server = command_server::CommandServer::new(config.command_server.clone());
        tokio::spawn(async move {
            if let Err(e) = cmd_server.run(command_tx, query_tx).await {
                log::error!("Command server failed: {}", e);
            }
        });
        log::info!(
            "Command server enabled on {}:{}",
            config.command_server.bind_address,
            config.command_server.port
        );
    }

    // Start cold restart timer (Sunday weekly restart — IBC's ColdRestartTime)
    // Gateway does NOT have a built-in cold restart. IBC implements its own timer,
    // and so does ibctl. The timer fires on Sunday at the configured time, kills
    // the JVM, and the state machine relaunches with full re-auth.
    let (cold_restart_tx, cold_restart_rx) = tokio::sync::mpsc::channel(1);
    let cold_restart_time = std::env::var("TWS_COLD_RESTART").unwrap_or_default();
    let _cold_restart_handle = cold_restart::spawn_cold_restart_scheduler(
        cold_restart_time,
        cold_restart_tx,
    );

    // Create and run the state machine
    let mut state_machine = state_machine::StateMachine::new(
        config,
        agent_client,
        supervisor,
        handler_registry,
        signal_rx,
        command_rx,
        query_rx,
        cold_restart_rx,
    );

    state_machine.run().await?;

    Ok(())
}

/// Parse the `--config <path>` CLI argument.
fn parse_config_arg(args: &[String]) -> Option<String> {
    let mut iter = args.iter().skip(1); // Skip binary name
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                return iter.next().cloned();
            }
            _ if arg.starts_with("--config=") => {
                return Some(arg.trim_start_matches("--config=").to_string());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("ibctl {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                print_usage();
                std::process::exit(1);
            }
        }
    }
    None
}

/// Print usage information.
fn print_usage() {
    eprintln!(
        "Usage: ibctl [OPTIONS]\n\
         \n\
         Options:\n\
         \x20 -c, --config <PATH>  Path to TOML config file (default: ibctl.toml)\n\
         \x20 -h, --help           Print help\n\
         \x20 -V, --version        Print version\n\
         \n\
         Environment variables override config file values. See ibctl.toml.example\n\
         for the full list of configuration options."
    );
}

