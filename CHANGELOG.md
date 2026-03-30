# Changelog

## [0.2.2] - 2026-03-30

### Security
- Passwords use `secrecy::SecretString` — zeroed on drop, redacted in Debug
- TOTP secret piped via stdin to oathtool (no longer visible in /proc/cmdline)
- Removed NOPASSWD sudoers and sudo package from Docker image
- UDS agent socket moved to /run/ibctl/ with 700 permissions
- Added `cargo audit` to CI pipeline
- Added global pre-commit hook for credential scanning (detect-secrets)

### Fixed
- CIDR subnet matching in `is_allowed()` (was string-only comparison)
- `supervisor.wait()` no longer blocks tokio runtime (now async polling)
- `supervisor.kill()` no longer blocks tokio runtime (async sleep)
- TOTP generation uses `spawn_blocking` to avoid blocking runtime
- ConfiguringApi state retries capped at 10, then restarts Gateway
- `TotpProvider::Builtin` returns clear error instead of silent oathtool fallback
- Socat zombie process prevented via `Drop` impl on `StateMachine`
- `find_java()` no longer spawns blocking `which` subprocess
- LOGS query returns explicit `not_implemented` error instead of fake empty array

### Changed
- 7 stringly-typed config fields converted to proper Rust enums
  (TradingMode, TotpProvider, TwoFaTimeoutAction, GatewayProgram,
   SessionAction, AcceptIncoming, LogLevel)
- Credential resolution deduplicated — handlers use Config directly
- `ApiConfigSettings::from_env()` replaces misleading `from_config()`
- Socat ports configurable via `[gateway]` config section
- State machine constructor uses `Channels` struct (was 8 separate args)
- Extracted `client_advisory()` pure function from state machine
- Extracted `parse_time_with_ampm()` and `PRECAUTION_LABELS` from api_config
- 10+ dead code items removed (zero compiler warnings)

### Added
- CI workflow: `cargo test` + `cargo clippy` + `cargo audit` on every push/PR
- Docker HEALTHCHECK via command server STATUS endpoint
- `.dockerignore` to reduce build context
- 57 unit tests across command_server, config, cold_restart, api_config, state_machine
- TCP command server rate limiting (max 10 concurrent connections)

## [0.2.1] - 2026-03-30

### Fixed
- TOML parser handles unknown sections (`[dashboard]`) via serde flatten
- `TimingConfig` tolerates partial TOML with `serde(default)`

## [0.2.0] - 2026-03-30

- Initial release — fresh repo after credential rotation
- Rust binary + Java agent replacing IBC for IB Gateway automation
- State machine with 11 states, 10+ dialog handlers
- HTTP+JSON over Unix domain socket for Rust-Java IPC
- IBC wire-compatible TCP command server
- Sunday cold restart timer
- Socat port forwarding owned by state machine
- Docker multi-stage build with GitHub Actions release workflow
