# Incident Report — 2026-04-16 — False-Connected State (Silent)

## Severity: CRITICAL (score 7/10) — L2 module boundary invariant violation

## Summary

On 2026-04-16 at approximately 05:06 UTC, both LIVE and PAPER state machines
entered the `Connected` state while the underlying IB Gateway was still
displaying its login form with API Server status labeled "disconnected".
The dashboard advertised "Connected · 3 clients" / "Connected · 4 clients"
for roughly one hour before the user noticed via VNC. No alert fired. No
recovery attempted. Clients connecting to the published ports would have
reached a non-functional Gateway.

## Timeline (UTC)

- 04:48 — State machine begins login cycle after prior session loss
- 04:50-04:57 — Multiple ReconnectingSession / WaitingFor2fa attempts
- 04:57:54 — Liveness check correctly detected login form; state → WaitingForLogin
- 05:00:29 — 2FA timeout → Restarting
- 05:02:04 — JVM relaunched, login retried
- 05:02:28-05:03:25 — WaitingForApiReady bounced back to WaitingFor2fa twice (fail-closed re-entry)
- 05:04:13 — DismissingPopups → WaitingForApiReady
- 05:05:20-05:06:14 — Label inspection found 5 labels, 0 textfields, but no "connected" string (60 samples over ~60s)
- **05:06:14** — **WaitingForApiReady timed out at 120s; transitioned to ConfiguringApi on fail-OPEN**
- 05:06:14-42 — ApiConfig retried 3 times; configuration dialog never found (Gateway at login form)
- **05:06:42** — **ConfiguringApi exhausted retries; transitioned to Connected on fail-OPEN** (false state entry)
- 05:06:42 onward — No further state transitions. Active liveness check at line 1437 fired every 30s but inspected the `tables` array (always empty for the Connection Status view) rather than the `labels` array where "disconnected" actually appears
- 06:00-ish — User observed via VNC that both gateways were at the login form and API Server label said "disconnected" (red); dashboard still showed both as Connected
- 06:05 — Manual RESTART commands issued to break the false-Connected state

## Failure Record

**Symptom:** State machine reported `Connected` and published it to dashboard,
ZMQ pub socket, and query snapshot, while underlying Gateway was at login form
with API Server disconnected. No clients could trade. No alert fired.

**Surface layer:** L2 (module boundary) — invariant violation spanning three
state-handler functions (`do_api_ready`, `do_configure_api`, `do_connected`).

**Trigger path:**

1. Upstream 2FA failure put Gateway in a broken state (login form persistent, no API server)
2. `do_api_ready` timed out at 120s without ever confirming "connected" — **fail-open** (returned `State::ConfiguringApi`)
3. `do_configure_api` retried 3 times; config dialog unreachable because Gateway is at login form — **fail-open** (returned `State::Connected`)
4. `do_connected` ran its active liveness check but inspected `components["tables"]` which is empty. The actual Connection Status is rendered as JLabels (`labels` array contains `["Purpose","Status","API Server","disconnected","IBKR GATEWAY"]`). The check never triggered.

**Suspected invariant:** _"The state machine MUST NOT enter `Connected` without positive evidence that the API Server is actually connected. The state machine MUST be able to detect disconnection from any post-Connected observation."_

**Blast radius:** Dashboard, ZMQ subscribers, TCP clients, any dependent trading
system. Silent failure for ~60 minutes. Severity would have been higher during
market hours; this fired during off-hours.

## Severity Scoring

| Factor | Applies | Rationale |
|---|---|---|
| Affects persistence/data integrity | 0 | State is ephemeral |
| Affects money/security/safety | 1 | Trading decisions based on false connection signals |
| Breaks public API | 1 | Published STATUS says connected while socat forwards to dead port |
| Cross-module failure | 1 | Rust state machine + Java agent + dashboard UI |
| Non-deterministic/intermittent | 1 | Only happens after 2FA-failure cycle |
| Hard to observe/poor logs | 1 | No alert, no error log, silent false-positive |
| Requires repeated patches | 1 | Multiple commits recently touched this area |
| Creates branching/special-cases | 1 | Fail-open paths are special cases for "unknown state" |
| Impacts performance | 0 | No perf impact |
| Impacts multiple user-facing behaviors | 1 | Dashboard lies, clients connect to dead gateway |

**Score: 7/10 → Escalation budget: 4**

## Layer Climb

1. **L1 (logic)** — Liveness check reads wrong component array
   - Invariant: "inspect all UI representations that could encode status"
   - L1 owns part of the fix, but doesn't own the systemic issue — escalate

2. **L2 (module)** — State-transition handlers violate their contract
   - `do_api_ready` contract: "only return `ConfiguringApi` when API server is confirmed connected"
   - `do_configure_api` contract: "only return `Connected` when configuration succeeded (or was cleanly skipped by design)"
   - Both violated via fail-open defaults — **target layer**

3. **L3 (interface)** — Philosophy: "fail-open" propagates bad state across boundaries
   - Already partially addressed by prior commit 488fbdc ("fail-closed state verification")
   - The two specific sites that remained fail-open are artifacts of incremental tightening, not intentional design

## Fix

**L1 — Liveness check reads labels instead of tables** (`state_machine/mod.rs`):

```rust
// BEFORE: checked components["tables"] for API Server row (always empty)
// AFTER:  checks components["labels"] for "api server" + "disconnected" tokens
if let Some(labels) = components.get("labels").and_then(|l| l.as_array()) {
    let label_texts: Vec<String> = labels.iter()
        .filter_map(|l| l.as_str())
        .map(|s| s.to_lowercase())
        .collect();
    let has_api_server = label_texts.iter().any(|s| s.contains("api server"));
    let has_disconnected = label_texts.iter().any(|s| s == "disconnected");
    if has_api_server && has_disconnected {
        log::warn!("Liveness check FAILED — API Server label: disconnected");
        return Ok(State::WaitingForLogin);
    }
}
```

**L2 — WaitingForApiReady fail-closes on 120s timeout** (`state_machine/mod.rs:1132`):

```rust
// BEFORE: return Ok(State::ConfiguringApi) (fabricated progress)
// AFTER:  return Ok(State::Restarting) — kill JVM, start clean
```

**L2 — ConfiguringApi fail-closes on 3 retry exhaustion** (`state_machine/mod.rs:1185`):

```rust
// BEFORE: return Ok(State::Connected) (fabricated success)
// AFTER:  return Ok(State::Restarting) — kill JVM, start clean
```

## Propagation

- `abort_client_id_task()` called on both new fail-closed paths to prevent leaked watchers
- No downstream "coping logic" to remove — dashboard and socat will observe `Restarting` and react correctly
- Existing `session_lost` monitor suppression window (±5 min of scheduled restarts) still applies

## Tripwires Added

- [x] Structured log: `"restarting JVM (fail-closed)"` at both new fail-closed sites
- [x] Log at liveness-check detection: `"Liveness check FAILED — API Server label: disconnected"`
- [ ] TODO: integration test for WaitingForApiReady where Gateway never reports connected
- [ ] TODO: add a cross-layer invariant: if `Connected` entered and observation cache shows login form OR disconnected label for N consecutive ticks, emit alert AND transition

## Lessons

1. **Fail-open is a contract violation dressed as resilience.** Every fail-open
   transition is equivalent to saying "I don't know what state we're in, but
   I'll pretend we succeeded". The cost of that lie is propagated to every
   downstream observer.

2. **UI state has multiple representations — inspect all of them or inspect
   the source of truth.** Gateway renders the same logical state (API Server
   connected/disconnected) as either JLabels OR a JTable depending on the
   window variant. Checking only one misses half the cases. Future label
   inspection code should iterate *all* text components.

3. **"Should never happen" state happened.** The invariant "state machine
   reaches Connected only when connected" was asserted but not enforced. It
   must be enforced with positive evidence at every transition boundary,
   not assumed from context.

## Follow-ups

- [ ] Add a cross-layer consistency monitor (L4): dashboard/external observer
      that compares state machine's reported `Connected` against a direct
      TCP probe of the API port and alerts on disagreement
- [ ] Audit remaining state handlers for other fail-open patterns
- [ ] Document in `architecture.md`: fail-closed is the contract for all
      transitions into `Connected`; any exception requires a written rationale
