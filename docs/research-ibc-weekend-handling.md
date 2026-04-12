# IBC & gnzsnz Weekend Handling Research

Research into how IBC (IB Controller) and gnzsnz ib-gateway-docker handle IB Gateway being unavailable during weekends.

## Findings

**1. IBC's LoginDialogDisplayTimeout** (`config.ini`, `SessionManager.java`): Default 60 seconds. If the login dialog GUI never renders, IBC exits with code 1112 (88 mod 256). The `ibcstart.sh` shell loop auto-restarts on this specific exit code. But this is for GUI rendering failures, not server unavailability.

**2. The weekend-relevant path is `NotCurrentlyAvailableDialogHandler.java`**: When IB servers are offline, Gateway shows a "not currently available" dialog. IBC clicks OK, sends Alt+F4 to kill the login frame, and exits *normally*. The shell script loop then **breaks** (does not restart) unless an autorestart file exists. This is a terminal exit -- no retry, no backoff.

**3. `LoginFailedDialogHandler.java` and `LoginErrorDialogHandler.java`** both trigger cold restarts (clean shutdown + the shell loop restarts IBC). `TooManyFailedLoginAttemptsDialogHandler.java` parses the wait time from the dialog and schedules a re-login after the specified delay.

**4. gnzsnz adds zero weekend logic.** No HEALTHCHECK in Dockerfile, no weekend detection, no retry logic. It relies entirely on `docker restart: always` + IBC's internal behavior. This creates a **restart loop during the maintenance window** (~240-360 cycles over 6 hours).

**5. IBC's `ColdRestartTime`** (`IbcTws.java`) is the closest thing to weekend handling -- it schedules a Sunday cold restart after 01:00 US/Eastern. But it only controls *when* to restart on Sunday, not how to handle failures during the maintenance window.

**6. `ExistingSessionDetectedAction`** is completely unrelated to server availability. It handles concurrent login conflicts with 4 modes: manual/primary/primaryoverride/secondary.

**Bottom line: Neither IBC nor gnzsnz gracefully handle the weekend maintenance window. IBC exits; Docker/systemd restart policies create a tight restart loop. For ibctl, you need your own weekend-aware logic -- time-based maintenance window detection, exponential backoff, or IB system status checking.**

## Warm Restart / Autorestart Mechanism

Research into how IB Gateway resumes sessions without re-authentication after a JVM restart.

### How It Works

When IB Gateway exits (crash or clean shutdown), it writes a session state file to `$TWS_SETTINGS_PATH/<session_hash>/autorestart`. This marker file's existence tells Gateway "a session existed before shutdown — try to resume it."

On relaunch, passing `-Drestart=<session_hash>` as a JVM flag triggers Gateway's internal session resume logic. Gateway validates the session hash with IB servers and skips the full authentication flow (no username, no password, no 2FA).

### IBC's Implementation

IBC uses the same mechanism. Its `ibcstart.sh` shell loop checks for the autorestart file after the JVM exits. If present, the script relaunches with `-Drestart`. If absent, IBC falls through to cold authentication.

**Critical workaround shared by both IBC and ibctl:** The install4j launcher (`$TWS_PATH/<version>/ibgateway` executable) has its own auto-restart mechanism that races against the supervisor. Both IBC and ibctl rename this executable to `ibgateway.ibctl-disabled` on every launch to prevent install4j from consuming the autorestart token before the supervisor reads it.

### Session State Files

```
$TWS_SETTINGS_PATH/
├── <session_hash>/
│   ├── autorestart           # Marker file — existence = warm restart possible
│   └── [binary session data] # Cached session state
├── jts.ini                   # Gateway config (NOT session state)
└── .iborder                  # Order cache (NOT session state)
```

The session hash directory name varies per session. ibctl scans `$TWS_SETTINGS_PATH` for any subdirectory containing an `autorestart` file.

### Timing

- **Warm restart window:** if JVM restarts within a few minutes, session resume is virtually guaranteed.
- **Inactivity expiry:** sessions may expire after ~1 hour of complete inactivity (no API calls, no heartbeats) — untested exact limit.
- **Maintenance windows:** sessions are forcefully closed during IB's scheduled maintenance. Warm restart won't work across maintenance boundaries.
- **ibctl timeout:** 120 seconds. If Gateway doesn't self-authenticate within this window, ibctl falls back to cold auth.

### Server-Side Validation

The autorestart mechanism is **server-validated**. IB servers check the session hash and (likely) the client's source IP. The session token alone isn't sufficient — the server probably requires the same IP address to accept the resume.

**Evidence:** the autorestart file is designed for same-host JVM restarts (container restart, process crash recovery), not for session migration across hosts.

### Cross-Host Portability (Untested)

**Question:** can the autorestart session be used from a different host (failover site)?

**Theory:** copy `$TWS_SETTINGS_PATH/<session_hash>/autorestart` to the standby host and launch with `-Drestart=<session_hash>`. If IB servers don't enforce IP affinity, the failover site could resume without re-authentication.

**Unknowns:**
- Whether IB servers bind sessions to source IP (likely yes)
- Whether the session hash contains host-specific data
- Whether `jts.ini` state must also match
- Whether there's a crypto binding (client cert, machine ID) in the session

**If IP-bound:** failover requires cold auth (full login + 2FA). The autorestart file is useless from a different IP.

**If NOT IP-bound:** near-instant failover (2-10 seconds, no 2FA). This would be worth testing by copying the autorestart directory to a standby host and launching with the flag.
