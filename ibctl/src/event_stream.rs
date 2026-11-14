//! NDJSON event stream reader for the Java agent's multiplexed socket.
//!
//! Connects to the agent's Unix domain socket, sends `SUBSCRIBE\n` to
//! switch to event stream mode, then reads newline-delimited JSON events
//! into a bounded mpsc channel for the state machine's select! loop.
//!
//! Reconnects automatically with exponential backoff on disconnect.
//! The event stream is additive — the state machine still works
//! (via degraded polling) if the stream is unavailable.

use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::agent_events::AgentEvent;

/// Spawn a background task that reads the agent's NDJSON event stream.
///
/// Returns a bounded receiver. The task reconnects on disconnect with
/// exponential backoff (100ms → 5s). Dropping the receiver stops the task.
pub fn spawn_event_reader(
    socket_path: PathBuf,
    buffer_size: usize,
) -> mpsc::Receiver<AgentEvent> {
    let (tx, rx) = mpsc::channel(buffer_size);

    tokio::spawn(async move {
        let mut backoff_ms = 100u64;
        let max_backoff_ms = 5_000u64;

        loop {
            match UnixStream::connect(&socket_path).await {
                Ok(mut stream) => {
                    // Send SUBSCRIBE to switch connection to event stream mode
                    if let Err(e) = stream.write_all(b"SUBSCRIBE\n").await {
                        log::warn!("Failed to send SUBSCRIBE: {}", e);
                        continue;
                    }

                    backoff_ms = 100; // reset on successful connect
                    log::info!("Connected to agent event stream at {}", socket_path.display());

                    let reader = BufReader::new(stream);
                    let mut lines = reader.lines();

                    loop {
                        match lines.next_line().await {
                            Ok(Some(line)) => {
                                if line.trim().is_empty() {
                                    continue;
                                }
                                match serde_json::from_str::<AgentEvent>(&line) {
                                    Ok(event) => {
                                        if tx.send(event).await.is_err() {
                                            log::info!("Event channel closed — shutting down event reader");
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "Failed to parse agent event: {} (line: {})",
                                            e,
                                            &line[..line.len().min(200)]
                                        );
                                    }
                                }
                            }
                            Ok(None) => {
                                log::info!("Agent event stream ended (EOF)");
                                break;
                            }
                            Err(e) => {
                                log::warn!("Agent event stream read error: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    log::debug!(
                        "Event stream connect failed: {} (retry in {}ms)",
                        e,
                        backoff_ms
                    );
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(max_backoff_ms);
        }
    });

    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn test_event_reader_parses_ndjson() {
        // Create a temp UDS path
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        // Start a fake multiplexed server that expects SUBSCRIBE
        let listener = UnixListener::bind(&sock_path).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, write_half) = stream.into_split();

            // Read the SUBSCRIBE line from client
            let mut reader = tokio::io::BufReader::new(read_half);
            let mut line = String::new();
            use tokio::io::AsyncBufReadExt as _;
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("SUBSCRIBE"), "Expected SUBSCRIBE, got: {}", line);

            let mut writer = tokio::io::BufWriter::new(write_half);

            // Send hello + snapshot + window_opened
            writer.write_all(b"{\"type\":\"hello\",\"protocol_version\":2,\"agent_tick_ms\":50,\"ts\":1000}\n").await.unwrap();
            writer.write_all(b"{\"type\":\"snapshot\",\"seq\":1,\"windows\":[],\"ts\":1000}\n").await.unwrap();
            writer.write_all(b"{\"type\":\"window_opened\",\"seq\":2,\"window_id\":42,\"window_title\":\"IBKR Gateway\",\"window_class\":\"ibgateway.az\",\"has_login_button\":true,\"bounds\":{\"x\":0,\"y\":0,\"width\":800,\"height\":600},\"ts\":1001}\n").await.unwrap();
            writer.flush().await.unwrap();

            // Keep connection open briefly
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        // Start the reader
        let mut rx = spawn_event_reader(sock_path, 16);

        // Read events
        let hello = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        ).await.unwrap().unwrap();
        assert!(matches!(hello, AgentEvent::Hello { protocol_version: 2, .. }));

        let snapshot = rx.recv().await.unwrap();
        assert!(matches!(snapshot, AgentEvent::Snapshot { .. }));

        let opened = rx.recv().await.unwrap();
        match opened {
            AgentEvent::WindowOpened { window_title, has_login_button, seq, .. } => {
                assert_eq!(window_title, "IBKR Gateway");
                assert!(has_login_button);
                assert_eq!(seq, 2);
            }
            _ => panic!("expected WindowOpened, got {:?}", opened),
        }

        server.await.unwrap();
    }
}
