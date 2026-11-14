//! OS signal handling for graceful shutdown.
//!
//! Converts SIGTERM and SIGINT into channel messages that the main loop
//! can select on alongside other async operations.

use futures_core::stream::Stream;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use thiserror::Error;
use tokio::sync::mpsc;

use std::pin::Pin;
use std::task::Context;

use crate::types::Signal;

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("failed to register signal handler: {0}")]
    Registration(#[from] std::io::Error),
}

/// Register OS signal handlers and return a channel receiver plus a future
/// that bridges OS signals to the channel.
///
/// The returned receiver should be polled in the main select loop.
/// The returned future should be spawned via a `JoinSet` for structured
/// concurrency — the caller owns the task lifetime.
pub fn setup_signal_handler() -> Result<(mpsc::Receiver<Signal>, impl std::future::Future<Output = ()>), SignalError> {
    let (tx, rx) = mpsc::channel(4);

    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    let task = async move {
        loop {
            // Poll the Signals stream using std::future::poll_fn,
            // which gives us access to the futures_core::Stream::poll_next.
            let sig = std::future::poll_fn(|cx: &mut Context<'_>| {
                Pin::new(&mut signals).poll_next(cx)
            })
            .await;

            match sig {
                Some(SIGTERM) => {
                    log::info!("Received SIGTERM");
                    let _ = tx.send(Signal::Terminate).await;
                }
                Some(SIGINT) => {
                    log::info!("Received SIGINT");
                    let _ = tx.send(Signal::Interrupt).await;
                }
                Some(_) => {} // Ignore unexpected signals
                None => break, // Signal stream closed
            }
        }
    };

    log::debug!("Signal handlers registered for SIGTERM and SIGINT");
    Ok((rx, task))
}
