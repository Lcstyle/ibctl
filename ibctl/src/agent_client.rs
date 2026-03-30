//! HTTP+JSON client for communicating with the ibctl Java agent over a Unix domain socket.
//!
//! The agent runs inside the IB Gateway JVM and exposes a REST-like API over UDS.
//! This client translates high-level operations (list windows, click button, etc.)
//! into HTTP requests over the socket.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("agent not reachable at {path}: {source}")]
    ConnectionFailed {
        path: String,
        source: std::io::Error,
    },
    #[error("agent request failed: {0}")]
    RequestFailed(String),
    #[error("agent returned error: {0}")]
    Agent(String),
    #[error("failed to parse agent response: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("timeout waiting for agent response")]
    Timeout,
}

/// Generic response envelope from the agent.
#[derive(Debug, Deserialize)]
pub struct AgentResponse<T> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

/// Bounding rectangle from the Java agent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Bounds {
    #[serde(default)]
    pub x: i32,
    #[serde(default)]
    pub y: i32,
    #[serde(default)]
    pub width: i32,
    #[serde(default)]
    pub height: i32,
}

/// Information about a visible window in the IB Gateway.
/// Field names match the Java agent's JSON output from SwingInspector.listWindows().
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub id: u64,
    pub title: String,
    /// Java class name of the window (e.g., "ibgateway.az")
    #[serde(alias = "class_name", alias = "class", default)]
    pub class: String,
    #[serde(default)]
    pub bounds: Option<Bounds>,
    #[serde(default)]
    pub visible: bool,
}

/// Client for the ibctl Java agent running inside the Gateway JVM.
///
/// Communicates over HTTP+JSON on a Unix domain socket.
pub struct AgentClient {
    socket_path: PathBuf,
}

impl AgentClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Check if the agent is alive and responding.
    pub async fn health(&self) -> Result<bool, AgentError> {
        let resp: AgentResponse<serde_json::Value> = self.get("/health").await?;
        Ok(resp.ok)
    }

    /// List all visible windows in the IB Gateway.
    pub async fn list_windows(&self) -> Result<Vec<WindowInfo>, AgentError> {
        let resp: AgentResponse<Vec<WindowInfo>> = self.get("/windows").await?;
        self.unwrap_response(resp)
    }

    /// Click a button by its label text within a window.
    pub async fn click_button(
        &self,
        window_id: u64,
        label: &str,
    ) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/click", window_id);
        let body = serde_json::json!({ "label": label });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }

    /// Type text into a text field by its positional index within a window.
    pub async fn type_text(
        &self,
        window_id: u64,
        field_index: usize,
        text: &str,
    ) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/type", window_id);
        let body = serde_json::json!({
            "fieldIndex": field_index,
            "text": text,
        });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        // Agent returns {"found": true, "typed": true} or a simple boolean
        Ok(resp.ok)
    }

    /// Navigate and click a menu item by path (e.g., "Configure/API/Settings").
    /// Path components are separated by "/".
    pub async fn click_menu(
        &self,
        window_id: u64,
        menu_path: &str,
    ) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/menu", window_id);
        let body = serde_json::json!({ "path": menu_path });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }

    /// Get or set a checkbox state by label text in a window.
    /// Pass `Some(true)` to check, `Some(false)` to uncheck, `None` to query.
    pub async fn set_checkbox(
        &self,
        window_id: u64,
        label: &str,
        state: Option<bool>,
    ) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/checkbox", window_id);
        let body = if let Some(s) = state {
            serde_json::json!({ "label": label, "state": s.to_string() })
        } else {
            serde_json::json!({ "label": label })
        };
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }

    /// Select an item in a JList by text match.
    /// Used for the 2FA device selection dialog.
    pub async fn select_list_item(
        &self,
        window_id: u64,
        item_text: &str,
    ) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/selectlist", window_id);
        let body = serde_json::json!({ "item": item_text });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }

    /// Click at x,y coordinates relative to a window.
    /// Useful for dismissing menus or clicking arbitrary locations.
    pub async fn click_at(
        &self,
        window_id: u64,
        x: i32,
        y: i32,
    ) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/clickat", window_id);
        let body = serde_json::json!({ "x": x.to_string(), "y": y.to_string() });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }

    /// Select a tree node by name in the first JTree of a window.
    /// Used to navigate the Global Configuration dialog's left panel.
    pub async fn select_tree_node(
        &self,
        window_id: u64,
        node_name: &str,
    ) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/tree", window_id);
        let body = serde_json::json!({ "node": node_name });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }

    /// Dump all interactive components in a window for diagnostics.
    pub async fn dump_components(
        &self,
        window_id: u64,
    ) -> Result<serde_json::Value, AgentError> {
        let path = format!("/windows/{}/dump", window_id);
        let resp: AgentResponse<serde_json::Value> = self.get(&path).await?;
        self.unwrap_response(resp)
    }

    /// Send a keystroke to a window (e.g., "Enter", "Escape", "Ctrl+F").
    pub async fn send_key(
        &self,
        window_id: u64,
        key: &str,
    ) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/key", window_id);
        let body = serde_json::json!({ "key": key });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }

    // --- Internal HTTP methods ---
    //
    // Raw HTTP/1.1 over Unix domain socket. Matches the Java agent's manual
    // HTTP parser (HttpApi.java). No hyper dependency needed — the protocol
    // is simple request/response with JSON bodies.

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, AgentError> {
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        let body = self.send_raw(&request).await?;
        serde_json::from_str(&body).map_err(|e| {
            log::debug!("Failed to parse response for GET {}: body={}", path, body);
            AgentError::ParseError(e)
        })
    }

    async fn post<T: serde::de::DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, AgentError> {
        let json_body = serde_json::to_string(body).map_err(AgentError::ParseError)?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            json_body.len(),
            json_body
        );
        let resp_body = self.send_raw(&request).await?;
        serde_json::from_str(&resp_body).map_err(|e| {
            log::debug!("Failed to parse response for POST {}: body={}", path, resp_body);
            AgentError::ParseError(e)
        })
    }

    /// Send a raw HTTP request over the UDS and return the response body.
    /// All operations are bounded by a 10-second timeout to prevent hanging
    /// if the agent stops responding (SEC-01 fix).
    async fn send_raw(&self, request: &str) -> Result<String, AgentError> {
        const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        // Connect with timeout
        let mut stream = tokio::time::timeout(TIMEOUT, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| AgentError::Timeout)?
            .map_err(|e| AgentError::ConnectionFailed {
                path: self.socket_path.display().to_string(),
                source: e,
            })?;

        // Send request with timeout
        tokio::time::timeout(TIMEOUT, stream.write_all(request.as_bytes()))
            .await
            .map_err(|_| AgentError::Timeout)?
            .map_err(|e| AgentError::RequestFailed(format!("write failed: {}", e)))?;

        // Read response with timeout
        let mut response = Vec::new();
        tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut response))
            .await
            .map_err(|_| AgentError::Timeout)?
            .map_err(|e| AgentError::RequestFailed(format!("read failed: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response);

        // Parse HTTP response: skip status line and headers, extract body
        // HTTP/1.1 200 OK\r\n...headers...\r\n\r\nbody
        let body = response_str
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_else(|| response_str.to_string());

        if body.is_empty() {
            return Err(AgentError::RequestFailed("empty response body".into()));
        }

        Ok(body)
    }

    /// Unwrap an AgentResponse, converting agent-level errors to AgentError.
    fn unwrap_response<T>(&self, resp: AgentResponse<T>) -> Result<T, AgentError> {
        if resp.ok {
            resp.data
                .ok_or_else(|| AgentError::Agent("response ok but no data".to_string()))
        } else {
            Err(AgentError::Agent(
                resp.error.unwrap_or_else(|| "unknown agent error".to_string()),
            ))
        }
    }
}
