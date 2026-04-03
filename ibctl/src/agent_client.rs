//! HTTP+JSON client for communicating with the ibctl Java agent over a Unix domain socket.
//!
//! The agent runs inside the IB Gateway JVM and exposes a REST-like API over UDS.
//! This client translates high-level operations (list windows, click button, etc.)
//! into HTTP requests over the socket.
//!
//! The `AgentApi` trait abstracts the agent interface, allowing test mocks via
//! `AgentClient::mock()`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::types::WindowId;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub id: WindowId,
    pub title: String,
    #[serde(alias = "class_name", alias = "class", default)]
    pub class: String,
    #[serde(default)]
    pub bounds: Option<Bounds>,
    #[serde(default)]
    pub visible: bool,
}

// ---------------------------------------------------------------------------
// Trait: AgentApi
// ---------------------------------------------------------------------------

/// Abstract interface for the Java agent. Production uses UDS HTTP; tests use mocks.
pub trait AgentApi: Send + Sync {
    fn health(&self) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn list_windows(&self) -> impl std::future::Future<Output = Result<Vec<WindowInfo>, AgentError>> + Send;
    fn click_button(&self, window_id: WindowId, label: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn type_text(&self, window_id: WindowId, field_index: usize, text: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn click_menu(&self, window_id: WindowId, menu_path: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn set_checkbox(&self, window_id: WindowId, label: &str, state: Option<bool>) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn select_list_item(&self, window_id: WindowId, item_text: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn click_at(&self, window_id: WindowId, x: i32, y: i32) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn select_tree_node(&self, window_id: WindowId, node_name: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn dump_components(&self, window_id: WindowId) -> impl std::future::Future<Output = Result<serde_json::Value, AgentError>> + Send;
    fn list_tabs(&self, window_id: WindowId) -> impl std::future::Future<Output = Result<serde_json::Value, AgentError>> + Send;
    fn send_key(&self, window_id: WindowId, key: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
}

// ---------------------------------------------------------------------------
// AgentClient: public API (delegates to inner trait object)
// ---------------------------------------------------------------------------

/// Client for the ibctl Java agent. Wraps either a real UDS agent or a test mock.
pub struct AgentClient {
    inner: Box<dyn AgentApiBoxed>,
}

impl AgentClient {
    /// Create a client connected to a real Java agent over a Unix domain socket.
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            inner: Box::new(UdsAgent {
                socket_path: socket_path.as_ref().to_path_buf(),
            }),
        }
    }

    /// Create a mock client for testing. The mock returns the configured responses.
    #[cfg(test)]
    pub fn mock(mock: MockAgent) -> Self {
        Self {
            inner: Box::new(mock),
        }
    }

    pub async fn health(&self) -> Result<bool, AgentError> {
        self.inner.health_boxed().await
    }
    pub async fn list_windows(&self) -> Result<Vec<WindowInfo>, AgentError> {
        self.inner.list_windows_boxed().await
    }
    pub async fn click_button(&self, window_id: WindowId, label: &str) -> Result<bool, AgentError> {
        self.inner.click_button_boxed(window_id, label).await
    }
    pub async fn type_text(&self, window_id: WindowId, field_index: usize, text: &str) -> Result<bool, AgentError> {
        self.inner.type_text_boxed(window_id, field_index, text).await
    }
    pub async fn click_menu(&self, window_id: WindowId, menu_path: &str) -> Result<bool, AgentError> {
        self.inner.click_menu_boxed(window_id, menu_path).await
    }
    pub async fn set_checkbox(&self, window_id: WindowId, label: &str, state: Option<bool>) -> Result<bool, AgentError> {
        self.inner.set_checkbox_boxed(window_id, label, state).await
    }
    pub async fn select_list_item(&self, window_id: WindowId, item_text: &str) -> Result<bool, AgentError> {
        self.inner.select_list_item_boxed(window_id, item_text).await
    }
    pub async fn click_at(&self, window_id: WindowId, x: i32, y: i32) -> Result<bool, AgentError> {
        self.inner.click_at_boxed(window_id, x, y).await
    }
    pub async fn select_tree_node(&self, window_id: WindowId, node_name: &str) -> Result<bool, AgentError> {
        self.inner.select_tree_node_boxed(window_id, node_name).await
    }
    pub async fn dump_components(&self, window_id: WindowId) -> Result<serde_json::Value, AgentError> {
        self.inner.dump_components_boxed(window_id).await
    }
    pub async fn list_tabs(&self, window_id: WindowId) -> Result<serde_json::Value, AgentError> {
        self.inner.list_tabs_boxed(window_id).await
    }
    pub async fn send_key(&self, window_id: WindowId, key: &str) -> Result<bool, AgentError> {
        self.inner.send_key_boxed(window_id, key).await
    }
}

// ---------------------------------------------------------------------------
// Object-safe wrapper trait (needed because `impl Future` isn't dyn-compatible)
// ---------------------------------------------------------------------------

type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

trait AgentApiBoxed: Send + Sync {
    fn health_boxed(&self) -> BoxFut<'_, Result<bool, AgentError>>;
    fn list_windows_boxed(&self) -> BoxFut<'_, Result<Vec<WindowInfo>, AgentError>>;
    fn click_button_boxed<'a>(&'a self, window_id: WindowId, label: &'a str) -> BoxFut<'a, Result<bool, AgentError>>;
    fn type_text_boxed<'a>(&'a self, window_id: WindowId, field_index: usize, text: &'a str) -> BoxFut<'a, Result<bool, AgentError>>;
    fn click_menu_boxed<'a>(&'a self, window_id: WindowId, menu_path: &'a str) -> BoxFut<'a, Result<bool, AgentError>>;
    fn set_checkbox_boxed<'a>(&'a self, window_id: WindowId, label: &'a str, state: Option<bool>) -> BoxFut<'a, Result<bool, AgentError>>;
    fn select_list_item_boxed<'a>(&'a self, window_id: WindowId, item_text: &'a str) -> BoxFut<'a, Result<bool, AgentError>>;
    fn click_at_boxed(&self, window_id: WindowId, x: i32, y: i32) -> BoxFut<'_, Result<bool, AgentError>>;
    fn select_tree_node_boxed<'a>(&'a self, window_id: WindowId, node_name: &'a str) -> BoxFut<'a, Result<bool, AgentError>>;
    fn dump_components_boxed(&self, window_id: WindowId) -> BoxFut<'_, Result<serde_json::Value, AgentError>>;
    fn list_tabs_boxed(&self, window_id: WindowId) -> BoxFut<'_, Result<serde_json::Value, AgentError>>;
    fn send_key_boxed<'a>(&'a self, window_id: WindowId, key: &'a str) -> BoxFut<'a, Result<bool, AgentError>>;
}

/// Blanket impl: any `T: AgentApi` can be used as a boxed trait object.
impl<T: AgentApi> AgentApiBoxed for T {
    fn health_boxed(&self) -> BoxFut<'_, Result<bool, AgentError>> {
        Box::pin(self.health())
    }
    fn list_windows_boxed(&self) -> BoxFut<'_, Result<Vec<WindowInfo>, AgentError>> {
        Box::pin(self.list_windows())
    }
    fn click_button_boxed<'a>(&'a self, window_id: WindowId, label: &'a str) -> BoxFut<'a, Result<bool, AgentError>> {
        Box::pin(self.click_button(window_id, label))
    }
    fn type_text_boxed<'a>(&'a self, window_id: WindowId, field_index: usize, text: &'a str) -> BoxFut<'a, Result<bool, AgentError>> {
        Box::pin(self.type_text(window_id, field_index, text))
    }
    fn click_menu_boxed<'a>(&'a self, window_id: WindowId, menu_path: &'a str) -> BoxFut<'a, Result<bool, AgentError>> {
        Box::pin(self.click_menu(window_id, menu_path))
    }
    fn set_checkbox_boxed<'a>(&'a self, window_id: WindowId, label: &'a str, state: Option<bool>) -> BoxFut<'a, Result<bool, AgentError>> {
        Box::pin(self.set_checkbox(window_id, label, state))
    }
    fn select_list_item_boxed<'a>(&'a self, window_id: WindowId, item_text: &'a str) -> BoxFut<'a, Result<bool, AgentError>> {
        Box::pin(self.select_list_item(window_id, item_text))
    }
    fn click_at_boxed(&self, window_id: WindowId, x: i32, y: i32) -> BoxFut<'_, Result<bool, AgentError>> {
        Box::pin(self.click_at(window_id, x, y))
    }
    fn select_tree_node_boxed<'a>(&'a self, window_id: WindowId, node_name: &'a str) -> BoxFut<'a, Result<bool, AgentError>> {
        Box::pin(self.select_tree_node(window_id, node_name))
    }
    fn dump_components_boxed(&self, window_id: WindowId) -> BoxFut<'_, Result<serde_json::Value, AgentError>> {
        Box::pin(self.dump_components(window_id))
    }
    fn list_tabs_boxed(&self, window_id: WindowId) -> BoxFut<'_, Result<serde_json::Value, AgentError>> {
        Box::pin(self.list_tabs(window_id))
    }
    fn send_key_boxed<'a>(&'a self, window_id: WindowId, key: &'a str) -> BoxFut<'a, Result<bool, AgentError>> {
        Box::pin(self.send_key(window_id, key))
    }
}

// ---------------------------------------------------------------------------
// UdsAgent: real implementation over Unix domain socket
// ---------------------------------------------------------------------------

struct UdsAgent {
    socket_path: PathBuf,
}

impl AgentApi for UdsAgent {
    async fn health(&self) -> Result<bool, AgentError> {
        let resp: AgentResponse<serde_json::Value> = self.get("/health").await?;
        Ok(resp.ok)
    }
    async fn list_windows(&self) -> Result<Vec<WindowInfo>, AgentError> {
        let resp: AgentResponse<Vec<WindowInfo>> = self.get("/windows").await?;
        self.unwrap_response(resp)
    }
    async fn click_button(&self, window_id: WindowId, label: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/click", window_id.0);
        let body = serde_json::json!({ "label": label });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }
    async fn type_text(&self, window_id: WindowId, field_index: usize, text: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/type", window_id.0);
        let body = serde_json::json!({ "fieldIndex": field_index, "text": text });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }
    async fn click_menu(&self, window_id: WindowId, menu_path: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/menu", window_id.0);
        let body = serde_json::json!({ "path": menu_path });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }
    async fn set_checkbox(&self, window_id: WindowId, label: &str, state: Option<bool>) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/checkbox", window_id.0);
        let body = if let Some(s) = state {
            serde_json::json!({ "label": label, "state": s.to_string() })
        } else {
            serde_json::json!({ "label": label })
        };
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }
    async fn select_list_item(&self, window_id: WindowId, item_text: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/selectlist", window_id.0);
        let body = serde_json::json!({ "item": item_text });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }
    async fn click_at(&self, window_id: WindowId, x: i32, y: i32) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/clickat", window_id.0);
        let body = serde_json::json!({ "x": x.to_string(), "y": y.to_string() });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }
    async fn select_tree_node(&self, window_id: WindowId, node_name: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/tree", window_id.0);
        let body = serde_json::json!({ "node": node_name });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }
    async fn dump_components(&self, window_id: WindowId) -> Result<serde_json::Value, AgentError> {
        let path = format!("/windows/{}/dump", window_id.0);
        let resp: AgentResponse<serde_json::Value> = self.get(&path).await?;
        self.unwrap_response(resp)
    }
    async fn list_tabs(&self, window_id: WindowId) -> Result<serde_json::Value, AgentError> {
        let path = format!("/windows/{}/tabs", window_id.0);
        let resp: AgentResponse<serde_json::Value> = self.get(&path).await?;
        self.unwrap_response(resp)
    }
    async fn send_key(&self, window_id: WindowId, key: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/key", window_id.0);
        let body = serde_json::json!({ "key": key });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        Ok(resp.ok)
    }
}

impl UdsAgent {
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

    async fn send_raw(&self, request: &str) -> Result<String, AgentError> {
        const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        let mut stream = tokio::time::timeout(TIMEOUT, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| AgentError::Timeout)?
            .map_err(|e| AgentError::ConnectionFailed {
                path: self.socket_path.display().to_string(),
                source: e,
            })?;

        tokio::time::timeout(TIMEOUT, stream.write_all(request.as_bytes()))
            .await
            .map_err(|_| AgentError::Timeout)?
            .map_err(|e| AgentError::RequestFailed(format!("write failed: {}", e)))?;

        let mut response = Vec::new();
        tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut response))
            .await
            .map_err(|_| AgentError::Timeout)?
            .map_err(|e| AgentError::RequestFailed(format!("read failed: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response);
        let body = response_str
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_else(|| response_str.to_string());

        if body.is_empty() {
            return Err(AgentError::RequestFailed("empty response body".into()));
        }

        Ok(body)
    }

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

// ---------------------------------------------------------------------------
// MockAgent: test mock with configurable responses
// ---------------------------------------------------------------------------

#[cfg(test)]
pub struct MockAgent {
    pub windows: Vec<WindowInfo>,
    pub healthy: bool,
    pub click_result: bool,
}

#[cfg(test)]
impl Default for MockAgent {
    fn default() -> Self {
        Self {
            windows: Vec::new(),
            healthy: true,
            click_result: true,
        }
    }
}

#[cfg(test)]
impl AgentApi for MockAgent {
    async fn health(&self) -> Result<bool, AgentError> { Ok(self.healthy) }
    async fn list_windows(&self) -> Result<Vec<WindowInfo>, AgentError> { Ok(self.windows.clone()) }
    async fn click_button(&self, _: WindowId, _: &str) -> Result<bool, AgentError> { Ok(self.click_result) }
    async fn type_text(&self, _: WindowId, _: usize, _: &str) -> Result<bool, AgentError> { Ok(true) }
    async fn click_menu(&self, _: WindowId, _: &str) -> Result<bool, AgentError> { Ok(self.click_result) }
    async fn set_checkbox(&self, _: WindowId, _: &str, _: Option<bool>) -> Result<bool, AgentError> { Ok(true) }
    async fn select_list_item(&self, _: WindowId, _: &str) -> Result<bool, AgentError> { Ok(true) }
    async fn click_at(&self, _: WindowId, _: i32, _: i32) -> Result<bool, AgentError> { Ok(true) }
    async fn select_tree_node(&self, _: WindowId, _: &str) -> Result<bool, AgentError> { Ok(true) }
    async fn dump_components(&self, _: WindowId) -> Result<serde_json::Value, AgentError> { Ok(serde_json::json!({})) }
    async fn list_tabs(&self, _: WindowId) -> Result<serde_json::Value, AgentError> { Ok(serde_json::json!({"tabs": []})) }
    async fn send_key(&self, _: WindowId, _: &str) -> Result<bool, AgentError> { Ok(true) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_health() {
        let client = AgentClient::mock(MockAgent::default());
        assert!(client.health().await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_unhealthy() {
        let client = AgentClient::mock(MockAgent { healthy: false, ..Default::default() });
        assert!(!client.health().await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_list_windows() {
        let win = WindowInfo {
            id: WindowId(1),
            title: "IB Gateway".to_string(),
            class: "test".to_string(),
            bounds: None,
            visible: true,
        };
        let client = AgentClient::mock(MockAgent {
            windows: vec![win.clone()],
            ..Default::default()
        });
        let windows = client.list_windows().await.unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].title, "IB Gateway");
    }

    #[tokio::test]
    async fn test_mock_click_button() {
        let client = AgentClient::mock(MockAgent { click_result: false, ..Default::default() });
        assert!(!client.click_button(WindowId(1), "OK").await.unwrap());
    }
}
