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

/// Outcome of a `set_checkbox` call, decoded from the agent's inner JSON.
///
/// The agent's HTTP envelope (`AgentResponse.ok`) is set independently of the
/// Swing-side match — `wrapOk(...)` is called even when the label doesn't
/// match any button in the target window. The real "did we find the checkbox"
/// signal is `data.found`, which we surface here so callers can distinguish
/// "match succeeded, click applied" from "no button in the panel had a
/// matching label".
///
/// This type was for a long time the *only* place that read the inner `found`;
/// every other action verb returned the envelope and so could not report a
/// miss. That asymmetry is gone — see [`action_applied`], which applies the
/// same reasoning to the seven `bool`-returning verbs. `set_checkbox` keeps a
/// dedicated struct because callers also want `selected` and `changed`, which
/// have no analogue in a click.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckboxOutcome {
    #[serde(default)]
    pub found: bool,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub selected: Option<bool>,
    #[serde(default)]
    pub changed: Option<bool>,
    #[serde(default)]
    pub error: Option<String>,
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
///
/// # Contract for the action verbs
///
/// `click_button`, `type_text`, `click_menu`, `select_list_item`, `click_at`,
/// `select_tree_node` and `send_key` all return a `bool` that means **"the
/// widget was found and the action applied"** — nothing weaker. Callers may
/// branch on it. See [`action_applied`] for how it is derived and for the
/// fail-open bug that existed while it merely echoed the HTTP envelope.
///
/// * `Ok(true)`  — found, acted.
/// * `Ok(false)` — no such widget. Expected; fall back or report failure.
/// * `Err(..)`   — transport failure, agent-level rejection, or the widget was
///   found and the action then threw.
///
/// `health` is the exception: `/health` has no widget, so its bool is the
/// envelope's `ok`, which is the right answer there.
pub trait AgentApi: Send + Sync {
    fn health(&self) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn list_windows(&self) -> impl std::future::Future<Output = Result<Vec<WindowInfo>, AgentError>> + Send;
    fn click_button(&self, window_id: WindowId, label: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn type_text(&self, window_id: WindowId, field_index: usize, text: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn click_menu(&self, window_id: WindowId, menu_path: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn set_checkbox(&self, window_id: WindowId, label: &str, state: Option<bool>) -> impl std::future::Future<Output = Result<CheckboxOutcome, AgentError>> + Send;
    fn select_list_item(&self, window_id: WindowId, item_text: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn click_at(&self, window_id: WindowId, x: i32, y: i32) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn select_tree_node(&self, window_id: WindowId, node_name: &str) -> impl std::future::Future<Output = Result<bool, AgentError>> + Send;
    fn dump_components(&self, window_id: WindowId) -> impl std::future::Future<Output = Result<serde_json::Value, AgentError>> + Send;
    fn list_clients(&self, window_id: WindowId) -> impl std::future::Future<Output = Result<serde_json::Value, AgentError>> + Send;
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

    /// Create a client over any `AgentApi` implementation.
    ///
    /// `MockAgent` answers each verb from a fixed field, which is right for
    /// most tests but cannot express a UI that changes as you interact with it
    /// — a click there succeeds whether or not the button is in the dump. When
    /// a test needs the two to agree (a panel still being built, a mode toggle
    /// that relabels the submit button), it supplies its own fake instead of
    /// growing `MockAgent` for everyone.
    #[cfg(test)]
    pub fn mock_api<A: AgentApi + 'static>(api: A) -> Self {
        Self {
            inner: Box::new(api),
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
    pub async fn set_checkbox(&self, window_id: WindowId, label: &str, state: Option<bool>) -> Result<CheckboxOutcome, AgentError> {
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
    pub async fn list_clients(&self, window_id: WindowId) -> Result<serde_json::Value, AgentError> {
        self.inner.list_clients_boxed(window_id).await
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
    fn set_checkbox_boxed<'a>(&'a self, window_id: WindowId, label: &'a str, state: Option<bool>) -> BoxFut<'a, Result<CheckboxOutcome, AgentError>>;
    fn select_list_item_boxed<'a>(&'a self, window_id: WindowId, item_text: &'a str) -> BoxFut<'a, Result<bool, AgentError>>;
    fn click_at_boxed(&self, window_id: WindowId, x: i32, y: i32) -> BoxFut<'_, Result<bool, AgentError>>;
    fn select_tree_node_boxed<'a>(&'a self, window_id: WindowId, node_name: &'a str) -> BoxFut<'a, Result<bool, AgentError>>;
    fn dump_components_boxed(&self, window_id: WindowId) -> BoxFut<'_, Result<serde_json::Value, AgentError>>;
    fn list_clients_boxed(&self, window_id: WindowId) -> BoxFut<'_, Result<serde_json::Value, AgentError>>;
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
    fn set_checkbox_boxed<'a>(&'a self, window_id: WindowId, label: &'a str, state: Option<bool>) -> BoxFut<'a, Result<CheckboxOutcome, AgentError>> {
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
    fn list_clients_boxed(&self, window_id: WindowId) -> BoxFut<'_, Result<serde_json::Value, AgentError>> {
        Box::pin(self.list_clients(window_id))
    }
    fn send_key_boxed<'a>(&'a self, window_id: WindowId, key: &'a str) -> BoxFut<'a, Result<bool, AgentError>> {
        Box::pin(self.send_key(window_id, key))
    }
}

/// Decode an *action* verb's reply into "did the agent actually do it".
///
/// # Why this exists
///
/// The agent's HTTP envelope (`AgentResponse::ok`) is set by the Java side's
/// `wrapOk(...)`, which is called with the Swing result *whatever that result
/// was* — including a miss. Enumerated from `SwingInspector`, every action verb
/// answers with an inner JSON object, and the envelope reads `ok: true` for all
/// of these:
///
/// ```text
/// clickButton     hit    {"found":true,"clicked":true}
///                 miss   {"found":false,"error":"Button not found: Paper Log In"}
/// typeText        hit    {"found":true,"typed":true}
///                 miss   {"found":false,"error":"TextField not found at index: 1"}
///                 threw  {"found":true,"typed":false,"error":"…"}
/// sendKey         threw  {"found":true,"sent":false,"error":"Invalid keystroke: …"}
/// clickMenu       miss   {"found":false,"error":"Menu not found: …"}
/// selectListItem  miss   {"found":false,"error":"List item not found: …"}
/// selectTreeNode  threw  {"found":true,"error":"…"}
/// clickAt         miss   {"found":false,"error":"Window not found"}
/// ```
///
/// So `resp.ok` answers "did the agent reply", never "did a widget get
/// touched". Returning it as each verb's boolean made every action report
/// unconditional success, which in turn made every caller that branches on
/// that boolean unreachable: label-fallback loops always took their first
/// branch, and `if !submitted { send_key("Enter") }` fallbacks could never
/// fire.
///
/// `LoginHandler` was the sharp end. It clicked a "Paper Log In" button that
/// did not exist, was told `true`, set `login_submitted`, and left the gateway
/// parked on a filled-in login form — indefinitely, with no error logged
/// anywhere, because from the code's point of view the login had succeeded.
///
/// The real signal is the inner `found`, qualified by the absence of `error`.
/// This function is the single place that reads it.
///
/// # Outcomes
///
/// * `Ok(true)`  — the widget was found and the action applied.
/// * `Ok(false)` — nothing matched. An ordinary, expected answer; callers fall
///   back to another label or report failure.
/// * `Err(..)`   — the widget was found but the action threw, or the agent
///   rejected the request, or the reply does not satisfy the contract.
///
/// The three are deliberately kept distinct. Folding `Err` into `Ok(false)`
/// would be cheaper for callers, but "there is no such button" and "the agent
/// did not understand me" call for different responses, and collapsing them is
/// precisely how the original defect stayed invisible for so long.
fn action_applied(resp: AgentResponse<serde_json::Value>, what: &str) -> Result<bool, AgentError> {
    let Some(data) = resp.data else {
        // Envelope-level rejection (`wrapError`): a malformed request from us,
        // or a window that disappeared between listing and acting. Not the
        // same thing as "the button is absent", so not `Ok(false)`.
        return Err(AgentError::Agent(
            resp.error
                .unwrap_or_else(|| format!("{what}: agent returned no result body")),
        ));
    };

    let Some(found) = data.get("found").and_then(|f| f.as_bool()) else {
        // A reply with no `found` cannot be interpreted, so say so. Defaulting
        // to `false` would silently disable every action in the process;
        // defaulting to `true` would restore the exact fail-open this function
        // exists to remove. Either would be a quiet catastrophe on an agent /
        // binary version skew, so this is loud instead.
        return Err(AgentError::Agent(format!(
            "{what}: agent result has no `found` field: {data}"
        )));
    };

    if !found {
        return Ok(false);
    }

    // `found: true` carrying an `error` means the widget was located and the
    // action then failed — an interrupted `invokeAndWait`, an unparseable
    // keystroke, a tree selection that threw. Reporting that as success is how
    // a half-completed interaction looks identical to a finished one.
    if let Some(err) = data.get("error").and_then(|e| e.as_str()) {
        return Err(AgentError::Agent(format!("{what}: {err}")));
    }

    Ok(true)
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
        action_applied(resp, &format!("click_button({label})"))
    }
    async fn type_text(&self, window_id: WindowId, field_index: usize, text: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/type", window_id.0);
        let body = serde_json::json!({ "fieldIndex": field_index, "text": text });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        action_applied(resp, &format!("type_text(field {field_index})"))
    }
    async fn click_menu(&self, window_id: WindowId, menu_path: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/menu", window_id.0);
        let body = serde_json::json!({ "path": menu_path });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        action_applied(resp, &format!("click_menu({menu_path})"))
    }
    async fn set_checkbox(&self, window_id: WindowId, label: &str, state: Option<bool>) -> Result<CheckboxOutcome, AgentError> {
        let path = format!("/windows/{}/checkbox", window_id.0);
        let body = if let Some(s) = state {
            serde_json::json!({ "label": label, "state": s.to_string() })
        } else {
            serde_json::json!({ "label": label })
        };
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        // Inner data is the Swing-side JSON:
        //   {"found":true,"label":"…","selected":true,"changed":false,"class":"…"}
        //   {"found":false,"error":"Checkbox not found: …"}
        // If envelope-level error path fires (data is None), surface it as
        // found:false with the envelope error attached — same shape as the
        // Swing-side miss so the caller has one thing to branch on.
        match resp.data {
            Some(v) => serde_json::from_value(v).map_err(AgentError::ParseError),
            None => Ok(CheckboxOutcome {
                found: false,
                error: resp.error,
                ..Default::default()
            }),
        }
    }
    async fn select_list_item(&self, window_id: WindowId, item_text: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/selectlist", window_id.0);
        let body = serde_json::json!({ "item": item_text });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        action_applied(resp, &format!("select_list_item({item_text})"))
    }
    async fn click_at(&self, window_id: WindowId, x: i32, y: i32) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/clickat", window_id.0);
        let body = serde_json::json!({ "x": x.to_string(), "y": y.to_string() });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        action_applied(resp, &format!("click_at({x},{y})"))
    }
    async fn select_tree_node(&self, window_id: WindowId, node_name: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/tree", window_id.0);
        let body = serde_json::json!({ "node": node_name });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        action_applied(resp, &format!("select_tree_node({node_name})"))
    }
    async fn dump_components(&self, window_id: WindowId) -> Result<serde_json::Value, AgentError> {
        let path = format!("/windows/{}/dump", window_id.0);
        let resp: AgentResponse<serde_json::Value> = self.get(&path).await?;
        self.unwrap_response(resp)
    }
    async fn list_clients(&self, window_id: WindowId) -> Result<serde_json::Value, AgentError> {
        let path = format!("/windows/{}/clients", window_id.0);
        let resp: AgentResponse<serde_json::Value> = self.get(&path).await?;
        self.unwrap_response(resp)
    }
    async fn send_key(&self, window_id: WindowId, key: &str) -> Result<bool, AgentError> {
        let path = format!("/windows/{}/key", window_id.0);
        let body = serde_json::json!({ "key": key });
        let resp: AgentResponse<serde_json::Value> = self.post(&path, &body).await?;
        action_applied(resp, &format!("send_key({key})"))
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
    /// Response returned by `dump_components()` for ALL window IDs.
    /// Tests set this to simulate specific Gateway UI states
    /// (e.g. labels = ["API Server","disconnected"] for a disconnected gateway).
    pub dump_response: serde_json::Value,
    /// Per-window overrides of `dump_response`, keyed by window id. For a
    /// Gateway showing two windows with the same title, only one of which
    /// carries the login form.
    pub dump_by_window: std::collections::HashMap<u64, serde_json::Value>,
    /// What `dump_components` reports once `type_text` has been called — the
    /// Gateway enables "Log In" only after a password is entered.
    pub dump_after_type: Option<serde_json::Value>,
    /// Set by `type_text`; gates `dump_after_type`.
    pub typed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Response returned by `list_clients()` for ALL window IDs.
    /// Tests set this to simulate API Client row status + tab list.
    pub list_clients_response: serde_json::Value,
    /// Labels for which `set_checkbox` returns `found: false`. Any label not
    /// in this set returns `found: true`. Used to simulate the label-drift
    /// bug seen in the field.
    pub not_found_labels: std::collections::HashSet<String>,
    /// Labels for which `click_button` returns `Ok(false)` — i.e. no such
    /// button in the window. The `click_button` analogue of
    /// `not_found_labels`, and the only way to test a label-fallback path now
    /// that a miss is actually reportable.
    pub click_not_found: std::collections::HashSet<String>,
    /// What `type_text` reports. `false` simulates a text field that is not
    /// present, which used to be indistinguishable from a successful type.
    pub type_text_found: bool,
    /// What `select_list_item` reports: `true` for the IB Key device picker
    /// (it has a device list), `false` for the challenge prompt (it has none).
    pub list_item_found: bool,
    /// Every label passed to `click_button`, in order. Lets a test assert what
    /// was *not* clicked, which for a mode-sensitive login is the interesting
    /// half.
    pub clicked: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Every (window, key) passed to `send_key`, in order.
    pub keys_sent: std::sync::Arc<std::sync::Mutex<Vec<(u64, String)>>>,
    /// What `send_key` reports; `false` simulates a key the agent could not send.
    pub send_key_result: bool,
    /// How long `send_key` takes to reply, to simulate the Gateway holding a
    /// key press open behind a confirmation prompt.
    pub send_key_delay: Option<std::time::Duration>,
}

#[cfg(test)]
impl Default for MockAgent {
    fn default() -> Self {
        Self {
            windows: Vec::new(),
            healthy: true,
            click_result: true,
            dump_response: serde_json::json!({}),
            dump_by_window: std::collections::HashMap::new(),
            dump_after_type: None,
            typed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            list_clients_response: serde_json::json!({
                "api_client_row_status": serde_json::Value::Null,
                "tabs": []
            }),
            not_found_labels: std::collections::HashSet::new(),
            click_not_found: std::collections::HashSet::new(),
            type_text_found: true,
            list_item_found: true,
            clicked: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            keys_sent: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            send_key_result: true,
            send_key_delay: None,
        }
    }
}

#[cfg(test)]
impl AgentApi for MockAgent {
    async fn health(&self) -> Result<bool, AgentError> { Ok(self.healthy) }
    async fn list_windows(&self) -> Result<Vec<WindowInfo>, AgentError> { Ok(self.windows.clone()) }
    async fn click_button(&self, _: WindowId, label: &str) -> Result<bool, AgentError> {
        self.clicked.lock().unwrap().push(label.to_string());
        if self.click_not_found.contains(label) {
            return Ok(false);
        }
        Ok(self.click_result)
    }
    async fn type_text(&self, _: WindowId, _: usize, _: &str) -> Result<bool, AgentError> {
        self.typed.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(self.type_text_found)
    }
    async fn click_menu(&self, _: WindowId, _: &str) -> Result<bool, AgentError> { Ok(self.click_result) }
    async fn set_checkbox(&self, _: WindowId, label: &str, state: Option<bool>) -> Result<CheckboxOutcome, AgentError> {
        if self.not_found_labels.contains(label) {
            Ok(CheckboxOutcome {
                found: false,
                error: Some(format!("Checkbox not found: {label}")),
                ..Default::default()
            })
        } else {
            Ok(CheckboxOutcome {
                found: true,
                label: Some(label.to_string()),
                selected: state,
                changed: Some(true),
                error: None,
            })
        }
    }
    async fn select_list_item(&self, _: WindowId, _: &str) -> Result<bool, AgentError> { Ok(self.list_item_found) }
    async fn click_at(&self, _: WindowId, _: i32, _: i32) -> Result<bool, AgentError> { Ok(true) }
    async fn select_tree_node(&self, _: WindowId, _: &str) -> Result<bool, AgentError> { Ok(true) }
    async fn dump_components(&self, id: WindowId) -> Result<serde_json::Value, AgentError> {
        if self.typed.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(after) = &self.dump_after_type {
                return Ok(after.clone());
            }
        }
        Ok(self.dump_by_window.get(&id.0).unwrap_or(&self.dump_response).clone())
    }
    async fn list_clients(&self, _: WindowId) -> Result<serde_json::Value, AgentError> {
        Ok(self.list_clients_response.clone())
    }
    async fn send_key(&self, window: WindowId, key: &str) -> Result<bool, AgentError> {
        self.keys_sent.lock().unwrap().push((window.0, key.to_string()));
        if let Some(delay) = self.send_key_delay {
            tokio::time::sleep(delay).await;
        }
        Ok(self.send_key_result)
    }
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
    // ---------------------------------------------------------------------
    // action_applied: the decoder that used to be `Ok(resp.ok)`
    //
    // Each case below is a verbatim reply shape from SwingInspector.java. The
    // first one is the most severe: a paper login clicking a button that is not there.
    // ---------------------------------------------------------------------

    fn envelope(data: serde_json::Value) -> AgentResponse<serde_json::Value> {
        AgentResponse { ok: true, data: Some(data), error: None }
    }

    #[test]
    fn action_applied_reports_a_miss_as_false() {
        // clickButton's miss shape. `ok` is true — the agent replied fine —
        // and this is exactly the reply that used to be read as success.
        let resp = envelope(serde_json::json!({
            "found": false,
            "error": "Button not found: Paper Log In"
        }));
        assert!(!action_applied(resp, "click_button(Paper Log In)").unwrap());
    }

    #[test]
    fn action_applied_reports_a_hit_as_true() {
        let resp = envelope(serde_json::json!({"found": true, "clicked": true}));
        assert!(action_applied(resp, "click_button(OK)").unwrap());
    }

    #[test]
    fn action_applied_errors_when_found_but_the_action_threw() {
        // typeText's interrupted-invokeAndWait shape: the field was located and
        // the write then failed. Reporting this as success is how a half-typed
        // password looks identical to a typed one.
        let resp = envelope(serde_json::json!({
            "found": true, "typed": false, "error": "InterruptedException"
        }));
        let err = action_applied(resp, "type_text(field 1)").unwrap_err();
        assert!(err.to_string().contains("InterruptedException"), "got: {err}");
    }

    #[test]
    fn action_applied_errors_on_envelope_rejection() {
        // wrapError(...) — our request was malformed, or the window vanished.
        // Distinct from "no such widget" and must not be flattened into it.
        let resp = AgentResponse::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some("Missing 'label' field".to_string()),
        };
        let err = action_applied(resp, "click_button(?)").unwrap_err();
        assert!(err.to_string().contains("Missing 'label' field"), "got: {err}");
    }

    #[test]
    fn action_applied_errors_when_found_is_absent() {
        // Version skew between this binary and the agent jar. Must be loud:
        // defaulting to false would silently disable every action in the
        // process, and defaulting to true would restore the original fail-open.
        let resp = envelope(serde_json::json!({"clicked": true}));
        let err = action_applied(resp, "click_button(OK)").unwrap_err();
        assert!(err.to_string().contains("no `found` field"), "got: {err}");
    }

    #[tokio::test]
    async fn mock_click_button_can_report_a_missing_label() {
        let client = AgentClient::mock(MockAgent {
            click_not_found: ["Paper Log In".to_string()].into_iter().collect(),
            ..Default::default()
        });
        assert!(!client.click_button(WindowId(1), "Paper Log In").await.unwrap());
        assert!(client.click_button(WindowId(1), "Log In").await.unwrap());
    }
}
