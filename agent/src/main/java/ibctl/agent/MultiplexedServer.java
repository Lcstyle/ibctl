package ibctl.agent;

import java.awt.*;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.*;

/**
 * Multiplexed NIO server: single Unix domain socket serving both HTTP API
 * requests and NDJSON event streams. Protocol auto-detection per connection:
 *
 * <ul>
 *   <li>{@code SUBSCRIBE\n} as first line → event stream mode (NDJSON push)</li>
 *   <li>HTTP method as first line → HTTP request/response mode</li>
 * </ul>
 *
 * <p>Thread model: one accept thread + one thread per client connection.
 * At typical load (2 HTTP + 2 event stream clients for dual mode), this is
 * 5 threads total — well within budget for an in-process Java agent.
 *
 * <p>Event subscribers receive broadcast events. Multiple subscribers are
 * supported (one per Rust ibctl instance in dual-mode deployment).
 */
public class MultiplexedServer {
    private static final int QUEUE_CAPACITY = 256;
    private static final int PROTOCOL_VERSION = 2;
    private static final long KEEPALIVE_INTERVAL_MS = 30_000;

    // Event broadcast infrastructure
    private static final LinkedBlockingQueue<String> eventQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private static final AtomicLong sequence = new AtomicLong(0);
    private static volatile boolean overflowed = false;

    // Active event subscribers — broadcast thread sends to all
    private static final Set<SocketChannel> eventSubscribers = ConcurrentHashMap.newKeySet();
    private static final AtomicInteger clientCounter = new AtomicInteger(0);

    /**
     * Start the multiplexed server. Blocks forever (run on daemon thread).
     */
    public static void start(String socketPath) throws IOException {
        Path path = Path.of(socketPath);
        Files.deleteIfExists(path);
        // Also clean up legacy .events socket if it exists
        Files.deleteIfExists(Path.of(socketPath + ".events"));

        ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(path));

        System.out.println("[ibctl-agent] Multiplexed server listening on " + socketPath);

        // Start the event broadcaster thread
        Thread broadcaster = new Thread(() -> broadcastLoop(), "ibctl-event-broadcast");
        broadcaster.setDaemon(true);
        broadcaster.start();

        // Accept loop — one thread per connection
        while (true) {
            try {
                SocketChannel client = server.accept();
                int id = clientCounter.incrementAndGet();
                Thread t = new Thread(() -> handleClient(client, id), "ibctl-client-" + id);
                t.setDaemon(true);
                t.start();
            } catch (Exception e) {
                System.err.println("[ibctl-agent] Accept error: " + e.getMessage());
            }
        }
    }

    // --- Connection handling ---

    private static void handleClient(SocketChannel client, int id) {
        try {
            // Read first line to detect protocol
            ByteBuffer buf = ByteBuffer.allocate(8192);
            StringBuilder sb = new StringBuilder();

            while (client.read(buf) > 0) {
                buf.flip();
                byte[] bytes = new byte[buf.remaining()];
                buf.get(bytes);
                sb.append(new String(bytes, StandardCharsets.UTF_8));
                buf.clear();

                String data = sb.toString();
                // Check for SUBSCRIBE (event stream) or HTTP request line
                if (data.startsWith("SUBSCRIBE")) {
                    int nlIdx = data.indexOf('\n');
                    if (nlIdx >= 0) {
                        handleEventStream(client, id);
                        return;
                    }
                } else if (data.contains("\r\n\r\n")) {
                    // Complete HTTP request
                    handleHttpRequest(client, data);
                    return;
                } else if (data.contains("\n") && !data.startsWith("SUBSCRIBE")) {
                    // Non-HTTP, non-SUBSCRIBE — probably malformed
                    handleHttpRequest(client, data);
                    return;
                }
            }
        } catch (Exception e) {
            // Client disconnected during handshake
        } finally {
            try { client.close(); } catch (IOException ignored) {}
        }
    }

    // --- HTTP mode ---

    private static void handleHttpRequest(SocketChannel client, String rawRequest) {
        try {
            if (rawRequest.isEmpty()) {
                client.close();
                return;
            }

            String[] lines = rawRequest.split("\r\n");
            if (lines.length == 0) {
                client.close();
                return;
            }

            String requestLine = lines[0];
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) {
                sendResponse(client, 400, "{\"ok\":false,\"error\":\"Bad request\"}");
                return;
            }

            String method = parts[0];
            String path = parts[1];

            // Parse headers
            java.util.Map<String, String> headers = new java.util.HashMap<>();
            for (int i = 1; i < lines.length; i++) {
                if (lines[i].isEmpty()) break;
                int colonIdx = lines[i].indexOf(':');
                if (colonIdx > 0) {
                    headers.put(
                        lines[i].substring(0, colonIdx).trim().toLowerCase(),
                        lines[i].substring(colonIdx + 1).trim()
                    );
                }
            }

            // Read body if Content-Length present
            String body = "";
            String contentLengthStr = headers.get("content-length");
            if (contentLengthStr != null) {
                int contentLength = Integer.parseInt(contentLengthStr.trim());
                int headerEndPos = rawRequest.indexOf("\r\n\r\n");
                if (headerEndPos >= 0) {
                    StringBuilder bodyBuilder = new StringBuilder(rawRequest.substring(headerEndPos + 4));
                    ByteBuffer buf = ByteBuffer.allocate(4096);
                    while (bodyBuilder.length() < contentLength) {
                        int bytesRead = client.read(buf);
                        if (bytesRead <= 0) break;
                        buf.flip();
                        byte[] bytes = new byte[buf.remaining()];
                        buf.get(bytes);
                        bodyBuilder.append(new String(bytes, StandardCharsets.UTF_8));
                        buf.clear();
                    }
                    body = bodyBuilder.toString();
                    if (body.length() > contentLength) {
                        body = body.substring(0, contentLength);
                    }
                }
            }

            // Route the request (same routing as HttpApi)
            String response = route(method, path, body);
            sendResponse(client, 200, response);

        } catch (Exception e) {
            try {
                String errorJson = "{\"ok\":false,\"error\":" + SwingInspector.jsonString(e.getMessage()) + "}";
                sendResponse(client, 500, errorJson);
            } catch (IOException ignored) {}
        } finally {
            try { client.close(); } catch (IOException ignored) {}
        }
    }

    private static void sendResponse(SocketChannel client, int statusCode, String body) throws IOException {
        String statusText = statusCode == 200 ? "OK" : statusCode == 400 ? "Bad Request" : "Internal Server Error";
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String response = "HTTP/1.1 " + statusCode + " " + statusText + "\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n"
                + "Connection: close\r\n"
                + "\r\n";

        ByteBuffer headerBuf = ByteBuffer.wrap(response.getBytes(StandardCharsets.UTF_8));
        while (headerBuf.hasRemaining()) { client.write(headerBuf); }

        ByteBuffer bodyBuf = ByteBuffer.wrap(bodyBytes);
        while (bodyBuf.hasRemaining()) { client.write(bodyBuf); }
    }

    // --- HTTP routing (migrated from HttpApi) ---

    private static String route(String method, String path, String body) {
        if ("GET".equals(method) && "/health".equals(path)) {
            return wrapOk("{\"status\":\"running\"}");
        }

        if ("GET".equals(method) && "/windows".equals(path)) {
            return wrapOk(SwingInspector.listWindows());
        }

        if (path.startsWith("/windows/")) {
            String remainder = path.substring("/windows/".length());
            int slashIdx = remainder.indexOf('/');
            if (slashIdx < 0) return wrapError("Missing sub-path");

            long windowId;
            try {
                windowId = Long.parseLong(remainder.substring(0, slashIdx));
            } catch (NumberFormatException e) {
                return wrapError("Invalid window ID");
            }
            String subPath = remainder.substring(slashIdx);

            if ("GET".equals(method) && "/components".equals(subPath))
                return wrapOk(SwingInspector.getComponentTree(windowId));
            if ("POST".equals(method) && "/find".equals(subPath)) {
                String type = extractJsonField(body, "type");
                String filter = extractJsonField(body, "filter");
                return wrapOk(SwingInspector.findComponent(windowId, type != null ? type : "", filter));
            }
            if ("POST".equals(method) && "/click".equals(subPath)) {
                String label = extractJsonField(body, "label");
                if (label == null) return wrapError("Missing 'label' field");
                return wrapOk(SwingInspector.clickButton(windowId, label));
            }
            if ("POST".equals(method) && "/type".equals(subPath)) {
                String fieldIndexStr = extractJsonField(body, "fieldIndex");
                String text = extractJsonField(body, "text");
                if (fieldIndexStr == null) return wrapError("Missing 'fieldIndex' field");
                if (text == null) return wrapError("Missing 'text' field");
                try {
                    int fieldIndex = Integer.parseInt(fieldIndexStr);
                    return wrapOk(SwingInspector.typeText(windowId, fieldIndex, text));
                } catch (NumberFormatException e) {
                    return wrapError("Invalid fieldIndex");
                }
            }
            if ("POST".equals(method) && "/key".equals(subPath)) {
                String key = extractJsonField(body, "key");
                if (key == null) return wrapError("Missing 'key' field");
                return wrapOk(SwingInspector.sendKey(windowId, key));
            }
            if ("POST".equals(method) && "/menu".equals(subPath)) {
                String menuPath = extractJsonField(body, "path");
                if (menuPath == null) return wrapError("Missing 'path' field");
                return wrapOk(SwingInspector.clickMenu(windowId, menuPath));
            }
            if ("GET".equals(method) && "/tabs".equals(subPath))
                return wrapOk(SwingInspector.listTabs(windowId));
            if ("POST".equals(method) && "/selectlist".equals(subPath)) {
                String item = extractJsonField(body, "item");
                if (item == null) return wrapError("Missing 'item' field");
                return wrapOk(SwingInspector.selectListItem(windowId, item));
            }
            if ("POST".equals(method) && "/clickat".equals(subPath)) {
                String xStr = extractJsonField(body, "x");
                String yStr = extractJsonField(body, "y");
                if (xStr == null || yStr == null) return wrapError("Missing 'x' or 'y' field");
                try {
                    return wrapOk(SwingInspector.clickAt(windowId, Integer.parseInt(xStr), Integer.parseInt(yStr)));
                } catch (NumberFormatException e) {
                    return wrapError("Invalid x/y coordinates");
                }
            }
            if ("POST".equals(method) && "/tree".equals(subPath)) {
                String node = extractJsonField(body, "node");
                if (node == null) return wrapError("Missing 'node' field");
                return wrapOk(SwingInspector.selectTreeNode(windowId, node));
            }
            if ("GET".equals(method) && "/dump".equals(subPath))
                return wrapOk(SwingInspector.dumpInteractiveComponents(windowId));
            if ("POST".equals(method) && "/checkbox".equals(subPath)) {
                String label = extractJsonField(body, "label");
                if (label == null) return wrapError("Missing 'label' field");
                String stateStr = extractJsonField(body, "state");
                Boolean desiredState = stateStr != null ? Boolean.parseBoolean(stateStr) : null;
                return wrapOk(SwingInspector.setCheckBox(windowId, label, desiredState));
            }

            return wrapError("Unknown endpoint: " + path);
        }

        return wrapError("Not found: " + method + " " + path);
    }

    private static String wrapOk(String data) {
        return "{\"ok\":true,\"data\":" + data + ",\"error\":null}";
    }

    private static String wrapError(String message) {
        return "{\"ok\":false,\"data\":null,\"error\":" + SwingInspector.jsonString(message) + "}";
    }

    static String extractJsonField(String json, String field) {
        return HttpApi.extractJsonField(json, field);
    }

    // --- Event stream mode ---

    private static void handleEventStream(SocketChannel client, int id) {
        eventSubscribers.add(client);
        System.out.println("[ibctl-agent] Event subscriber connected (#" + id + ", total=" + eventSubscribers.size() + ")");
        try {
            // Send hello
            writeLine(client, buildHello());
            // Send snapshot of all current windows
            writeLine(client, buildSnapshot());
            // If overflow occurred before this client, signal resync
            if (overflowed) {
                overflowed = false;
                writeLine(client, buildOverflow());
            }

            // Keep connection alive — events are pushed by the broadcast thread.
            // This thread just sends keepalives and detects disconnect.
            while (client.isOpen()) {
                Thread.sleep(KEEPALIVE_INTERVAL_MS);
                writeLine(client, buildKeepalive());
            }
        } catch (Exception e) {
            // Client disconnected
        } finally {
            eventSubscribers.remove(client);
            System.out.println("[ibctl-agent] Event subscriber disconnected (#" + id + ", remaining=" + eventSubscribers.size() + ")");
            try { client.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Background thread: drains the event queue and broadcasts to all subscribers.
     * Removes dead subscribers on write failure.
     */
    private static void broadcastLoop() {
        while (true) {
            try {
                // Block until an event is available (or timeout for housekeeping)
                String event = eventQueue.poll(5, TimeUnit.SECONDS);
                if (event == null) continue;

                // Batch: drain all pending events
                java.util.List<String> batch = new java.util.ArrayList<>();
                batch.add(event);
                eventQueue.drainTo(batch);

                // Broadcast to all subscribers
                for (String e : batch) {
                    for (SocketChannel sub : eventSubscribers) {
                        try {
                            writeLine(sub, e);
                        } catch (IOException ex) {
                            // Dead subscriber — remove
                            eventSubscribers.remove(sub);
                            try { sub.close(); } catch (IOException ignored) {}
                        }
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static void writeLine(SocketChannel client, String json) throws IOException {
        byte[] bytes = (json + "\n").getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        while (buf.hasRemaining()) {
            if (client.write(buf) == -1) {
                throw new IOException("Client closed");
            }
        }
    }

    // --- Event emission (called from AWT thread via WindowMonitor) ---

    /**
     * Emit a window_opened event + semantic events based on component inspection.
     * Called from WindowMonitor's AWT listener (runs on AWT event thread).
     */
    public static void windowOpened(Window w) {
        long seq = sequence.incrementAndGet();
        boolean hasLoginButton = hasLoginButton(w);
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"type\":\"window_opened\"");
        sb.append(",\"seq\":").append(seq);
        sb.append(",\"window_id\":").append(System.identityHashCode(w));
        sb.append(",\"window_title\":").append(SwingInspector.jsonString(getWindowTitle(w)));
        sb.append(",\"window_class\":").append(SwingInspector.jsonString(w.getClass().getName()));
        sb.append(",\"has_login_button\":").append(hasLoginButton);
        appendBounds(sb, w);
        sb.append(",\"ts\":").append(System.currentTimeMillis());
        sb.append("}");
        enqueue(sb.toString());

        // --- Wave 3: semantic events ---
        emitSemanticEvents(w, seq);
    }

    /**
     * Emit a window_closed event.
     */
    public static void windowClosed(Window w) {
        long seq = sequence.incrementAndGet();
        StringBuilder sb = new StringBuilder(128);
        sb.append("{\"type\":\"window_closed\"");
        sb.append(",\"seq\":").append(seq);
        sb.append(",\"window_id\":").append(System.identityHashCode(w));
        sb.append(",\"window_title\":").append(SwingInspector.jsonString(getWindowTitle(w)));
        sb.append(",\"ts\":").append(System.currentTimeMillis());
        sb.append("}");
        enqueue(sb.toString());
    }

    // --- Wave 3: Semantic event emission ---

    /**
     * Inspect the Swing component tree of a newly opened window and emit
     * high-level semantic events. These give the Rust state machine richer
     * information without needing HTTP dump_components calls.
     *
     * Runs on AWT event thread (safe for Swing component access).
     */
    private static void emitSemanticEvents(Window w, long parentSeq) {
        String title = getWindowTitle(w);
        String titleLower = title.toLowerCase();

        // Login form detection
        if (titleLower.contains("ib gateway") || titleLower.contains("ibkr gateway")) {
            emitLoginFormEvent(w, title);
        }

        // 2FA dialog detection
        if (titleLower.contains("second factor") || titleLower.contains("security code")
                || titleLower.contains("ib key authenticat")) {
            emitTwofaEvent(w, title);
        }

        // Error/warning dialog detection (JOptionPane or small dialog with message)
        if (w instanceof Dialog) {
            Dialog d = (Dialog) w;
            if (d.isModal() || titleLower.contains("error") || titleLower.contains("warning")
                    || titleLower.contains("failed") || titleLower.contains("connection")) {
                emitErrorDialogEvent(w, title);
            }
        }
    }

    /**
     * Emit login_form_ready with field inventory from component inspection.
     */
    private static void emitLoginFormEvent(Window w, String title) {
        int textFieldCount = 0;
        int passwordFieldCount = 0;
        String loginButtonLabel = null;
        String selectedMode = null;

        // Walk component tree
        java.util.List<Component> all = new java.util.ArrayList<>();
        collectComponents(w, all);

        for (Component c : all) {
            if (c instanceof JTextField && !(c instanceof JPasswordField)) {
                textFieldCount++;
            } else if (c instanceof JPasswordField) {
                passwordFieldCount++;
            } else if (c instanceof JButton) {
                String text = ((JButton) c).getText();
                if (text != null) {
                    String tl = text.toLowerCase();
                    if (tl.contains("log in") || tl.equals("login")) {
                        loginButtonLabel = text;
                    }
                }
            } else if (c instanceof JRadioButton) {
                JRadioButton rb = (JRadioButton) c;
                if (rb.isSelected()) {
                    selectedMode = rb.getText();
                }
            }
        }

        // Only emit if this looks like a login form (has fields or login button)
        if (textFieldCount == 0 && passwordFieldCount == 0 && loginButtonLabel == null) {
            return;
        }

        long seq = sequence.incrementAndGet();
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"type\":\"login_form_ready\"");
        sb.append(",\"seq\":").append(seq);
        sb.append(",\"window_id\":").append(System.identityHashCode(w));
        sb.append(",\"text_field_count\":").append(textFieldCount);
        sb.append(",\"password_field_count\":").append(passwordFieldCount);
        if (loginButtonLabel != null) {
            sb.append(",\"login_button\":").append(SwingInspector.jsonString(loginButtonLabel));
        } else {
            sb.append(",\"login_button\":null");
        }
        if (selectedMode != null) {
            sb.append(",\"selected_mode\":").append(SwingInspector.jsonString(selectedMode));
        } else {
            sb.append(",\"selected_mode\":null");
        }
        sb.append(",\"ts\":").append(System.currentTimeMillis());
        sb.append("}");
        enqueue(sb.toString());
    }

    /**
     * Emit twofa_prompt with dialog structure details.
     */
    private static void emitTwofaEvent(Window w, String title) {
        String promptType = "challenge"; // default
        java.util.List<String> devices = new java.util.ArrayList<>();

        java.util.List<Component> all = new java.util.ArrayList<>();
        collectComponents(w, all);

        for (Component c : all) {
            if (c instanceof JList) {
                // Device selection list
                promptType = "device_selection";
                JList<?> list = (JList<?>) c;
                javax.swing.ListModel<?> model = list.getModel();
                for (int i = 0; i < model.getSize(); i++) {
                    Object item = model.getElementAt(i);
                    if (item != null) devices.add(item.toString());
                }
            } else if (c instanceof JTextField) {
                // Code entry field
                promptType = "code_entry";
            }
        }

        long seq = sequence.incrementAndGet();
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"type\":\"twofa_prompt\"");
        sb.append(",\"seq\":").append(seq);
        sb.append(",\"window_id\":").append(System.identityHashCode(w));
        sb.append(",\"prompt_type\":").append(SwingInspector.jsonString(promptType));
        sb.append(",\"devices\":[");
        for (int i = 0; i < devices.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(SwingInspector.jsonString(devices.get(i)));
        }
        sb.append("]");
        sb.append(",\"ts\":").append(System.currentTimeMillis());
        sb.append("}");
        enqueue(sb.toString());
    }

    /**
     * Emit error_dialog with message text and button labels.
     */
    private static void emitErrorDialogEvent(Window w, String title) {
        String message = null;
        java.util.List<String> buttons = new java.util.ArrayList<>();

        java.util.List<Component> all = new java.util.ArrayList<>();
        collectComponents(w, all);

        for (Component c : all) {
            if (c instanceof JLabel) {
                String text = ((JLabel) c).getText();
                if (text != null && !text.isEmpty() && text.length() > 3) {
                    // Take the longest label as the message
                    if (message == null || text.length() > message.length()) {
                        message = text;
                    }
                }
            } else if (c instanceof JButton) {
                String text = ((JButton) c).getText();
                if (text != null && !text.isEmpty()) {
                    buttons.add(text);
                }
            }
        }

        // Skip if no meaningful content
        if (message == null && buttons.isEmpty()) return;

        long seq = sequence.incrementAndGet();
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"type\":\"error_dialog\"");
        sb.append(",\"seq\":").append(seq);
        sb.append(",\"window_id\":").append(System.identityHashCode(w));
        sb.append(",\"window_title\":").append(SwingInspector.jsonString(title));
        if (message != null) {
            sb.append(",\"message\":").append(SwingInspector.jsonString(message));
        } else {
            sb.append(",\"message\":null");
        }
        sb.append(",\"buttons\":[");
        for (int i = 0; i < buttons.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(SwingInspector.jsonString(buttons.get(i)));
        }
        sb.append("]");
        sb.append(",\"ts\":").append(System.currentTimeMillis());
        sb.append("}");
        enqueue(sb.toString());
    }

    // --- Helpers ---

    private static void collectComponents(Container c, java.util.List<Component> result) {
        for (Component child : c.getComponents()) {
            result.add(child);
            if (child instanceof Container) {
                collectComponents((Container) child, result);
            }
        }
    }

    private static void enqueue(String event) {
        if (!eventQueue.offer(event)) {
            eventQueue.poll();
            overflowed = true;
            eventQueue.offer(event);
        }
    }

    // --- Protocol message builders ---

    static String buildHello() {
        return "{\"type\":\"hello\""
                + ",\"protocol_version\":" + PROTOCOL_VERSION
                + ",\"agent_tick_ms\":" + IbctlAgent.agentTickMs
                + ",\"ts\":" + System.currentTimeMillis()
                + "}";
    }

    static String buildSnapshot() {
        long seq = sequence.incrementAndGet();
        List<Window> windows = WindowMonitor.getOpenWindows();
        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"type\":\"snapshot\"");
        sb.append(",\"seq\":").append(seq);
        sb.append(",\"windows\":[");
        boolean first = true;
        for (Window w : windows) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"window_id\":").append(System.identityHashCode(w));
            sb.append(",\"window_title\":").append(SwingInspector.jsonString(getWindowTitle(w)));
            sb.append(",\"window_class\":").append(SwingInspector.jsonString(w.getClass().getName()));
            sb.append(",\"has_login_button\":").append(hasLoginButton(w));
            appendBounds(sb, w);
            sb.append("}");
        }
        sb.append("]");
        sb.append(",\"ts\":").append(System.currentTimeMillis());
        sb.append("}");
        return sb.toString();
    }

    private static String buildKeepalive() {
        return "{\"type\":\"keepalive\""
                + ",\"seq\":" + sequence.incrementAndGet()
                + ",\"ts\":" + System.currentTimeMillis()
                + "}";
    }

    private static String buildOverflow() {
        return "{\"type\":\"overflow\""
                + ",\"seq\":" + sequence.incrementAndGet()
                + ",\"ts\":" + System.currentTimeMillis()
                + "}";
    }

    static String getWindowTitle(Window w) {
        if (w instanceof Frame) return ((Frame) w).getTitle();
        if (w instanceof Dialog) return ((Dialog) w).getTitle();
        return "";
    }

    private static void appendBounds(StringBuilder sb, Window w) {
        Rectangle bounds = w.getBounds();
        sb.append(",\"bounds\":{\"x\":").append(bounds.x);
        sb.append(",\"y\":").append(bounds.y);
        sb.append(",\"width\":").append(bounds.width);
        sb.append(",\"height\":").append(bounds.height);
        sb.append("}");
    }

    private static boolean hasLoginButton(Window w) {
        return findButton(w, "Login") != null
            || findButton(w, "Log In") != null
            || findButton(w, "Paper Log In") != null;
    }

    private static javax.swing.JButton findButton(Container c, String text) {
        for (Component child : c.getComponents()) {
            if (child instanceof javax.swing.JButton) {
                javax.swing.JButton btn = (javax.swing.JButton) child;
                if (text.equals(btn.getText())) return btn;
            }
            if (child instanceof Container) {
                javax.swing.JButton found = findButton((Container) child, text);
                if (found != null) return found;
            }
        }
        return null;
    }
}
