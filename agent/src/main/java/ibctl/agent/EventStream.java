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
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Pushes UI events as newline-delimited JSON (NDJSON) over a dedicated
 * Unix domain socket. One client at a time (the Rust state machine).
 *
 * <p>Protocol features (per GPT-5.4 architectural review):
 * <ul>
 *   <li>{@code hello} — protocol version + capabilities on connect</li>
 *   <li>{@code snapshot} — all current windows on connect</li>
 *   <li>{@code seq} — monotonic sequence number on every event</li>
 *   <li>{@code overflow} — emitted if queue drops events (never silent)</li>
 *   <li>{@code keepalive} — periodic heartbeat</li>
 * </ul>
 *
 * <p>Thread model:
 * <ul>
 *   <li>AWT EventListener enqueues events (non-blocking offer to bounded queue)</li>
 *   <li>Writer thread accepts one connection, sends hello+snapshot, drains queue</li>
 *   <li>If client disconnects, loops back to accept</li>
 * </ul>
 */
public class EventStream {
    private static final int QUEUE_CAPACITY = 256;
    private static final int PROTOCOL_VERSION = 1;
    private static final long KEEPALIVE_INTERVAL_MS = 30_000;

    private static final LinkedBlockingQueue<String> eventQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private static final AtomicLong sequence = new AtomicLong(0);
    private static volatile boolean overflowed = false;

    /**
     * Start the event stream server. Blocks forever (run on daemon thread).
     */
    public static void start(String socketPath) throws IOException {
        Path path = Path.of(socketPath);
        Files.deleteIfExists(path);

        ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(path));

        System.out.println("[ibctl-agent] Event stream listening on " + socketPath);

        while (true) {
            try {
                SocketChannel client = server.accept();
                System.out.println("[ibctl-agent] Event stream client connected");
                handleClient(client);
            } catch (Exception e) {
                System.err.println("[ibctl-agent] Event stream accept error: " + e.getMessage());
            }
        }
    }

    private static void handleClient(SocketChannel client) {
        try {
            // Send hello
            writeLine(client, buildHello());

            // Send snapshot of all current windows
            writeLine(client, buildSnapshot());

            // If we overflowed before this client connected, signal resync
            if (overflowed) {
                overflowed = false;
                writeLine(client, buildOverflow());
            }

            // Main event loop: drain queue with keepalive timeout
            while (client.isOpen()) {
                String event = eventQueue.poll(KEEPALIVE_INTERVAL_MS,
                        java.util.concurrent.TimeUnit.MILLISECONDS);

                if (event == null) {
                    // Timeout — send keepalive
                    writeLine(client, buildKeepalive());
                } else {
                    writeLine(client, event);

                    // Drain any additional queued events (batch)
                    String next;
                    while ((next = eventQueue.poll()) != null) {
                        writeLine(client, next);
                    }
                }
            }
        } catch (Exception e) {
            // Client disconnected or write failed
            System.out.println("[ibctl-agent] Event stream client disconnected");
        } finally {
            try { client.close(); } catch (IOException ignored) {}
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

    // --- Event emission (called from AWT thread) ---

    /**
     * Emit a window_opened event. Called from WindowMonitor's AWT listener.
     * Non-blocking: if queue full, drops oldest and sets overflow flag.
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
    }

    /**
     * Emit a window_closed event. Called from WindowMonitor's AWT listener.
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

    // --- Protocol messages ---

    private static String buildHello() {
        return "{\"type\":\"hello\""
                + ",\"protocol_version\":" + PROTOCOL_VERSION
                + ",\"agent_tick_ms\":" + IbctlAgent.agentTickMs
                + ",\"ts\":" + System.currentTimeMillis()
                + "}";
    }

    private static String buildSnapshot() {
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

    // --- Helpers ---

    private static void enqueue(String event) {
        if (!eventQueue.offer(event)) {
            // Queue full — drop oldest, set overflow flag
            eventQueue.poll();
            overflowed = true;
            eventQueue.offer(event);
        }
    }

    private static String getWindowTitle(Window w) {
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

    /**
     * Check if a window contains a login button — the authoritative signal
     * that this is the login form (not the config dialog or connected state).
     *
     * Matches IBC's GatewayLoginFrameHandler.recogniseWindow() which checks
     * for "Login", "Log In", or "Paper Log In" buttons.
     *
     * Runs on the AWT event thread (caller context), safe for Swing.
     */
    private static boolean hasLoginButton(Window w) {
        return findButton(w, "Login") != null
            || findButton(w, "Log In") != null
            || findButton(w, "Paper Log In") != null;
    }

    /**
     * Find a JButton by label text in a container hierarchy.
     * Matches IBC's SwingUtils.findButton() pattern.
     */
    private static javax.swing.JButton findButton(Container c, String text) {
        for (Component child : c.getComponents()) {
            if (child instanceof javax.swing.JButton) {
                javax.swing.JButton btn = (javax.swing.JButton) child;
                if (text.equals(btn.getText())) {
                    return btn;
                }
            }
            if (child instanceof Container) {
                javax.swing.JButton found = findButton((Container) child, text);
                if (found != null) return found;
            }
        }
        return null;
    }
}
