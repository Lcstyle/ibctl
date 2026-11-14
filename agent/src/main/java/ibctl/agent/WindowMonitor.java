package ibctl.agent;

import java.awt.*;
import java.awt.event.WindowEvent;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.swing.SwingUtilities;

/**
 * Monitors AWT window open/close events and maintains a thread-safe list
 * of currently open windows. Supports blocking waits for windows matching
 * a title pattern.
 *
 * <p>Also stamps the main Gateway JFrame title with a {@code [LIVE]} or
 * {@code [PAPER]} suffix so operators can tell the two instances apart on
 * VNC. Mode is derived from the {@code -DjtsConfigDir=...} system property
 * the JVM was launched with (contains either {@code Jts_live} or
 * {@code Jts_paper}). ibctl's title predicates all use {@code contains},
 * so the suffix is transparent to downstream detection logic.
 */
public class WindowMonitor {
    private static final CopyOnWriteArrayList<Window> openWindows = new CopyOnWriteArrayList<>();
    private static final CopyOnWriteArrayList<WindowWaiter> waiters = new CopyOnWriteArrayList<>();
    private static volatile boolean installed = false;

    /** "LIVE", "PAPER", or "" (unknown — no stamping done). */
    private static final String MODE_TAG = detectModeTag();
    /** Frames we have already attached the title-reapply listener to. */
    private static final Set<Frame> taggedFrames =
            Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

    /**
     * Registers the AWTEventListener for window open/close events.
     * Safe to call multiple times; only installs once.
     */
    public static void install() {
        if (installed) return;
        installed = true;

        // Capture any already-open windows
        for (Window w : Window.getWindows()) {
            if (w.isShowing() && !openWindows.contains(w)) {
                openWindows.add(w);
            }
        }

        Toolkit.getDefaultToolkit().addAWTEventListener(event -> {
            if (!(event instanceof WindowEvent)) return;
            WindowEvent we = (WindowEvent) event;
            Window window = we.getWindow();

            if (we.getID() == WindowEvent.WINDOW_OPENED) {
                if (!openWindows.contains(window)) {
                    openWindows.add(window);
                }
                stampModeTag(window);
                notifyWaiters(window);
                MultiplexedServer.windowOpened(window);
            } else if (we.getID() == WindowEvent.WINDOW_CLOSED) {
                openWindows.remove(window);
                MultiplexedServer.windowClosed(window);
            }
        }, AWTEvent.WINDOW_EVENT_MASK);
    }

    /**
     * Returns the current list of open windows (snapshot).
     */
    public static List<Window> getOpenWindows() {
        // Prune any windows that have been disposed but we missed the event
        openWindows.removeIf(w -> !w.isShowing());
        return List.copyOf(openWindows);
    }

    /**
     * Blocks until a window with a title matching the given regex pattern appears,
     * or until the timeout expires.
     *
     * @param titlePattern regex pattern to match against window titles
     * @param timeoutMs    maximum time to wait in milliseconds
     * @return the matching Window, or null if timed out
     */
    public static Window waitForWindow(String titlePattern, long timeoutMs) {
        Pattern pattern = Pattern.compile(titlePattern);

        // Check already-open windows first
        for (Window w : openWindows) {
            String title = getWindowTitle(w);
            if (title != null && pattern.matcher(title).find()) {
                return w;
            }
        }

        // Register a waiter and block
        WindowWaiter waiter = new WindowWaiter(pattern);
        waiters.add(waiter);
        try {
            if (waiter.latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                return waiter.matched;
            }
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            waiters.remove(waiter);
        }
    }

    /**
     * Returns JSON array of currently open windows.
     */
    public static String toJson() {
        List<Window> windows = getOpenWindows();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Window w : windows) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{");
            sb.append("\"id\":").append(System.identityHashCode(w));
            sb.append(",\"title\":").append(SwingInspector.jsonString(getWindowTitle(w)));
            sb.append(",\"class\":").append(SwingInspector.jsonString(w.getClass().getName()));
            sb.append(",\"showing\":").append(w.isShowing());
            sb.append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    // --- Internal ---

    private static void notifyWaiters(Window window) {
        String title = getWindowTitle(window);
        for (WindowWaiter waiter : waiters) {
            if (title != null && waiter.pattern.matcher(title).find()) {
                waiter.matched = window;
                waiter.latch.countDown();
            }
        }
    }

    private static String getWindowTitle(Window w) {
        if (w instanceof Frame) return ((Frame) w).getTitle();
        if (w instanceof Dialog) return ((Dialog) w).getTitle();
        return "";
    }

    /**
     * Stamps the Gateway main window's title with a mode tag once per window.
     * Re-applies if Gateway rewrites the title later (PropertyChangeListener).
     * No-op for dialogs, for non-Gateway windows, or if mode is unknown.
     */
    private static void stampModeTag(Window window) {
        if (MODE_TAG.isEmpty()) return;
        if (!(window instanceof Frame)) return;
        Frame frame = (Frame) window;
        String title = frame.getTitle();
        if (title == null) return;
        String lower = title.toLowerCase();
        // Only the main Gateway frame — skip dialogs and unrelated frames.
        if (!(lower.contains("ibkr gateway") || lower.contains("ib gateway"))) return;

        final String suffix = " [" + MODE_TAG + "]";
        Runnable applyIfNeeded = () -> {
            String current = frame.getTitle();
            if (current != null && !current.contains(suffix)) {
                frame.setTitle(current + suffix);
            }
        };
        SwingUtilities.invokeLater(applyIfNeeded);

        // Re-apply on title changes — Frame fires "title" property events.
        // WeakHashMap-backed set dedupes per frame without leaking references.
        if (taggedFrames.add(frame)) {
            frame.addPropertyChangeListener("title", evt -> applyIfNeeded.run());
        }
    }

    private static String detectModeTag() {
        String jts = System.getProperty("jtsConfigDir", "");
        if (jts.contains("Jts_live")) return "LIVE";
        if (jts.contains("Jts_paper")) return "PAPER";
        return "";
    }

    private static class WindowWaiter {
        final Pattern pattern;
        final CountDownLatch latch = new CountDownLatch(1);
        volatile Window matched;

        WindowWaiter(Pattern pattern) {
            this.pattern = pattern;
        }
    }
}
