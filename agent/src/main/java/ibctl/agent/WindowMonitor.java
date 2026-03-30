package ibctl.agent;

import java.awt.*;
import java.awt.event.WindowEvent;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Monitors AWT window open/close events and maintains a thread-safe list
 * of currently open windows. Supports blocking waits for windows matching
 * a title pattern.
 */
public class WindowMonitor {
    private static final CopyOnWriteArrayList<Window> openWindows = new CopyOnWriteArrayList<>();
    private static final CopyOnWriteArrayList<WindowWaiter> waiters = new CopyOnWriteArrayList<>();
    private static volatile boolean installed = false;

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
                notifyWaiters(window);
            } else if (we.getID() == WindowEvent.WINDOW_CLOSED) {
                openWindows.remove(window);
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

    private static class WindowWaiter {
        final Pattern pattern;
        final CountDownLatch latch = new CountDownLatch(1);
        volatile Window matched;

        WindowWaiter(Pattern pattern) {
            this.pattern = pattern;
        }
    }
}
