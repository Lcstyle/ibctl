package ibctl.agent;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.lang.reflect.InvocationTargetException;
import javax.swing.*;

/**
 * Utility class for performing UI actions thread-safely.
 * All mutating operations execute on the Swing EDT via SwingUtilities.invokeAndWait.
 */
public class Actions {

    /**
     * Click a component. For AbstractButton subclasses (JButton, JToggleButton, etc.),
     * uses doClick(). For other components, dispatches a mouse click event.
     */
    public static void clickComponent(Component c) throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(() -> {
            if (c instanceof AbstractButton) {
                ((AbstractButton) c).doClick();
            } else {
                // For non-button components, dispatch a mouse click at center
                Point center = new Point(c.getWidth() / 2, c.getHeight() / 2);
                c.dispatchEvent(new java.awt.event.MouseEvent(
                        c,
                        java.awt.event.MouseEvent.MOUSE_CLICKED,
                        System.currentTimeMillis(),
                        0,
                        center.x, center.y,
                        1, // click count
                        false // not a popup trigger
                ));
            }
        });
    }

    /**
     * Type text into a JTextField. Requests focus first, then sets the text.
     */
    public static void typeIntoField(JTextField field, String text) throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(() -> {
            field.requestFocusInWindow();
            field.setText(text);
        });
    }

    /**
     * Send a key event to a window. Dispatches both KEY_PRESSED and KEY_RELEASED
     * events to the window's focus owner (or the window itself if no focus owner).
     *
     * @param window    the target window
     * @param keyCode   the VK_ key code (e.g. KeyEvent.VK_ENTER)
     * @param modifiers modifier mask (e.g. KeyEvent.CTRL_DOWN_MASK)
     */
    public static void sendKeyToWindow(Window window, int keyCode, int modifiers) throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(() -> {
            Component target = window.getFocusOwner();
            if (target == null) target = window;

            char keyChar = KeyEvent.CHAR_UNDEFINED;
            // Try to derive a reasonable keyChar for simple keys
            if (modifiers == 0 && keyCode >= KeyEvent.VK_A && keyCode <= KeyEvent.VK_Z) {
                keyChar = (char) ('a' + (keyCode - KeyEvent.VK_A));
            } else if (modifiers == 0 && keyCode >= KeyEvent.VK_0 && keyCode <= KeyEvent.VK_9) {
                keyChar = (char) ('0' + (keyCode - KeyEvent.VK_0));
            }

            long now = System.currentTimeMillis();

            KeyEvent press = new KeyEvent(
                    target, KeyEvent.KEY_PRESSED, now,
                    modifiers, keyCode, keyChar
            );
            KeyEvent release = new KeyEvent(
                    target, KeyEvent.KEY_RELEASED, now,
                    modifiers, keyCode, keyChar
            );

            target.dispatchEvent(press);
            target.dispatchEvent(release);

            // If it's a printable character with no modifiers, also send KEY_TYPED
            if (modifiers == 0 && keyChar != KeyEvent.CHAR_UNDEFINED) {
                KeyEvent typed = new KeyEvent(
                        target, KeyEvent.KEY_TYPED, now,
                        0, KeyEvent.VK_UNDEFINED, keyChar
                );
                target.dispatchEvent(typed);
            }
        });
    }

    /**
     * Clear a text field by setting its text to empty string.
     */
    public static void clearField(JTextField field) throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(() -> {
            field.requestFocusInWindow();
            field.setText("");
        });
    }
}
