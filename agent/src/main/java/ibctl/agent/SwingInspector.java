package ibctl.agent;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.*;

/**
 * Component tree walking utility for Swing UI inspection and interaction.
 * All methods that mutate UI state use SwingUtilities.invokeAndWait for thread safety.
 */
public class SwingInspector {

    /**
     * Returns a JSON array of all visible Window instances with id, title, class, bounds.
     */
    public static String listWindows() {
        Window[] windows = Window.getWindows();
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Window w : windows) {
            if (!w.isShowing()) continue;
            if (!first) sb.append(",");
            first = false;
            sb.append("{");
            sb.append("\"id\":").append(System.identityHashCode(w));
            sb.append(",\"title\":").append(jsonString(getWindowTitle(w)));
            sb.append(",\"class\":").append(jsonString(w.getClass().getName()));
            Rectangle bounds = w.getBounds();
            sb.append(",\"bounds\":{");
            sb.append("\"x\":").append(bounds.x);
            sb.append(",\"y\":").append(bounds.y);
            sb.append(",\"width\":").append(bounds.width);
            sb.append(",\"height\":").append(bounds.height);
            sb.append("}}");
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Returns the recursive component tree of a window as JSON.
     */
    public static String getComponentTree(long windowId) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "null";
        }
        return componentToJson(window, 0);
    }

    /**
     * Find a JTextField in the given window by position index (0-based).
     */
    public static JTextField findTextField(long windowId, int index) {
        Window window = findWindowById(windowId);
        if (window == null) return null;

        List<JTextField> fields = new ArrayList<>();
        collectComponents(window, JTextField.class, fields);

        if (index >= 0 && index < fields.size()) {
            return fields.get(index);
        }
        return null;
    }

    /**
     * Find a JButton in the given window by text label.
     */
    /**
     * Find any AbstractButton (JButton, JRadioButton, JToggleButton, JCheckBox)
     * by label text. Matches IBC's SwingUtils.findButton() which searches all
     * AbstractButton subclasses.
     */
    public static AbstractButton findButton(long windowId, String label) {
        Window window = findWindowById(windowId);
        if (window == null) return null;

        List<AbstractButton> buttons = new ArrayList<>();
        collectComponents(window, AbstractButton.class, buttons);

        // Exact match first (IBC pattern)
        for (AbstractButton button : buttons) {
            String text = button.getText();
            if (text != null && text.equals(label)) {
                return button;
            }
        }
        // Case-insensitive fallback
        for (AbstractButton button : buttons) {
            String text = button.getText();
            if (text != null && text.equalsIgnoreCase(label)) {
                return button;
            }
        }
        return null;
    }

    /**
     * Click any AbstractButton by label. Covers JButton, JRadioButton,
     * JToggleButton, JCheckBox. Uses SwingUtilities.invokeAndWait for thread safety.
     * Returns JSON result string.
     */
    public static String clickButton(long windowId, String label) {
        AbstractButton button = findButton(windowId, label);
        if (button == null) {
            return "{\"found\":false,\"error\":\"Button not found: " + escapeJson(label) + "\"}";
        }

        // Use invokeLater (not invokeAndWait) because doClick() may open a modal
        // dialog that blocks the EDT, which would deadlock invokeAndWait.
        // This matches the same pattern used in setCheckBox.
        SwingUtilities.invokeLater(() -> {
            if (!button.isSelected() && (button instanceof JRadioButton || button instanceof JToggleButton)) {
                button.setSelected(true);
            }
            button.doClick();
        });
        try { Thread.sleep(IbctlAgent.agentTickMs); } catch (InterruptedException ignored) {}
        return "{\"found\":true,\"clicked\":true}";
    }

    /**
     * Type text into a text field by index. Uses SwingUtilities.invokeAndWait.
     * Returns JSON result string.
     */
    public static String typeText(long windowId, int fieldIndex, String text) {
        JTextField field = findTextField(windowId, fieldIndex);
        if (field == null) {
            return "{\"found\":false,\"error\":\"TextField not found at index: " + fieldIndex + "\"}";
        }

        try {
            SwingUtilities.invokeAndWait(() -> {
                field.requestFocusInWindow();
                field.setText(text);
            });
            return "{\"found\":true,\"typed\":true}";
        } catch (InterruptedException | InvocationTargetException e) {
            return "{\"found\":true,\"typed\":false,\"error\":" + jsonString(e.getMessage()) + "}";
        }
    }

    /**
     * Send a keystroke to a window. The keyStroke string should be parseable by
     * KeyStroke.getKeyStroke() (e.g. "ctrl F", "ENTER", "alt F4").
     * Returns JSON result string.
     */
    /**
     * List all JTabbedPane tab titles in a window.
     * Used to enumerate connected API client IDs from the Gateway's client tabs.
     * Returns JSON: {"tabs": [{"index": 0, "title": "Client 50"}, ...]}
     */
    public static String listTabs(long windowId) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"tabs\":[],\"error\":\"Window not found\"}";
        }

        List<JTabbedPane> panes = new ArrayList<>();
        collectComponents(window, JTabbedPane.class, panes);

        StringBuilder sb = new StringBuilder("{\"tabs\":[");
        boolean first = true;
        for (JTabbedPane pane : panes) {
            for (int i = 0; i < pane.getTabCount(); i++) {
                if (!first) sb.append(",");
                first = false;
                String title = pane.getTitleAt(i);
                sb.append("{\"index\":").append(i);
                sb.append(",\"title\":").append(jsonString(title != null ? title : ""));
                sb.append(",\"selected\":").append(pane.getSelectedIndex() == i);
                sb.append("}");
            }
        }
        sb.append("]}");
        return sb.toString();
    }

    /**
     * Send a mouse click at coordinates relative to the window.
     * Useful for dismissing menus or clicking arbitrary locations.
     */
    public static String clickAt(long windowId, int x, int y) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"found\":false,\"error\":\"Window not found\"}";
        }

        SwingUtilities.invokeLater(() -> {
            java.awt.event.MouseEvent press = new java.awt.event.MouseEvent(
                window, java.awt.event.MouseEvent.MOUSE_PRESSED,
                System.currentTimeMillis(), 0, x, y, 1, false, java.awt.event.MouseEvent.BUTTON1);
            java.awt.event.MouseEvent release = new java.awt.event.MouseEvent(
                window, java.awt.event.MouseEvent.MOUSE_RELEASED,
                System.currentTimeMillis(), 0, x, y, 1, false, java.awt.event.MouseEvent.BUTTON1);
            java.awt.event.MouseEvent click = new java.awt.event.MouseEvent(
                window, java.awt.event.MouseEvent.MOUSE_CLICKED,
                System.currentTimeMillis(), 0, x, y, 1, false, java.awt.event.MouseEvent.BUTTON1);
            window.dispatchEvent(press);
            window.dispatchEvent(release);
            window.dispatchEvent(click);
        });
        try { Thread.sleep(IbctlAgent.agentTickMs); } catch (InterruptedException ignored) {}
        return "{\"found\":true,\"clicked\":true,\"x\":" + x + ",\"y\":" + y + "}";
    }

    /**
     * Select an item in the first JList found in a window by matching text.
     * Used for the 2FA device selection dialog.
     */
    public static String selectListItem(long windowId, String itemText) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"found\":false,\"error\":\"Window not found\"}";
        }

        List<JList> lists = new ArrayList<>();
        collectComponents(window, JList.class, lists);
        if (lists.isEmpty()) {
            return "{\"found\":false,\"error\":\"No JList found in window\"}";
        }

        JList<?> list = lists.get(0);
        javax.swing.ListModel<?> model = list.getModel();

        for (int i = 0; i < model.getSize(); i++) {
            Object item = model.getElementAt(i);
            String text = item != null ? item.toString() : "";
            if (text.equalsIgnoreCase(itemText) || text.toLowerCase().contains(itemText.toLowerCase())) {
                final int idx = i;
                final JList<?> finalList = list;
                SwingUtilities.invokeLater(() -> {
                    finalList.setSelectedIndex(idx);
                    finalList.ensureIndexIsVisible(idx);
                });
                try { Thread.sleep(IbctlAgent.agentTickMs); } catch (InterruptedException ignored) {}
                return "{\"found\":true,\"index\":" + i + ",\"text\":" + jsonString(text) + "}";
            }
        }

        return "{\"found\":false,\"error\":\"List item not found: " + escapeJson(itemText) + "\"}";
    }

    public static String sendKey(long windowId, String keyStroke) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"found\":false,\"error\":\"Window not found\"}";
        }

        KeyStroke ks = KeyStroke.getKeyStroke(keyStroke);
        if (ks == null) {
            return "{\"found\":true,\"sent\":false,\"error\":\"Invalid keystroke: " + escapeJson(keyStroke) + "\"}";
        }

        try {
            SwingUtilities.invokeAndWait(() -> {
                Component target = window.getFocusOwner();
                if (target == null) target = window;
                KeyEvent press = new KeyEvent(target, KeyEvent.KEY_PRESSED,
                        System.currentTimeMillis(), ks.getModifiers(),
                        ks.getKeyCode(), ks.getKeyChar());
                KeyEvent release = new KeyEvent(target, KeyEvent.KEY_RELEASED,
                        System.currentTimeMillis(), ks.getModifiers(),
                        ks.getKeyCode(), ks.getKeyChar());
                target.dispatchEvent(press);
                target.dispatchEvent(release);
            });
            return "{\"found\":true,\"sent\":true}";
        } catch (InterruptedException | InvocationTargetException e) {
            return "{\"found\":true,\"sent\":false,\"error\":" + jsonString(e.getMessage()) + "}";
        }
    }

    /**
     * Navigate and click a menu item by path (e.g., "Configure/API/Settings").
     * Mirrors IBC's approach of navigating JMenuBar -> JMenu -> JMenuItem.
     * Path components are separated by "/".
     * Returns JSON result string.
     */
    public static String clickMenu(long windowId, String menuPath) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"found\":false,\"error\":\"Window not found\"}";
        }

        if (!(window instanceof JFrame)) {
            return "{\"found\":false,\"error\":\"Window is not a JFrame (no menu bar)\"}";
        }

        JMenuBar menuBar = ((JFrame) window).getJMenuBar();
        if (menuBar == null) {
            return "{\"found\":false,\"error\":\"No menu bar found\"}";
        }

        String[] parts = menuPath.split("/");
        if (parts.length == 0) {
            return "{\"found\":false,\"error\":\"Empty menu path\"}";
        }

        try {
            // Find the top-level menu
            JMenu topMenu = null;
            for (int i = 0; i < menuBar.getMenuCount(); i++) {
                JMenu menu = menuBar.getMenu(i);
                if (menu != null && menu.getText() != null &&
                    menu.getText().equalsIgnoreCase(parts[0].trim())) {
                    topMenu = menu;
                    break;
                }
            }

            if (topMenu == null) {
                return "{\"found\":false,\"error\":\"Menu not found: " + escapeJson(parts[0]) + "\"}";
            }

            // If only one path component, click the top-level menu
            if (parts.length == 1) {
                final JMenu menuToClick = topMenu;
                SwingUtilities.invokeAndWait(() -> menuToClick.doClick());
                return "{\"found\":true,\"clicked\":true}";
            }

            // Navigate sub-menus
            final JMenu finalTopMenu = topMenu;
            SwingUtilities.invokeAndWait(() -> finalTopMenu.doClick());
            Thread.sleep(IbctlAgent.agentTickMs); // Let menu open

            // Walk remaining path components
            javax.swing.MenuElement currentMenu = topMenu;
            for (int pathIdx = 1; pathIdx < parts.length; pathIdx++) {
                String target = parts[pathIdx].trim();
                boolean found = false;

                javax.swing.MenuElement[] subElements;
                if (currentMenu instanceof JMenu) {
                    subElements = ((JMenu) currentMenu).getMenuComponents().length > 0 ?
                        ((JMenu) currentMenu).getPopupMenu().getSubElements() :
                        new javax.swing.MenuElement[0];
                } else {
                    subElements = currentMenu.getSubElements();
                }

                for (javax.swing.MenuElement elem : subElements) {
                    if (elem instanceof JMenuItem) {
                        JMenuItem item = (JMenuItem) elem;
                        if (item.getText() != null && item.getText().equalsIgnoreCase(target)) {
                            if (pathIdx == parts.length - 1) {
                                // Last item — click it
                                final JMenuItem itemToClick = item;
                                SwingUtilities.invokeAndWait(() -> itemToClick.doClick());
                                return "{\"found\":true,\"clicked\":true,\"item\":" + jsonString(item.getText()) + "}";
                            } else if (item instanceof JMenu) {
                                // Intermediate menu — navigate into it
                                currentMenu = (JMenu) item;
                                found = true;
                                break;
                            }
                        }
                    }
                }

                if (!found && pathIdx < parts.length - 1) {
                    return "{\"found\":false,\"error\":\"Sub-menu not found: " + escapeJson(target) + "\"}";
                }
            }

            return "{\"found\":false,\"error\":\"Menu item not found at end of path\"}";
        } catch (InterruptedException | InvocationTargetException e) {
            return "{\"found\":true,\"clicked\":false,\"error\":" + jsonString(e.getMessage()) + "}";
        }
    }

    /**
     * Get or set a JCheckBox state by label text.
     * If setState is true, sets the checkbox. If false, clears it. If null, returns current state.
     * Mirrors IBC's pattern of finding checkboxes by label in config dialogs.
     */
    /**
     * Get or set a toggle-able button state by label text.
     * Searches ALL AbstractButton subclasses (JCheckBox, JToggleButton, and custom IB
     * components like the obfuscated 'r' class) since IB Gateway uses custom Swing
     * components that extend AbstractButton but are not standard JCheckBox.
     * Matches IBC's SwingUtils approach of searching all AbstractButton types.
     */
    public static String setCheckBox(long windowId, String label, Boolean desiredState) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"found\":false,\"error\":\"Window not found\"}";
        }

        // Search ALL AbstractButton subclasses — IB Gateway uses custom classes
        // like 'r' (extends JToggleButton or similar) for checkboxes
        List<AbstractButton> buttons = new ArrayList<>();
        collectComponents(window, AbstractButton.class, buttons);

        for (AbstractButton btn : buttons) {
            String text = btn.getText();
            if (text == null || text.isEmpty()) continue;

            // Match by exact text or case-insensitive startsWith
            if (text.equalsIgnoreCase(label) ||
                text.toLowerCase().startsWith(label.toLowerCase())) {
                // Read current state on the EDT for thread safety
                final AtomicReference<Boolean> stateRef = new AtomicReference<>(null);
                try {
                    SwingUtilities.invokeAndWait(() -> stateRef.set(btn.isSelected()));
                } catch (InterruptedException | InvocationTargetException e) {
                    return "{\"found\":true,\"error\":" + jsonString("Failed to read state: " + e.getMessage()) + "}";
                }
                boolean currentState = stateRef.get();

                if (desiredState == null) {
                    return "{\"found\":true,\"label\":" + jsonString(text) + ",\"selected\":" + currentState + ",\"class\":" + jsonString(btn.getClass().getSimpleName()) + "}";
                }
                if (currentState != desiredState) {
                    // Use invokeLater (not invokeAndWait) because doClick() may
                    // open a modal confirmation dialog that blocks the EDT.
                    SwingUtilities.invokeLater(() -> btn.doClick());
                    try { Thread.sleep(IbctlAgent.agentTickMs); } catch (InterruptedException ignored) {}
                }
                return "{\"found\":true,\"label\":" + jsonString(text) + ",\"selected\":" + desiredState + ",\"changed\":" + (currentState != desiredState) + ",\"class\":" + jsonString(btn.getClass().getSimpleName()) + "}";
            }
        }

        return "{\"found\":false,\"error\":\"Checkbox not found: " + escapeJson(label) + "\"}";
    }

    /**
     * Dump all interactive components in a window for diagnostics.
     * Lists all AbstractButtons, JCheckBoxes, JTextFields, JTree nodes with their
     * text, class, selected state, and visibility.
     */
    public static String dumpInteractiveComponents(long windowId) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"error\":\"Window not found\"}";
        }

        StringBuilder sb = new StringBuilder("{\"buttons\":[");
        List<AbstractButton> buttons = new ArrayList<>();
        collectComponents(window, AbstractButton.class, buttons);
        boolean first = true;
        for (AbstractButton b : buttons) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"class\":").append(jsonString(b.getClass().getName()));
            sb.append(",\"text\":").append(jsonString(b.getText()));
            sb.append(",\"visible\":").append(b.isVisible());
            sb.append(",\"enabled\":").append(b.isEnabled());
            sb.append(",\"selected\":").append(b.isSelected());
            sb.append(",\"type\":").append(jsonString(b.getClass().getSimpleName()));
            sb.append("}");
        }

        sb.append("],\"textfields\":[");
        List<JTextField> fields = new ArrayList<>();
        collectComponents(window, JTextField.class, fields);
        first = true;
        for (int i = 0; i < fields.size(); i++) {
            JTextField f = fields.get(i);
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"index\":").append(i);
            sb.append(",\"class\":").append(jsonString(f.getClass().getName()));
            sb.append(",\"text\":").append(jsonString(f.getText()));
            sb.append(",\"visible\":").append(f.isVisible());
            sb.append(",\"enabled\":").append(f.isEnabled());
            sb.append(",\"editable\":").append(f.isEditable());
            sb.append(",\"columns\":").append(f.getColumns());
            sb.append("}");
        }

        sb.append("],\"trees\":[");
        List<JTree> trees = new ArrayList<>();
        collectComponents(window, JTree.class, trees);
        first = true;
        for (JTree tree : trees) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"class\":").append(jsonString(tree.getClass().getName()));
            sb.append(",\"rowCount\":").append(tree.getRowCount());
            sb.append(",\"rows\":[");
            for (int row = 0; row < Math.min(tree.getRowCount(), 50); row++) {
                if (row > 0) sb.append(",");
                Object node = tree.getPathForRow(row);
                sb.append(jsonString(node != null ? node.toString() : "null"));
            }
            sb.append("]}");
        }

        // Labels (JLabel text — includes Connection Status fields)
        sb.append("],\"labels\":[");
        List<JLabel> labels = new ArrayList<>();
        collectComponents(window, JLabel.class, labels);
        first = true;
        for (JLabel l : labels) {
            String text = l.getText();
            if (text == null || text.isEmpty()) continue;
            if (!first) sb.append(",");
            first = false;
            sb.append(jsonString(text));
        }

        // Tables (JTable rows — Connection Status window uses this)
        sb.append("],\"tables\":[");
        List<JTable> tables = new ArrayList<>();
        collectComponents(window, JTable.class, tables);
        first = true;
        for (JTable table : tables) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"rows\":[");
            javax.swing.table.TableModel model = table.getModel();
            for (int row = 0; row < Math.min(model.getRowCount(), 20); row++) {
                if (row > 0) sb.append(",");
                sb.append("[");
                for (int col = 0; col < model.getColumnCount(); col++) {
                    if (col > 0) sb.append(",");
                    Object val = model.getValueAt(row, col);
                    sb.append(jsonString(val != null ? val.toString() : ""));
                }
                sb.append("]");
            }
            sb.append("]}");
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Select a tree node by path string in the first JTree in the window.
     * Path components separated by "/", e.g. "API" or "API/Settings".
     * Matches against tree node toString() values.
     */
    public static String selectTreeNode(long windowId, String nodePath) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"found\":false,\"error\":\"Window not found\"}";
        }

        List<JTree> trees = new ArrayList<>();
        collectComponents(window, JTree.class, trees);
        if (trees.isEmpty()) {
            return "{\"found\":false,\"error\":\"No JTree found in window\"}";
        }

        JTree tree = trees.get(0);
        String target = nodePath.trim();

        // Search tree rows for a path component matching the target
        for (int row = 0; row < tree.getRowCount(); row++) {
            javax.swing.tree.TreePath path = tree.getPathForRow(row);
            if (path == null) continue;

            // Check last component of the tree path
            Object lastComponent = path.getLastPathComponent();
            String nodeText = lastComponent != null ? lastComponent.toString() : "";

            if (nodeText.equalsIgnoreCase(target) ||
                nodeText.toLowerCase().contains(target.toLowerCase())) {
                final int selectedRow = row;
                final JTree finalTree = tree;
                try {
                    SwingUtilities.invokeAndWait(() -> {
                        finalTree.setSelectionRow(selectedRow);
                        finalTree.scrollRowToVisible(selectedRow);
                        // Fire selection to trigger the config panel to update
                        finalTree.expandRow(selectedRow);
                    });
                    return "{\"found\":true,\"row\":" + row + ",\"node\":" + jsonString(nodeText) + "}";
                } catch (InterruptedException | InvocationTargetException e) {
                    return "{\"found\":true,\"error\":" + jsonString(e.getMessage()) + "}";
                }
            }
        }

        return "{\"found\":false,\"error\":\"Tree node not found: " + escapeJson(target) + "\"}";
    }

    /**
     * Find a component by type and optional filter criteria. Returns JSON description.
     */
    public static String findComponent(long windowId, String type, String filter) {
        Window window = findWindowById(windowId);
        if (window == null) {
            return "{\"found\":false,\"error\":\"Window not found\"}";
        }

        List<Component> matches = new ArrayList<>();
        findComponentsByType(window, type, filter, matches);

        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Component c : matches) {
            if (!first) sb.append(",");
            first = false;
            sb.append(describeComponent(c));
        }
        sb.append("]");
        return sb.toString();
    }

    // --- Internal helpers ---

    static Window findWindowById(long id) {
        for (Window w : Window.getWindows()) {
            if (System.identityHashCode(w) == (int) id) {
                return w;
            }
        }
        return null;
    }

    private static String getWindowTitle(Window w) {
        if (w instanceof Frame) return ((Frame) w).getTitle();
        if (w instanceof Dialog) return ((Dialog) w).getTitle();
        return "";
    }

    static <T extends Component> void collectComponents(Container container, Class<T> type, List<T> result) {
        for (Component c : container.getComponents()) {
            if (type.isInstance(c)) {
                result.add(type.cast(c));
            }
            if (c instanceof Container) {
                collectComponents((Container) c, type, result);
            }
        }
    }

    private static void findComponentsByType(Container container, String type, String filter, List<Component> result) {
        for (Component c : container.getComponents()) {
            String className = c.getClass().getSimpleName().toLowerCase();
            if (className.contains(type.toLowerCase())) {
                if (filter == null || filter.isEmpty() || matchesFilter(c, filter)) {
                    result.add(c);
                }
            }
            if (c instanceof Container) {
                findComponentsByType((Container) c, type, filter, result);
            }
        }
    }

    private static boolean matchesFilter(Component c, String filter) {
        if (c instanceof AbstractButton) {
            String text = ((AbstractButton) c).getText();
            return text != null && text.contains(filter);
        }
        if (c instanceof JLabel) {
            String text = ((JLabel) c).getText();
            return text != null && text.contains(filter);
        }
        if (c instanceof JTextField) {
            String text = ((JTextField) c).getText();
            return text != null && text.contains(filter);
        }
        return false;
    }

    private static String componentToJson(Component c, int depth) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"class\":").append(jsonString(c.getClass().getName()));
        sb.append(",\"id\":").append(System.identityHashCode(c));
        sb.append(",\"visible\":").append(c.isVisible());
        sb.append(",\"enabled\":").append(c.isEnabled());

        Rectangle bounds = c.getBounds();
        sb.append(",\"bounds\":{");
        sb.append("\"x\":").append(bounds.x);
        sb.append(",\"y\":").append(bounds.y);
        sb.append(",\"width\":").append(bounds.width);
        sb.append(",\"height\":").append(bounds.height);
        sb.append("}");

        if (c instanceof AbstractButton) {
            sb.append(",\"text\":").append(jsonString(((AbstractButton) c).getText()));
        } else if (c instanceof JLabel) {
            sb.append(",\"text\":").append(jsonString(((JLabel) c).getText()));
        } else if (c instanceof JTextField) {
            sb.append(",\"text\":").append(jsonString(((JTextField) c).getText()));
        }

        if (c instanceof Window) {
            sb.append(",\"title\":").append(jsonString(getWindowTitle((Window) c)));
        }

        if (c instanceof Container) {
            Component[] children = ((Container) c).getComponents();
            if (children.length > 0) {
                sb.append(",\"children\":[");
                boolean first = true;
                for (Component child : children) {
                    if (!first) sb.append(",");
                    first = false;
                    sb.append(componentToJson(child, depth + 1));
                }
                sb.append("]");
            }
        }

        sb.append("}");
        return sb.toString();
    }

    private static String describeComponent(Component c) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"class\":").append(jsonString(c.getClass().getName()));
        sb.append(",\"id\":").append(System.identityHashCode(c));
        sb.append(",\"visible\":").append(c.isVisible());
        sb.append(",\"enabled\":").append(c.isEnabled());

        Rectangle bounds = c.getBounds();
        sb.append(",\"bounds\":{");
        sb.append("\"x\":").append(bounds.x);
        sb.append(",\"y\":").append(bounds.y);
        sb.append(",\"width\":").append(bounds.width);
        sb.append(",\"height\":").append(bounds.height);
        sb.append("}");

        if (c instanceof AbstractButton) {
            sb.append(",\"text\":").append(jsonString(((AbstractButton) c).getText()));
        } else if (c instanceof JLabel) {
            sb.append(",\"text\":").append(jsonString(((JLabel) c).getText()));
        } else if (c instanceof JTextField) {
            sb.append(",\"text\":").append(jsonString(((JTextField) c).getText()));
        }

        sb.append("}");
        return sb.toString();
    }

    static String jsonString(String value) {
        if (value == null) return "null";
        return "\"" + escapeJson(value) + "\"";
    }

    static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.toString();
    }
}
