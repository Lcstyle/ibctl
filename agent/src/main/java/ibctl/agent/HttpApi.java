package ibctl.agent;

import java.io.*;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Minimal HTTP/1.1 server over Unix domain socket using JDK 17 built-in APIs.
 * No external dependencies. Implements just enough HTTP to serve JSON API responses.
 */
public class HttpApi {

    /**
     * Start the HTTP server listening on the given Unix domain socket path.
     * This method blocks indefinitely, accepting connections in a loop.
     */
    public static void start(String socketPath) throws IOException {
        Path path = Path.of(socketPath);
        // Remove stale socket file if it exists
        Files.deleteIfExists(path);

        UnixDomainSocketAddress address = UnixDomainSocketAddress.of(path);
        ServerSocketChannel serverChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        serverChannel.bind(address);

        System.out.println("[ibctl-agent] HTTP server listening on " + socketPath);

        while (true) {
            try {
                SocketChannel client = serverChannel.accept();
                handleClient(client);
            } catch (Exception e) {
                System.err.println("[ibctl-agent] Error handling client: " + e.getMessage());
            }
        }
    }

    private static void handleClient(SocketChannel client) {
        try {
            // Read the full request
            ByteBuffer buf = ByteBuffer.allocate(8192);
            StringBuilder requestBuilder = new StringBuilder();
            int bytesRead;

            // Read until we have the complete headers (terminated by \r\n\r\n)
            while ((bytesRead = client.read(buf)) > 0) {
                buf.flip();
                byte[] bytes = new byte[buf.remaining()];
                buf.get(bytes);
                requestBuilder.append(new String(bytes, StandardCharsets.UTF_8));
                buf.clear();

                if (requestBuilder.toString().contains("\r\n\r\n")) {
                    break;
                }
            }

            String request = requestBuilder.toString();
            if (request.isEmpty()) {
                client.close();
                return;
            }

            // Parse request line
            String[] lines = request.split("\r\n");
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
            Map<String, String> headers = new HashMap<>();
            int headerEnd = 0;
            for (int i = 1; i < lines.length; i++) {
                if (lines[i].isEmpty()) {
                    headerEnd = i;
                    break;
                }
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
                // Extract body from what we already read
                int headerEndPos = request.indexOf("\r\n\r\n");
                if (headerEndPos >= 0) {
                    String partialBody = request.substring(headerEndPos + 4);
                    StringBuilder bodyBuilder = new StringBuilder(partialBody);

                    // Read remaining body bytes if needed
                    while (bodyBuilder.length() < contentLength) {
                        buf.clear();
                        bytesRead = client.read(buf);
                        if (bytesRead <= 0) break;
                        buf.flip();
                        byte[] bytes = new byte[buf.remaining()];
                        buf.get(bytes);
                        bodyBuilder.append(new String(bytes, StandardCharsets.UTF_8));
                    }
                    body = bodyBuilder.toString();
                    if (body.length() > contentLength) {
                        body = body.substring(0, contentLength);
                    }
                }
            }

            // Route the request
            String response = route(method, path, body);
            sendResponse(client, 200, response);

        } catch (Exception e) {
            try {
                String errorJson = "{\"ok\":false,\"error\":" + SwingInspector.jsonString(e.getMessage()) + "}";
                sendResponse(client, 500, errorJson);
            } catch (IOException ignored) {
            }
        } finally {
            try {
                client.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static String route(String method, String path, String body) {
        // GET /health
        if ("GET".equals(method) && "/health".equals(path)) {
            return wrapOk("{\"status\":\"running\"}");
        }

        // GET /windows
        if ("GET".equals(method) && "/windows".equals(path)) {
            return wrapOk(SwingInspector.listWindows());
        }

        // Routes with window ID: /windows/{id}/...
        if (path.startsWith("/windows/")) {
            String remainder = path.substring("/windows/".length());
            int slashIdx = remainder.indexOf('/');

            long windowId;
            String subPath;
            if (slashIdx < 0) {
                // Just /windows/{id} -- shouldn't happen but handle gracefully
                return wrapError("Missing sub-path");
            }

            try {
                windowId = Long.parseLong(remainder.substring(0, slashIdx));
            } catch (NumberFormatException e) {
                return wrapError("Invalid window ID");
            }
            subPath = remainder.substring(slashIdx);

            // GET /windows/{id}/components
            if ("GET".equals(method) && "/components".equals(subPath)) {
                String tree = SwingInspector.getComponentTree(windowId);
                return wrapOk(tree);
            }

            // POST /windows/{id}/find
            if ("POST".equals(method) && "/find".equals(subPath)) {
                String type = extractJsonField(body, "type");
                String filter = extractJsonField(body, "filter");
                String result = SwingInspector.findComponent(windowId, type != null ? type : "", filter);
                return wrapOk(result);
            }

            // POST /windows/{id}/click
            if ("POST".equals(method) && "/click".equals(subPath)) {
                String label = extractJsonField(body, "label");
                if (label == null) return wrapError("Missing 'label' field");
                String result = SwingInspector.clickButton(windowId, label);
                return wrapOk(result);
            }

            // POST /windows/{id}/type
            if ("POST".equals(method) && "/type".equals(subPath)) {
                String fieldIndexStr = extractJsonField(body, "fieldIndex");
                String text = extractJsonField(body, "text");
                if (fieldIndexStr == null) return wrapError("Missing 'fieldIndex' field");
                if (text == null) return wrapError("Missing 'text' field");
                int fieldIndex;
                try {
                    fieldIndex = Integer.parseInt(fieldIndexStr);
                } catch (NumberFormatException e) {
                    return wrapError("Invalid fieldIndex");
                }
                String result = SwingInspector.typeText(windowId, fieldIndex, text);
                return wrapOk(result);
            }

            // POST /windows/{id}/key
            if ("POST".equals(method) && "/key".equals(subPath)) {
                String key = extractJsonField(body, "key");
                if (key == null) return wrapError("Missing 'key' field");
                String result = SwingInspector.sendKey(windowId, key);
                return wrapOk(result);
            }

            // POST /windows/{id}/menu — navigate and click a menu item by path
            if ("POST".equals(method) && "/menu".equals(subPath)) {
                String menuPath = extractJsonField(body, "path");
                if (menuPath == null) return wrapError("Missing 'path' field");
                String result = SwingInspector.clickMenu(windowId, menuPath);
                return wrapOk(result);
            }

            // GET /windows/{id}/tabs — list JTabbedPane tab titles (client IDs)
            if ("GET".equals(method) && "/tabs".equals(subPath)) {
                String result = SwingInspector.listTabs(windowId);
                return wrapOk(result);
            }

            // GET /windows/{id}/clients — rich client-state metadata
            // (API Client row status + JTabbedPane tab list)
            if ("GET".equals(method) && "/clients".equals(subPath)) {
                String result = SwingInspector.listClients(windowId);
                return wrapOk(result);
            }

            // POST /windows/{id}/selectlist — select an item in a JList by text
            if ("POST".equals(method) && "/selectlist".equals(subPath)) {
                String item = extractJsonField(body, "item");
                if (item == null) return wrapError("Missing 'item' field");
                String result = SwingInspector.selectListItem(windowId, item);
                return wrapOk(result);
            }

            // POST /windows/{id}/clickat — click at x,y coordinates relative to window
            if ("POST".equals(method) && "/clickat".equals(subPath)) {
                String xStr = extractJsonField(body, "x");
                String yStr = extractJsonField(body, "y");
                if (xStr == null || yStr == null) return wrapError("Missing 'x' or 'y' field");
                try {
                    int x = Integer.parseInt(xStr);
                    int y = Integer.parseInt(yStr);
                    String result = SwingInspector.clickAt(windowId, x, y);
                    return wrapOk(result);
                } catch (NumberFormatException e) {
                    return wrapError("Invalid x/y coordinates");
                }
            }

            // POST /windows/{id}/tree — select a tree node by name
            if ("POST".equals(method) && "/tree".equals(subPath)) {
                String node = extractJsonField(body, "node");
                if (node == null) return wrapError("Missing 'node' field");
                String result = SwingInspector.selectTreeNode(windowId, node);
                return wrapOk(result);
            }

            // GET /windows/{id}/dump — dump all interactive components for diagnostics
            if ("GET".equals(method) && "/dump".equals(subPath)) {
                String result = SwingInspector.dumpInteractiveComponents(windowId);
                return wrapOk(result);
            }

            // POST /windows/{id}/checkbox — get or set a checkbox by label
            if ("POST".equals(method) && "/checkbox".equals(subPath)) {
                String label = extractJsonField(body, "label");
                if (label == null) return wrapError("Missing 'label' field");
                String stateStr = extractJsonField(body, "state");
                Boolean desiredState = stateStr != null ? Boolean.parseBoolean(stateStr) : null;
                String result = SwingInspector.setCheckBox(windowId, label, desiredState);
                return wrapOk(result);
            }

            return wrapError("Unknown endpoint: " + path);
        }

        return wrapError("Not found: " + method + " " + path);
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
        while (headerBuf.hasRemaining()) {
            client.write(headerBuf);
        }

        ByteBuffer bodyBuf = ByteBuffer.wrap(bodyBytes);
        while (bodyBuf.hasRemaining()) {
            client.write(bodyBuf);
        }
    }

    private static String wrapOk(String data) {
        return "{\"ok\":true,\"data\":" + data + ",\"error\":null}";
    }

    private static String wrapError(String message) {
        return "{\"ok\":false,\"data\":null,\"error\":" + SwingInspector.jsonString(message) + "}";
    }

    /**
     * Minimal JSON field extractor. Finds a string value for a given key.
     * Only handles simple flat JSON objects with string values.
     * This avoids pulling in any JSON library.
     */
    /**
     * Decode a JSON string body (the bytes between the surrounding quotes)
     * according to the standard JSON escape sequences: backslash-quote,
     * backslash-backslash, backslash-slash, backslash-b, backslash-f,
     * backslash-n, backslash-r, backslash-t, and backslash-u four-hex.
     * Unrecognized escapes are passed through as their second character
     * (mirrors the "be liberal in what you accept" side of Postel).
     *
     * Note: this javadoc deliberately avoids the literal backslash-u
     * sequence — javac processes those escapes even inside comments.
     */
    static String decodeJsonString(String json, int start, int end) {
        StringBuilder sb = new StringBuilder(end - start);
        int i = start;
        while (i < end) {
            char c = json.charAt(i);
            if (c != '\\' || i + 1 >= end) {
                sb.append(c);
                i++;
                continue;
            }
            char esc = json.charAt(i + 1);
            switch (esc) {
                case '"':  sb.append('"'); i += 2; break;
                case '\\': sb.append('\\'); i += 2; break;
                case '/':  sb.append('/'); i += 2; break;
                case 'b':  sb.append('\b'); i += 2; break;
                case 'f':  sb.append('\f'); i += 2; break;
                case 'n':  sb.append('\n'); i += 2; break;
                case 'r':  sb.append('\r'); i += 2; break;
                case 't':  sb.append('\t'); i += 2; break;
                case 'u':
                    if (i + 6 <= end) {
                        try {
                            int cp = Integer.parseInt(json.substring(i + 2, i + 6), 16);
                            sb.append((char) cp);
                            i += 6;
                            break;
                        } catch (NumberFormatException ignored) {
                            // Fall through to permissive path
                        }
                    }
                    sb.append(esc);
                    i += 2;
                    break;
                default:
                    sb.append(esc);
                    i += 2;
                    break;
            }
        }
        return sb.toString();
    }

    static String extractJsonField(String json, String field) {
        if (json == null || json.isEmpty()) return null;

        String key = "\"" + field + "\"";
        int keyIdx = json.indexOf(key);
        if (keyIdx < 0) return null;

        int colonIdx = json.indexOf(':', keyIdx + key.length());
        if (colonIdx < 0) return null;

        // Skip whitespace after colon
        int valueStart = colonIdx + 1;
        while (valueStart < json.length() && json.charAt(valueStart) == ' ') {
            valueStart++;
        }

        if (valueStart >= json.length()) return null;

        char firstChar = json.charAt(valueStart);

        // Handle string values.
        //
        // Two passes: first walk the raw JSON to find where the string
        // ends (respecting backslash escapes so a `\"` inside the value
        // doesn't terminate the scan). Then decode the JSON escape
        // sequences on the way out — returning the raw substring would
        // leave backslashes in the value, which is exactly the bug that
        // made Lcstyle/ibctl#4 look like a Unicode drift issue: Rust
        // sends `{"label":"Bypass \"same action pair trade\" …"}`, the
        // scanner correctly finds the boundaries, but the returned
        // string still contains backslashes, so setCheckBox compared
        // `Bypass \"same…` to Gateway's `Bypass "same…` and always missed.
        if (firstChar == '"') {
            int strStart = valueStart + 1;
            int strEnd = strStart;
            while (strEnd < json.length()) {
                char c = json.charAt(strEnd);
                if (c == '\\') {
                    strEnd += 2; // skip escaped char
                } else if (c == '"') {
                    break;
                } else {
                    strEnd++;
                }
            }
            return decodeJsonString(json, strStart, strEnd);
        }

        // Handle numeric values
        if (Character.isDigit(firstChar) || firstChar == '-') {
            int numEnd = valueStart;
            while (numEnd < json.length() && (Character.isDigit(json.charAt(numEnd)) || json.charAt(numEnd) == '-' || json.charAt(numEnd) == '.')) {
                numEnd++;
            }
            return json.substring(valueStart, numEnd);
        }

        // Handle null
        if (json.startsWith("null", valueStart)) {
            return null;
        }

        return null;
    }
}
