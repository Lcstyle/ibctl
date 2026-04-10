package ibctl.agent;

import java.lang.instrument.Instrumentation;

public class IbctlAgent {
    private static String socketPath = "/tmp/ibctl.sock";
    /** Agent-side delay after each UI action (ms). Configurable via IBCTL_AGENT_TICK_MS env var. */
    public static int agentTickMs = 50;

    public static void premain(String agentArgs, Instrumentation inst) {
        if (agentArgs != null && !agentArgs.isEmpty()) {
            socketPath = agentArgs;
        }
        // Read agent tick from env var (set by ibctl from timing.agent_tick_ms config)
        String tickEnv = System.getenv("IBCTL_AGENT_TICK_MS");
        if (tickEnv != null) {
            try {
                agentTickMs = Integer.parseInt(tickEnv.trim());
            } catch (NumberFormatException ignored) {}
        }

        // Install AWT window monitor before starting server
        WindowMonitor.install();

        // Start multiplexed server — single socket handles both HTTP and event streams
        Thread serverThread = new Thread(() -> {
            try {
                MultiplexedServer.start(socketPath);
            } catch (Exception e) {
                System.err.println("[ibctl-agent] Failed to start server: " + e.getMessage());
            }
        });
        serverThread.setDaemon(true);
        serverThread.setName("ibctl-agent-server");
        serverThread.start();

        System.out.println("[ibctl-agent] Agent initialized, listening on " + socketPath);
        System.out.println("[ibctl-agent] Protocol v2: HTTP + SUBSCRIBE on single socket");
    }

    public static String getSocketPath() {
        return socketPath;
    }
}
