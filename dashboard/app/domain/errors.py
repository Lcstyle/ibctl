"""Exception hierarchy for the ibctl dashboard.

Follows exception handling best practices:
- Data-carrying exceptions (not just messages)
- Exception translation at boundaries
- Fail fast with meaningful errors
"""


class DashboardError(Exception):
    """Base exception for all dashboard errors."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class IbctlConnectionError(DashboardError):
    """Failed to connect to ibctl's TCP command server."""

    def __init__(self, host: str, port: int, cause: str):
        self.host = host
        self.port = port
        self.cause = cause
        super().__init__(f"Cannot connect to ibctl at {host}:{port}: {cause}")


class IbctlCommandError(DashboardError):
    """ibctl returned an error response to a command."""

    def __init__(self, command: str, error: str):
        self.command = command
        self.error = error
        super().__init__(f"Command '{command}' failed: {error}")


class IbctlTimeoutError(DashboardError):
    """Timed out waiting for ibctl response."""

    def __init__(self, command: str, timeout_secs: float):
        self.command = command
        self.timeout_secs = timeout_secs
        super().__init__(f"Timeout after {timeout_secs}s waiting for '{command}' response")
