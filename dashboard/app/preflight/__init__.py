"""Pre-flight config validation for ibctl.

Validates TOML config + environment variable overrides against Pydantic models
before ibctl starts. Catches misconfigurations early with clear error messages.
"""
