"""
Enhanced logging subsystem for LoRaWAN Attack Simulator.

Provides:
- TRACE log level support
- Dual output (terminal + session log file)
- Structured JSONL logging
- Colored terminal output
- Secret masking
- Runtime reconfiguration
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Define TRACE log level (below DEBUG)
TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def trace(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    """Log a message with TRACE level."""
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)


# Add trace() method to Logger class
logging.Logger.trace = trace  # type: ignore


# ANSI color codes for terminal output
COLORS = {
    "RESET": "\033[0m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "DIM": "\033[2m",
    "BOLD": "\033[1m",
}

LEVEL_COLORS = {
    "ERROR": COLORS["RED"],
    "WARNING": COLORS["YELLOW"],
    "INFO": COLORS["RESET"],
    "DEBUG": COLORS["CYAN"],
    "TRACE": COLORS["DIM"],
}


class SecretMasker:
    """Mask sensitive data in log messages."""
    
    # Patterns for secret keys (hex strings of specific lengths)
    SECRET_PATTERNS = [
        (r'\b([0-9a-fA-F]{32})\b', 'app_key'),  # 16-byte hex (AppKey, NwkKey)
        (r'\b([0-9a-fA-F]{64})\b', 'root_key'),  # 32-byte hex
        (r'(app_key|nwk_key|app_s_key|nwk_s_key|app_session_key|network_session_key)["\']?\s*[:=]\s*["\']?([0-9a-fA-F]+)', 'key_value'),
    ]
    
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
    
    def mask(self, text: str) -> str:
        """Mask secrets in text."""
        if not self.enabled:
            return text
        
        # Mask 32-char hex strings (16-byte keys like AppKey)
        text = re.sub(
            r'\b([0-9a-fA-F]{8})([0-9a-fA-F]{16})([0-9a-fA-F]{8})\b',
            r'\1********\3',
            text
        )
        
        # Mask key=value patterns
        text = re.sub(
            r'(app_key|nwk_key|app_s_key|nwk_s_key|app_session_key|network_session_key)(["\']?\s*[:=]\s*["\']?)([0-9a-fA-F]{8})([0-9a-fA-F]+)',
            r'\1\2\3********',
            text,
            flags=re.IGNORECASE
        )
        
        return text


class JsonFormatter(logging.Formatter):
    """Structured JSONL formatter with optional secret masking."""
    
    def __init__(
        self,
        session_id: str | None = None,
        scenario_id: str | None = None,
        mask_secrets: bool = True,
    ) -> None:
        super().__init__()
        self.session_id = session_id
        self.scenario_id = scenario_id
        self.masker = SecretMasker(enabled=mask_secrets)
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSONL."""
        message = record.getMessage()
        
        # Mask secrets if enabled
        message = self.masker.mask(message)
        
        payload: dict[str, Any] = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        
        # Add session and scenario context
        if self.session_id:
            payload["session_id"] = self.session_id
        if self.scenario_id:
            payload["scenario_id"] = self.scenario_id
        
        # Add extra fields from record
        if hasattr(record, "scenario_id") and not self.scenario_id:
            payload["scenario_id"] = record.scenario_id
        if hasattr(record, "component"):
            payload["component"] = record.component
        
        return json.dumps(payload, separators=(",", ":"))


class ColoredConsoleFormatter(logging.Formatter):
    """Terminal formatter with color support and secret masking."""
    
    def __init__(
        self,
        use_colors: bool = True,
        mask_secrets: bool = True,
    ) -> None:
        super().__init__()
        self.use_colors = use_colors and sys.stdout.isatty()
        self.masker = SecretMasker(enabled=mask_secrets)
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record for terminal with colors."""
        message = record.getMessage()
        
        # Mask secrets if enabled
        message = self.masker.mask(message)
        
        # Get color for level
        color = LEVEL_COLORS.get(record.levelname, COLORS["RESET"]) if self.use_colors else ""
        reset = COLORS["RESET"] if self.use_colors else ""
        
        # Format: [LEVEL] logger - message
        return f"{color}[{record.levelname}]{reset} {record.name} - {message}"


class LoggingConfig:
    """Global logging configuration state."""
    
    def __init__(self) -> None:
        self.level: str = "INFO"
        self.session_log_file: Path | None = None
        self.session_id: str | None = None
        self.scenario_id: str | None = None
        self.mask_secrets: bool = True
        self.use_colors: bool = True
        self.log_phy_payload: bool = False
        self.log_semtech_udp: bool = False
    
    def to_dict(self) -> dict[str, Any]:
        """Export config as dict."""
        return {
            "level": self.level,
            "session_log_file": str(self.session_log_file) if self.session_log_file else None,
            "session_id": self.session_id,
            "scenario_id": self.scenario_id,
            "mask_secrets": self.mask_secrets,
            "use_colors": self.use_colors,
            "log_phy_payload": self.log_phy_payload,
            "log_semtech_udp": self.log_semtech_udp,
        }


# Global logging configuration
_logging_config = LoggingConfig()


def get_logging_config() -> LoggingConfig:
    """Get global logging configuration."""
    return _logging_config


def configure_logging(
    level: str = "INFO",
    log_file: str | Path | None = None,
    session_id: str | None = None,
    scenario_id: str | None = None,
    mask_secrets: bool = True,
    use_colors: bool = True,
    log_phy_payload: bool = False,
    log_semtech_udp: bool = False,
) -> None:
    """
    Configure logging with dual output (terminal + file).
    
    Args:
        level: Log level (ERROR, WARNING, INFO, DEBUG, TRACE)
        log_file: Path to session log file (auto-created if None)
        session_id: Session identifier for log context
        scenario_id: Scenario identifier for log context
        mask_secrets: Mask secrets in logs (default True)
        use_colors: Use colored terminal output (default True)
        log_phy_payload: Enable PHY payload logging
        log_semtech_udp: Enable Semtech UDP packet logging
    """
    global _logging_config
    
    # Update global config
    _logging_config.level = level.upper()
    _logging_config.session_id = session_id
    _logging_config.scenario_id = scenario_id
    _logging_config.mask_secrets = mask_secrets
    _logging_config.use_colors = use_colors
    _logging_config.log_phy_payload = log_phy_payload
    _logging_config.log_semtech_udp = log_semtech_udp
    
    # Create session log file if not provided
    if log_file is None:
        logs_dir = Path.cwd() / "logs"
        logs_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = logs_dir / f"session-{timestamp}.log"
    else:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
    
    _logging_config.session_log_file = log_file
    
    # Configure root logger
    logger = logging.getLogger("lorawan_sim")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    
    # Console handler (colored, human-readable)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredConsoleFormatter(
        use_colors=use_colors,
        mask_secrets=mask_secrets,
    ))
    logger.addHandler(console_handler)
    
    # File handler (JSONL, structured)
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setFormatter(JsonFormatter(
        session_id=session_id,
        scenario_id=scenario_id,
        mask_secrets=mask_secrets,
    ))
    logger.addHandler(file_handler)
    
    # Log configuration
    logger.info(f"Logging configured: level={level}, file={log_file}")
    if not mask_secrets:
        logger.warning("Secret masking disabled - sensitive data will appear in logs")


def reconfigure_level(level: str) -> None:
    """Reconfigure log level at runtime."""
    global _logging_config
    _logging_config.level = level.upper()
    
    logger = logging.getLogger("lorawan_sim")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.info(f"Log level changed to: {level.upper()}")


def set_scenario_context(scenario_id: str | None) -> None:
    """Update scenario context for logging."""
    global _logging_config
    _logging_config.scenario_id = scenario_id
    
    # Update formatters
    logger = logging.getLogger("lorawan_sim")
    for handler in logger.handlers:
        if isinstance(handler.formatter, JsonFormatter):
            handler.formatter.scenario_id = scenario_id
