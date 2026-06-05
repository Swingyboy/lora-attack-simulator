"""
Enhanced logging subsystem for LoRaWAN Attack Simulator.

Provides:
- TRACE log level support
- Dual output (terminal + session log file)
- Structured JSONL logging
- Colored terminal output
- Secret masking
- Runtime reconfiguration

# Logging Precedence

The logging system enforces explicit precedence rules to prevent
configuration confusion. When multiple sources try to set the log level,
the highest-precedence source wins.

## Precedence Order (Highest to Lowest)

1. **CLI Overrides** (`cli_override`)
   - Set via `set logging.level <LEVEL>` command
   - Always wins over scenario/framework defaults
   - Persists for entire session

2. **Scenario Configuration** (`scenario`)
   - Set via scenario JSON `logging.level` field
   - Applies when scenario is loaded
   - Can be overridden by CLI

3. **Framework Defaults** (`framework_default`)
   - Initial INFO level at shell startup
   - Lowest precedence
   - Overridden by scenario or CLI

## Usage Patterns

### Shell Initialization
```python
from lora_attack_toolkit.logging.logging import configure_logging

# Framework default (precedence: 0)
configure_logging(level=\"INFO\")  # Uses source=\"framework_default\"
```

### CLI Runtime Override
```python
from lora_attack_toolkit.logging.logging import reconfigure_level

# CLI override (precedence: 2 - highest)
reconfigure_level(\"DEBUG\", source=\"cli_override\")
```

### Scenario Loading (Future)
```python
# Scenario config (precedence: 1)
configure_logging(level=\"TRACE\", source=\"scenario\")
```

## Precedence Enforcement

The `LoggingConfig.set_level()` method enforces precedence:

- Higher/equal precedence: Level is changed
- Lower precedence: Change is blocked, current level retained

Example:
```python
config.set_level(\"INFO\", \"scenario\")      # Applies (precedence: 1)
config.set_level(\"DEBUG\", \"cli_override\") # Applies (precedence: 2, higher)
config.set_level(\"ERROR\", \"scenario\")     # BLOCKED (precedence: 1, lower than current)
config.set_level(\"TRACE\", \"cli_override\") # Applies (precedence: 2, equal to current)
```

## Log Levels

- **ERROR**: Errors that prevent operation (join failures, crypto errors)
- **WARNING**: Unexpected but recoverable (timeouts, retries)
- **INFO**: High-level operations (join success, attack phases)
- **DEBUG**: Detailed execution (packet building, state transitions)
- **TRACE**: Protocol-level details (PHY payloads, Semtech UDP packets)

## Handler Configuration

### Console Handler
- Colored output for readability
- Format: `[HH:MM:SS] [LEVEL] logger - message`
- Secret masking enabled by default

### File Handler
- JSONL format for structured logs
- Location: `logs/session-<timestamp>.log`
- Fields: timestamp, level, logger, message, session_id, scenario_id, extras

## Runtime Reconfiguration

Log level can be changed at runtime without recreating handlers:

```python
reconfigure_level(\"DEBUG\")  # Changes level, respects precedence
```

Handler clearing on reconfiguration prevents duplication:
- `logger.handlers.clear()` removes old handlers
- New handlers added (console + file)
- No handler leaks

## Secret Masking

Automatically masks hex keys in logs:
- 32+ hex character strings → masked
- Example: `00112233...` → `0011****`
- Disabled via `mask_secrets=False` (logs warning)

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
        
        # Format timestamp (HH:MM:SS)
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        
        # Format: [HH:MM:SS] [LEVEL] logger - message
        return f"[{timestamp}] {color}[{record.levelname}]{reset} {record.name} - {message}"


class LoggingConfig:
    """
    Global logging configuration state with explicit precedence.
    
    Logging Precedence (highest to lowest):
    1. CLI/Session overrides (set logging.level commands)
    2. Scenario configuration (logging section in scenario JSON)
    3. Framework defaults (INFO level, colored output, secret masking)
    """
    
    def __init__(self) -> None:
        self.level: str = "INFO"
        self.session_log_file: Path | None = None
        self.session_id: str | None = None
        self.scenario_id: str | None = None
        self.mask_secrets: bool = True
        self.use_colors: bool = True
        self.log_phy_payload: bool = False
        self.log_semtech_udp: bool = False
        
        # Track source of current log level for precedence
        self.level_source: str = "framework_default"  # "framework_default" | "scenario" | "cli_override"
    
    def set_level(self, level: str, source: str = "framework_default") -> bool:
        """
        Set log level with precedence checking.
        
        Args:
            level: New log level
            source: Source of the change (framework_default, scenario, cli_override)
        
        Returns:
            True if level was changed, False if blocked by precedence
        
        Precedence order:
            cli_override (2) > scenario (1) > framework_default (0)
        """
        precedence = {"framework_default": 0, "scenario": 1, "cli_override": 2}
        
        current_precedence = precedence.get(self.level_source, 0)
        new_precedence = precedence.get(source, 0)
        
        # Only apply if new source has higher or equal precedence
        if new_precedence >= current_precedence:
            self.level = level.upper()
            self.level_source = source
            return True
        return False
    
    def to_dict(self) -> dict[str, Any]:
        """Export config as dict."""
        return {
            "level": self.level,
            "level_source": self.level_source,
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
    
    # Set level with precedence (defaults to framework_default source)
    _logging_config.set_level(level, source="framework_default")
    
    # Update other config (no precedence needed for these)
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
    logger = logging.getLogger("lora_attack_toolkit")
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


def reconfigure_level(level: str, source: str = "cli_override") -> None:
    """
    Reconfigure log level at runtime with precedence awareness.
    
    Args:
        level: New log level (ERROR, WARNING, INFO, DEBUG, TRACE)
        source: Source of change (cli_override by default, scenario for scenario-driven changes)
    
    Note:
        Respects logging precedence. CLI overrides always win over scenario config.
    """
    global _logging_config
    
    # Try to set level with precedence check
    changed = _logging_config.set_level(level, source)
    
    if changed:
        # Update logger level
        logger = logging.getLogger("lora_attack_toolkit")
        logger.setLevel(getattr(logging, _logging_config.level, logging.INFO))
        logger.info(f"Log level changed to: {_logging_config.level} (source: {source})")
    else:
        logger = logging.getLogger("lora_attack_toolkit")
        logger.debug(f"Log level change to {level} blocked by precedence (current source: {_logging_config.level_source})")


def set_scenario_context(scenario_id: str | None) -> None:
    """Update scenario context for logging."""
    global _logging_config
    _logging_config.scenario_id = scenario_id
    
    # Update formatters
    logger = logging.getLogger("lora_attack_toolkit")
    for handler in logger.handlers:
        if isinstance(handler.formatter, JsonFormatter):
            handler.formatter.scenario_id = scenario_id
