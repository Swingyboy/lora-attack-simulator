"""
Interactive console for LoRaWAN attack simulator.

Provides Metasploit-like workflow for scenario management.
Uses cmd2 for autocomplete, help, and history.

Startup (session creation, logging setup, bootstrap) is handled by
main.py before constructing this console.
"""

from __future__ import annotations

import json
import logging
import signal
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cmd2

from lora_attack_toolkit.runtime.session import Session


@dataclass
class ScenarioMetadata:
    """Metadata extracted from a scenario file, enriched from the attack registry."""

    name: str
    path: Path
    title: str
    description: str
    category: str
    scenario_type: str

    @classmethod
    def from_file(cls, path: Path) -> ScenarioMetadata | None:
        """Extract metadata from scenario JSON file, resolving title/category from registry."""
        try:
            with open(path, "r") as f:
                data = json.load(f)

            scenario = data.get("scenario", {})
            attack_type = data.get("attack", {}).get("type", "")
            description = scenario.get("description", "No description")

            # Resolve title and category from the attack registry when available.
            title = path.stem
            category = "unknown"
            if attack_type:
                try:
                    from lora_attack_toolkit.attacks.registry import AttackRegistry

                    spec = AttackRegistry.get_spec(attack_type)
                    title = spec.title or attack_type
                    category = spec.category or attack_type
                except (ValueError, ImportError):
                    title = attack_type
                    category = attack_type

            return cls(
                name=path.stem,
                path=path,
                title=title,
                description=description,
                category=category,
                scenario_type=attack_type,
            )
        except (json.JSONDecodeError, IOError):
            return None


class LoRaWANConsole(cmd2.Cmd):
    """Interactive console for LoRaWAN offensive security testing."""

    intro = """
╔════════════════════════════════════════════════════════════════╗
║  LoRAT (LoRa Attack Toolkit) v0.2.0                           ║
║  Offensive Security Testing for LoRaWAN Network Servers       ║
║  Transport: Semtech UDP                                        ║
║                                                                ║
║  Type 'help' for available commands                           ║
║  Type 'show scenarios' to list available attack scenarios     ║
╚════════════════════════════════════════════════════════════════╝
"""

    prompt = "lorat > "

    # Disable built-in cmd2 commands that we don't want
    # (shortcuts confuse users; keep only our own)

    def __init__(self, session: Session | None = None, *args: Any, **kwargs: Any) -> None:
        """Initialize the console.

        Args:
            session: Application session. When omitted, a new Session is created
                     (preserves backward compatibility with direct instantiation).
        """
        super().__init__(*args, **kwargs)

        self.session = session if session is not None else Session()

        # Discover scenarios on startup
        self._discover_scenarios()

    def _discover_scenarios(self) -> None:
        """Discover available scenarios from examples directory."""
        self.scenario_metadata: dict[str, ScenarioMetadata] = {}

        # Look for JSON files in examples/attacks/
        examples_dir = Path("examples/attacks")
        if examples_dir.exists():
            for json_file in examples_dir.glob("*.json"):
                # Skip results files
                if ".result" not in json_file.name and ".results" not in json_file.name:
                    metadata = ScenarioMetadata.from_file(json_file)
                    if metadata:
                        self.scenario_metadata[metadata.name] = metadata

        self.poutput(f"Loaded {len(self.scenario_metadata)} scenarios")

    # ── show ────────────────────────────────────────────────────────────────

    def do_show(self, args: str) -> None:
        """Show scenarios, options, or logging configuration.

        Usage:
            show scenarios             - List all available attack scenarios
            show scenarios <category>  - Filter by category (replay, join_devnonce, forgery)
            show options              - Show current scenario parameters (requires active scenario)
            show options verbose      - Show extended metadata for each parameter
            show logging              - Show current logging configuration
            show <scenario_name>      - Inspect a scenario without loading it
        """
        if not args:
            # Default behavior when loaded
            if self.session.is_scenario_loaded():
                self._show_options()
            else:
                print("Usage: show [scenarios|options|logging|<scenario_name>]")
            return

        parts = args.split()
        if parts[0] == "scenarios":
            # Optional category filter
            category = parts[1] if len(parts) > 1 else None
            self._show_scenarios(category)
        elif parts[0] == "options":
            verbose = len(parts) > 1 and parts[1] == "verbose"
            if verbose:
                self._show_options_verbose()
            else:
                self._show_options()
        elif parts[0] == "logging":
            self._show_logging()
        else:
            # Try to show a specific scenario
            scenario_name = parts[0]
            if scenario_name in self.scenario_metadata:
                self._inspect_scenario(scenario_name)
            else:
                print(f"Unknown show command: {parts[0]}")
                print(
                    "Available: show scenarios [category], show options [verbose], show logging, show <scenario_name>"
                )

    def complete_show(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Autocomplete for show command."""
        words = line.split()
        # First argument
        if len(words) == 1 or (len(words) == 2 and not line.endswith(" ")):
            options = ["scenarios", "options", "logging"] + list(self.scenario_metadata)
            return [o for o in options if o.startswith(text)]
        # Second argument to 'show options'
        if len(words) >= 2 and words[1] == "options":
            return [v for v in ["verbose"] if v.startswith(text)]
        return []

    def _show_scenarios(self, category_filter: str | None = None) -> None:
        """Display available scenarios with metadata."""
        if not self.scenario_metadata:
            print("No scenarios found in examples/attacks/")
            return

        # Filter by category if specified
        scenarios = list(self.scenario_metadata.values())
        if category_filter:
            scenarios = [s for s in scenarios if s.category == category_filter]
            if not scenarios:
                print(f"No scenarios found for category: {category_filter}")
                print("Available categories: replay, join_devnonce, forgery")
                return

        print("\nAvailable Attack Scenarios:")
        if category_filter:
            print(f"Category: {category_filter}")
        print(f"{'Name':<25} {'Category':<15} {'Description':<50}")
        print("-" * 95)

        for metadata in sorted(scenarios, key=lambda s: (s.category, s.name)):
            desc = metadata.description
            if len(desc) > 47:
                desc = desc[:47] + "..."
            print(f"{metadata.name:<25} {metadata.category:<15} {desc:<50}")

        print(f"\n{len(scenarios)} scenario(s) available")
        print("Use 'use <scenario_name>' to load a scenario")
        print("Use 'show scenarios <category>' to filter by category")

    def _show_options(self) -> None:
        """Display current scenario options (compact)."""
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        if self.session.scenario_name is None or self.session.scenario_data is None:
            return

        metadata = self.scenario_metadata[self.session.scenario_name]

        print(f"\nScenario: {self.session.scenario_name}")
        print(f"Title: {metadata.title}")
        print(f"Category: {metadata.category}")
        print("=" * 70)
        print(f"{'Parameter Path':<40} {'Current Value':<30}")
        print("-" * 70)

        self._display_params(self.session.scenario_data)
        print("\nUse 'set <parameter> <value>' to modify parameters")
        print("Use 'show options verbose' for extended metadata")

    def _show_options_verbose(self) -> None:
        """Display current scenario options with full parameter metadata."""
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        if self.session.scenario_data is None:
            return

        from lora_attack_toolkit.app.params import all_paths, get_param

        try:
            from rich.console import Console
            from rich.table import Table

            console = Console()
            table = Table(title=f"Options: {self.session.scenario_name}", show_lines=True)
            table.add_column("Path", style="cyan", no_wrap=True)
            table.add_column("Type", style="magenta")
            table.add_column("Current Value", style="green")
            table.add_column("Default", style="yellow")
            table.add_column("Description")

            for path in all_paths():
                meta = get_param(path)
                if meta is None:
                    continue
                try:
                    current = str(self._get_nested_value(self.session.scenario_data, path))
                except (KeyError, TypeError):
                    current = "(not set)"
                allowed_str = ""
                if meta.allowed_values:
                    allowed_str = f"\nAllowed: {', '.join(meta.allowed_values)}"
                table.add_row(
                    path,
                    meta.type_str,
                    current,
                    str(meta.default) if meta.default is not None else "None",
                    meta.description + allowed_str,
                )
            console.print(table)
        except ImportError:
            # Fallback without rich
            for path in all_paths():
                meta = get_param(path)
                if meta is None:
                    continue
                try:
                    current = str(self._get_nested_value(self.session.scenario_data, path))
                except (KeyError, TypeError):
                    current = "(not set)"
                print(f"\n{path}")
                print(f"  Type:        {meta.type_str}")
                print(f"  Current:     {current}")
                print(f"  Default:     {meta.default}")
                print(f"  Description: {meta.description}")
                if meta.allowed_values:
                    print(f"  Allowed:     {', '.join(meta.allowed_values)}")

    def _display_params(self, d: dict[str, Any], prefix: str = "") -> None:
        """Recursively display parameters."""
        for key, value in sorted(d.items()):
            param_path = f"{prefix}.{key}" if prefix else key

            # Skip certain metadata fields
            if key in ["name", "description", "version"]:
                continue

            if isinstance(value, dict):
                self._display_params(value, param_path)
            else:
                value_str = str(value)
                if len(value_str) > 27:
                    value_str = value_str[:27] + "..."
                print(f"{param_path:<40} {value_str:<30}")

    def _show_logging(self) -> None:
        """Display current logging and output configuration."""
        from lora_attack_toolkit.logging.setup import get_logging_config

        config = get_logging_config()

        print("\n" + "=" * 60)
        print("LOGGING CONFIGURATION")
        print("=" * 60)
        print(f"\nLog Level:          {config.level}  (source: {config.level_source})")
        print(f"Session Log File:   {config.session_log_file or 'Not configured'}")
        print(f"Session ID:         {config.session_id or 'None'}")
        print(f"Scenario ID:        {config.scenario_id or 'None'}")
        print(f"Mask Secrets:       {'enabled' if config.mask_secrets else 'disabled'}")
        print(f"Colored Output:     {'enabled' if config.use_colors else 'disabled'}")
        print(f"PHY Payload Log:    {'enabled' if config.log_phy_payload else 'disabled'}")
        print(f"Semtech UDP Log:    {'enabled' if config.log_semtech_udp else 'disabled'}")
        print("=" * 60)
        print("\nOUTPUT CONFIGURATION")
        print("=" * 60)
        print(f"\nMetrics Mode:       {self.session.output_metrics}")
        print("=" * 60)

        print("\nTip: Use 'set logging.level <level>' to change log level")
        print("Available levels: ERROR, WARNING, INFO, DEBUG, TRACE")
        print("\nTip: Use 'set output.metrics <mode>' to control metrics output")
        print("Available modes: none, summary (default), full")

    # ── use ─────────────────────────────────────────────────────────────────

    def do_use(self, args: str) -> None:
        """Load a scenario into the current session.

        Usage:
            use <scenario_name>

        Example:
            use join-replay-v1
        """
        if not args:
            print("Usage: use <scenario_name>")
            print("Type 'show scenarios' to see available scenarios")
            return

        scenario_name = args.strip()

        if scenario_name not in self.scenario_metadata:
            print(f"Scenario not found: {scenario_name}")
            print("Type 'show scenarios' to see available scenarios")
            return

        try:
            metadata = self.scenario_metadata[scenario_name]
            with open(metadata.path, "r") as f:
                scenario_data = json.load(f)

            self.session.load_scenario(name=scenario_name, path=metadata.path, data=scenario_data)

            self.prompt = f"lorat({scenario_name}) > "

            print(f"✓ Loaded scenario: {scenario_name}")
            print(f"  Title: {metadata.title}")
            print(f"  Category: {metadata.category}")
            print(f"  Description: {metadata.description}")
            print("\nUse 'show options' to view parameters")
        except Exception as e:  # noqa: BLE001
            print(f"Error loading scenario: {e}")

    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Autocomplete scenario names for 'use'."""
        return [n for n in self.scenario_metadata if n.startswith(text)]

    # ── info ─────────────────────────────────────────────────────────────────

    def do_info(self, args: str) -> None:
        """Show detailed information about a scenario.

        Usage:
            info <scenario_name>
        """
        if not args:
            print("Usage: info <scenario_name>")
            print("Type 'show scenarios' to see available scenarios")
            return

        scenario_name = args.strip()
        self._inspect_scenario(scenario_name)

    def complete_info(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Autocomplete scenario names for 'info'."""
        return [n for n in self.scenario_metadata if n.startswith(text)]

    def _inspect_scenario(self, scenario_name: str) -> None:
        """Display detailed information about a scenario without loading it."""
        if scenario_name not in self.scenario_metadata:
            print(f"Scenario not found: {scenario_name}")
            print("Type 'show scenarios' to see available scenarios")
            return

        metadata = self.scenario_metadata[scenario_name]

        print(f"\nScenario: {metadata.name}")
        print("=" * 70)
        print(f"Title:       {metadata.title}")
        print(f"Category:    {metadata.category}")
        print(f"Type:        {metadata.scenario_type}")
        print(f"Path:        {metadata.path}")
        print("\nDescription:")
        print(f"  {metadata.description}")

        try:
            with open(metadata.path, "r") as f:
                scenario_data = json.load(f)

            print("\nDefault Parameters:")
            print("-" * 70)
            print(f"{'Parameter Path':<40} {'Default Value':<30}")
            print("-" * 70)
            self._display_params(scenario_data)

            print("\nTo use this scenario:")
            print(f"  use {scenario_name}")
            print("  set <parameter> <value>")
            print("  run")
        except Exception as e:  # noqa: BLE001
            print(f"\nCould not load default parameters: {e}")

        print()

    # ── set ─────────────────────────────────────────────────────────────────

    def do_set(self, args: str) -> None:
        """Set a parameter value for the current scenario or logging/output config.

        Usage:
            set <parameter> <value>

        Examples:
            set target.host 192.168.1.10
            set attack.config.replay_count 5
            set gateway.radio.rssi -70
            set logging.level debug
            set output.metrics summary
            set output.metrics full
            set output.metrics none
        """
        if not args:
            print("Usage: set <parameter> <value>")
            print("Example: set target.host 192.168.1.10")
            print("         set logging.level debug")
            return

        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            print("Error: Both parameter and value required")
            print("Usage: set <parameter> <value>")
            return

        param_path = parts[0]
        value_str = parts[1]

        if param_path.startswith("logging."):
            self._set_logging_param(param_path, value_str)
            return

        if param_path.startswith("output."):
            self._set_output_param(param_path, value_str)
            return

        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        if self.session.scenario_data is None:
            return

        try:
            self.session.set_parameter(param_path, value_str)
            self._set_nested_value(self.session.scenario_data, param_path, value_str)
            print(f"✓ Set {param_path} = {value_str}")
        except KeyError as e:
            print(f"Error: Parameter not found: {e}")
        except ValueError as e:
            print(f"Error: Invalid value: {e}")

    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Autocomplete parameter paths and values for 'set'."""
        from lora_attack_toolkit.app.params import all_paths, get_allowed_values

        words = line.split()
        # Are we completing the path (first argument)?
        if len(words) == 1 or (len(words) == 2 and not line.endswith(" ")):
            return [p for p in all_paths() if p.startswith(text)]

        # Are we completing the value (second argument)?
        if len(words) >= 2:
            path = words[1]
            allowed = get_allowed_values(path)
            if allowed:
                return [v for v in allowed if v.startswith(text)]
        return []

    def _set_nested_value(self, data: dict[str, Any], path: str, value_str: str) -> None:
        """Set a value in a nested dictionary using dot notation."""
        keys = path.split(".")
        current = data

        for key in keys[:-1]:
            if key not in current:
                raise KeyError(f"'{key}' in path '{path}'")
            current = current[key]
            if not isinstance(current, dict):
                raise KeyError(f"'{key}' is not a dict in path '{path}'")

        final_key = keys[-1]
        if final_key not in current:
            raise KeyError(f"'{final_key}' in path '{path}'")

        original_value = current[final_key]
        converted_value = self._convert_value(value_str, original_value)
        current[final_key] = converted_value

    def _convert_value(self, value_str: str, original_value: Any) -> Any:
        """Convert string value to appropriate type based on original value."""
        if value_str.lower() in ("none", "null"):
            return None

        if isinstance(original_value, bool):
            if value_str.lower() in ("true", "yes", "1"):
                return True
            elif value_str.lower() in ("false", "no", "0"):
                return False
            else:
                raise ValueError(f"Cannot convert '{value_str}' to bool")

        elif isinstance(original_value, int):
            try:
                return int(value_str)
            except ValueError:
                # Allow string sentinels (e.g. "random" for valid_devnonce_start).
                return value_str

        elif isinstance(original_value, float):
            try:
                return float(value_str)
            except ValueError:
                raise ValueError(f"Cannot convert '{value_str}' to float")

        else:
            return value_str

    def _set_logging_param(self, param_path: str, value_str: str) -> None:
        """Set logging configuration parameter."""
        from lora_attack_toolkit.logging.setup import reconfigure_level

        param_name = param_path.split(".", 1)[1] if "." in param_path else param_path

        if param_name == "level":
            valid_levels = ["ERROR", "WARNING", "INFO", "DEBUG", "TRACE"]
            level = value_str.upper()

            if level not in valid_levels:
                print(f"Error: Invalid log level '{value_str}'")
                print(f"Valid levels: {', '.join(valid_levels)}")
                return

            reconfigure_level(level)
            print(f"✓ Log level changed to: {level}")

        elif param_name == "file":
            print("Note: Log file cannot be changed during session")
            print("The current session log file will continue to be used")

        else:
            print(f"Error: Unknown logging parameter: {param_name}")
            print("Available: logging.level")

    def _set_output_param(self, param_path: str, value_str: str) -> None:
        """Set output configuration parameter."""
        param_name = param_path.split(".", 1)[1] if "." in param_path else param_path

        if param_name == "metrics":
            valid_modes = ["none", "summary", "full"]
            mode = value_str.lower()
            if mode not in valid_modes:
                print(f"Error: Invalid metrics mode '{value_str}'")
                print(f"Valid modes: {', '.join(valid_modes)}")
                return
            self.session.output_metrics = mode
            print(f"✓ Metrics output set to: {mode}")
        else:
            print(f"Error: Unknown output parameter: {param_name}")
            print("Available: output.metrics")

    # ── reset ────────────────────────────────────────────────────────────────

    def do_reset(self, args: str) -> None:
        """Reset parameters to default values.

        Usage:
            reset              - Reset all parameters to defaults
            reset <parameter>  - Reset specific parameter to default
        """
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        scenario_path = self.session.scenario_path
        if scenario_path is None:
            return

        if not args:
            try:
                with open(scenario_path, "r") as f:
                    scenario_data = json.load(f)

                self.session.load_scenario(
                    name=self.session.scenario_name or "", path=scenario_path, data=scenario_data
                )
                print("✓ Reset all parameters to defaults")
            except Exception as e:  # noqa: BLE001
                print(f"Error reloading scenario: {e}")
        else:
            param_path = args.strip()
            if self.session.scenario_data is None:
                return
            try:
                with open(scenario_path, "r") as f:
                    original_scenario = json.load(f)

                original_value = self._get_nested_value(original_scenario, param_path)
                self._set_nested_value_direct(
                    self.session.scenario_data, param_path, original_value
                )

                print(f"✓ Reset {param_path} to default: {original_value}")
            except KeyError as e:
                print(f"Error: Parameter not found: {e}")
            except Exception as e:  # noqa: BLE001
                print(f"Error: {e}")

    def _get_nested_value(self, data: dict[str, Any], path: str) -> Any:
        """Get a value from a nested dictionary using dot notation."""
        keys = path.split(".")
        current = data

        for key in keys:
            if key not in current:
                raise KeyError(f"'{key}' in path '{path}'")
            current = current[key]

        return current

    def _set_nested_value_direct(self, data: dict[str, Any], path: str, value: Any) -> None:
        """Set a value directly (without type conversion)."""
        keys = path.split(".")
        current = data

        for key in keys[:-1]:
            if key not in current:
                raise KeyError(f"'{key}' in path '{path}'")
            current = current[key]

        final_key = keys[-1]
        current[final_key] = value

    # ── validate ─────────────────────────────────────────────────────────────

    def do_validate(self, args: str) -> None:
        """Validate the current scenario configuration.

        Usage:
            validate
        """
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        if self.session.scenario_data is None:
            return

        print("Validating scenario configuration...")

        try:
            import tempfile

            from lora_attack_toolkit.config import load_attack_scenario

            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(self.session.scenario_data, f, indent=2)
                temp_path = f.name

            try:
                load_attack_scenario(temp_path)
                print("✓ Scenario configuration is valid")

                print("\nValidation Summary:")
                print(f"  Schema: {self.session.scenario_data.get('schema_version', 'unknown')}")
                print(f"  Category: {self.session.scenario_data['scenario']['category']}")
                print(f"  Attack Type: {self.session.scenario_data['attack']['type']}")
                print(
                    f"  Target: {self.session.scenario_data['target']['host']}:{self.session.scenario_data['target']['port']}"
                )

            finally:
                import os

                os.unlink(temp_path)

        except ImportError as e:
            print(f"✗ Validation failed: Missing dependencies ({e})")
        except ValueError as e:
            print(f"✗ Validation failed: {e}")
        except KeyError as e:
            print(f"✗ Validation error: Missing required field {e}")
        except Exception as e:  # noqa: BLE001
            print(f"✗ Validation error: {e}")

    # ── run ──────────────────────────────────────────────────────────────────

    def do_run(self, args: str) -> None:
        """Execute the currently loaded attack scenario.

        Usage:
            run

        Press Ctrl+C to interrupt a running attack and return to the prompt.
        """
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        if self.session.scenario_data is None:
            return

        print("Validating scenario...")
        import tempfile

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
                json.dump(self.session.scenario_data, tmp, indent=2)
                tmp_path = tmp.name

            from lora_attack_toolkit.config import load_attack_scenario

            scenario = load_attack_scenario(tmp_path)

        except Exception as e:  # noqa: BLE001
            print(f"\n❌ Validation failed: {e}")
            return
        finally:
            import os

            if "tmp_path" in locals():
                os.unlink(tmp_path)

        print("✓ Validation passed\n")

        print("=" * 60)
        print(
            f"Executing: {self.session.scenario_data.get('scenario', {}).get('title', self.session.scenario_name)}"
        )
        print("=" * 60)

        # Set up cooperative cancellation
        cancel_event = threading.Event()
        old_sigint = signal.getsignal(signal.SIGINT)

        def _sigint_handler(signum, frame):
            if not cancel_event.is_set():
                print("\n\n⚠️  Ctrl+C received — stopping attack gracefully...")
                cancel_event.set()

        try:
            from lora_attack_toolkit.logging.setup import reconfigure_level

            log_config = self.session.scenario_data.get("logging", {})
            log_level = log_config.get("level", "INFO").upper()
            reconfigure_level(log_level, source="scenario")

            logger = logging.getLogger("lora_attack_toolkit")

            from lora_attack_toolkit.runner import AttackRunner

            runner = AttackRunner(logger=logger)
            print("\n🚀 Starting attack execution...\n")
            print("   Press Ctrl+C to interrupt.\n")

            signal.signal(signal.SIGINT, _sigint_handler)
            results = runner.run(scenario, cancel_event=cancel_event)

            if results.get("interrupted"):
                print("\n⚠️  Attack was interrupted by user.")
                print("   Gateway stopped. You can modify parameters and run again.")

            self._display_results(results)
            self._save_results(results)

            if not results.get("interrupted"):
                print("\n✓ Attack execution complete")

        except Exception as e:  # noqa: BLE001
            print(f"\n❌ Attack execution failed: {e}")
            import traceback

            traceback.print_exc()
        finally:
            signal.signal(signal.SIGINT, old_sigint)

    # ── help override ────────────────────────────────────────────────────────

    def do_help(self, args: str) -> None:
        """Show help for commands or parameter metadata.

        Usage:
            help                        - List all commands
            help <command>              - Show help for a command
            help <parameter.path>       - Show metadata for a parameter
        """
        if args and "." in args:
            self._show_param_help(args.strip())
        else:
            super().do_help(args)

    def _show_param_help(self, path: str) -> None:
        """Display metadata for a registered parameter path."""
        from lora_attack_toolkit.app.params import get_param

        meta = get_param(path)
        if meta is None:
            print(f"Unknown parameter: {path}")
            print("Use 'show options verbose' to list all known parameters.")
            return

        current = "(not loaded)"
        if self.session.is_scenario_loaded() and self.session.scenario_data is not None:
            try:
                current = str(self._get_nested_value(self.session.scenario_data, path))
            except (KeyError, TypeError):
                current = "(not set)"

        try:
            from rich import box
            from rich.console import Console
            from rich.panel import Panel

            console = Console()
            lines = [
                f"[bold]Path:[/bold]          {meta.path}",
                f"[bold]Type:[/bold]          {meta.type_str}",
                f"[bold]Current value:[/bold] {current}",
                f"[bold]Default:[/bold]       {meta.default}",
                f"[bold]Description:[/bold]   {meta.description}",
            ]
            if meta.allowed_values:
                lines.append(f"[bold]Allowed:[/bold]       {', '.join(meta.allowed_values)}")
            console.print(Panel("\n".join(lines), title=f"Parameter: {path}", box=box.ROUNDED))
        except ImportError:
            print(f"\nParameter: {path}")
            print(f"  Type:          {meta.type_str}")
            print(f"  Current value: {current}")
            print(f"  Default:       {meta.default}")
            print(f"  Description:   {meta.description}")
            if meta.allowed_values:
                print(f"  Allowed:       {', '.join(meta.allowed_values)}")

    # ── metrics display ──────────────────────────────────────────────────────

    # Keys shown in summary mode per attack type
    _SUMMARY_METRICS: dict[str, list[str]] = {
        "join_devnonce": [
            "final_check",
            "valid_join_count",
            "accepted_generation_count",
            "generation_complete",
            "final_check_executed",
            "final_join_accepted",
            "final_devnonce_int",
        ],
    }
    _SUMMARY_METRICS_GENERIC: list[str] = [
        "attack_type",
        "total_uplinks",
        "total_downlinks",
        "success",
    ]

    def _display_results(self, results: dict[str, Any]) -> None:
        """Display attack execution results in formatted output."""
        print("\n" + "=" * 60)
        print("ATTACK RESULTS")
        print("=" * 60)

        success = results.get("execution_status") == "completed"
        status_symbol = "✓" if success else "✗"
        print(f"\nStatus: {status_symbol} {'SUCCESS' if success else 'FAILED'}")
        print(f"Message: {results.get('message', 'No message')}")

        metrics = results.get("metrics", {})
        metrics_mode = self.session.output_metrics

        if metrics and metrics_mode != "none":
            print(f"\n{'Metrics':-^60}")

            if metrics_mode == "summary":
                attack_type = metrics.get("attack_type", "")
                keys = self._SUMMARY_METRICS.get(attack_type, self._SUMMARY_METRICS_GENERIC)
                visible = {k: metrics[k] for k in keys if k in metrics}
            else:
                visible = metrics

            for key, value in visible.items():
                formatted_key = key.replace("_", " ").title()
                print(f"  {formatted_key:.<40} {value}")

            if metrics_mode == "summary" and len(metrics) > len(visible):
                print(f"  (use 'set output.metrics full' to see all {len(metrics)} fields)")

        expected_behavior = results.get("expected_behavior")
        if expected_behavior:
            print(f"\n{'Expected Behavior':-^60}")
            print(f"  {expected_behavior}")

        success_criteria = results.get("success_criteria")
        if success_criteria:
            print(f"\n{'Success Criteria':-^60}")
            for criterion in success_criteria:
                print(f"  • {criterion}")

        captured = results.get("captured_packets", {})
        if captured:
            if isinstance(captured, dict):
                uplinks = len(captured.get("uplinks", []))
                downlinks = len(captured.get("downlinks", []))
            else:
                uplinks = captured
                downlinks = 0
            print(f"\n{'Captured Packets':-^60}")
            print(f"  Uplinks: {uplinks}")
            print(f"  Downlinks: {downlinks}")

        print("\n" + "=" * 60)

    def _save_results(self, results: dict[str, Any]) -> None:
        """Save execution results to results/<session-id>/ directory."""
        if not self.session.scenario_path:
            return

        session_id = self.session.session_id or "default"
        results_dir = Path("results") / session_id
        results_dir.mkdir(parents=True, exist_ok=True)

        scenario_name = self.session.scenario_path.stem
        results_path = results_dir / f"{scenario_name}.results.json"

        try:
            with open(results_path, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to: {results_path}")
        except Exception as e:  # noqa: BLE001
            print(f"\n⚠️  Failed to save results: {e}")

    # ── misc commands ────────────────────────────────────────────────────────

    def do_clear(self, args: str) -> None:
        """Clear the current scenario session.

        Usage:
            clear
        """
        if self.session.is_scenario_loaded():
            print(f"Cleared scenario: {self.session.scenario_name}")
            self.session.clear_scenario()

        self.prompt = "lorat > "

    def do_exit(self, args: str) -> bool:
        """Exit the interactive shell.

        Usage:
            exit
        """
        print("Goodbye!")
        return True

    # Aliases
    do_quit = do_exit
    do_q = do_exit
    do_EOF = do_exit
    do_r = do_run

    def default(self, statement) -> None:
        """Handle unrecognised commands with a helpful hint."""
        # cmd2 passes a Statement object; get raw string
        line = str(statement)
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and "." in parts[0]:
            print(f"Unknown command. Did you mean:  set {line}")
        else:
            print(f"Unknown command: {line!r}")
        print("Type 'help' for available commands.")

    def emptyline(self) -> bool:
        """Do nothing on empty line."""
        return False
