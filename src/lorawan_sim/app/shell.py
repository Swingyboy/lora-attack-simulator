"""
Interactive shell for LoRaWAN attack simulator.

Provides Metasploit-like workflow for scenario management.
Uses only standard library to avoid dependency issues.
"""
from __future__ import annotations

import cmd
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lorawan_sim.app.session import Session


@dataclass
class ScenarioMetadata:
    """Metadata extracted from scenario file."""
    name: str
    path: Path
    title: str
    description: str
    category: str
    scenario_type: str
    
    @classmethod
    def from_file(cls, path: Path) -> ScenarioMetadata | None:
        """Extract metadata from scenario JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            scenario = data.get('scenario', {})
            return cls(
                name=path.stem,
                path=path,
                title=scenario.get('title', path.stem),
                description=scenario.get('description', 'No description'),
                category=scenario.get('category', 'unknown'),
                scenario_type=scenario.get('type', 'unknown')
            )
        except (json.JSONDecodeError, IOError):
            return None


class LoRaWANShell(cmd.Cmd):
    """Interactive shell for LoRaWAN offensive security testing."""

    intro = """
╔════════════════════════════════════════════════════════════════╗
║  LoRaWAN Offensive Security Testing Framework                 ║
║  Version: 0.1.0-mvp                                           ║
║  Transport: Semtech UDP                                        ║
║                                                                ║
║  Type 'help' for available commands                           ║
║  Type 'show scenarios' to list available attack scenarios     ║
╚════════════════════════════════════════════════════════════════╝
"""
    
    prompt = "lorawan-sim > "
    
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the shell."""
        super().__init__(*args, **kwargs)
        
        # Initialize session
        self.session = Session()
        
        # Initialize logging for shell session
        from sim_logging.json_logger import configure_logging
        
        configure_logging(
            level="INFO",
            session_id=self.session.session_id,
            mask_secrets=True,
            use_colors=True,
        )
        
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
        
        print(f"Loaded {len(self.scenario_metadata)} scenarios")
    
    def do_show(self, args: str) -> None:
        """Show scenarios, options, or logging configuration.
        
        Usage:
            show scenarios             - List all available attack scenarios
            show scenarios <category>  - Filter by category (replay, join_abuse, mac_abuse)
            show options              - Show current scenario parameters (requires active scenario)
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
                print("Available: show scenarios [category], show options, show logging, show <scenario_name>")
    
    def _show_scenarios(self, category_filter: str | None = None) -> None:
        """Display available scenarios with metadata.
        
        Args:
            category_filter: Optional category to filter (replay, join_abuse, mac_abuse)
        """
        if not self.scenario_metadata:
            print("No scenarios found in examples/attacks/")
            return
        
        # Filter by category if specified
        scenarios = self.scenario_metadata.values()
        if category_filter:
            scenarios = [s for s in scenarios if s.category == category_filter]
            if not scenarios:
                print(f"No scenarios found for category: {category_filter}")
                print("Available categories: replay, join_abuse, mac_abuse")
                return
        
        print("\nAvailable Attack Scenarios:")
        if category_filter:
            print(f"Category: {category_filter}")
        print(f"{'Name':<25} {'Category':<15} {'Description':<50}")
        print("-" * 95)
        
        for metadata in sorted(scenarios, key=lambda s: (s.category, s.name)):
            # Truncate description if too long
            desc = metadata.description
            if len(desc) > 47:
                desc = desc[:47] + "..."
            print(f"{metadata.name:<25} {metadata.category:<15} {desc:<50}")
        
        print(f"\n{len(list(scenarios))} scenario(s) available")
        print("Use 'use <scenario_name>' to load a scenario")
        print("Use 'show scenarios <category>' to filter by category")
    
    def _show_options(self) -> None:
        """Display current scenario options."""
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
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
        print("Example: set target.host 192.168.1.100")
    
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
                # Truncate long values
                value_str = str(value)
                if len(value_str) > 27:
                    value_str = value_str[:27] + "..."
                print(f"{param_path:<40} {value_str:<30}")
    
    def _show_logging(self) -> None:
        """Display current logging configuration."""
        from sim_logging.json_logger import get_logging_config
        
        config = get_logging_config()
        
        print("\n" + "=" * 60)
        print("LOGGING CONFIGURATION")
        print("=" * 60)
        print(f"\nLog Level:          {config.level}")
        print(f"Session Log File:   {config.session_log_file or 'Not configured'}")
        print(f"Session ID:         {config.session_id or 'None'}")
        print(f"Scenario ID:        {config.scenario_id or 'None'}")
        print(f"Mask Secrets:       {'enabled' if config.mask_secrets else 'disabled'}")
        print(f"Colored Output:     {'enabled' if config.use_colors else 'disabled'}")
        print(f"PHY Payload Log:    {'enabled' if config.log_phy_payload else 'disabled'}")
        print(f"Semtech UDP Log:    {'enabled' if config.log_semtech_udp else 'disabled'}")
        print("=" * 60)
        
        print("\nTip: Use 'set logging.level <level>' to change log level")
        print("Available levels: ERROR, WARNING, INFO, DEBUG, TRACE")
    
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
        
        # Load scenario from JSON
        try:
            metadata = self.scenario_metadata[scenario_name]
            with open(metadata.path, 'r') as f:
                scenario_data = json.load(f)
            
            # Use session API to load scenario
            self.session.load_scenario(
                name=scenario_name,
                path=metadata.path,
                data=scenario_data
            )
            
            # Update prompt to show active scenario
            self.prompt = f"lorawan-sim({scenario_name}) > "
            
            print(f"✓ Loaded scenario: {scenario_name}")
            print(f"  Title: {metadata.title}")
            print(f"  Category: {metadata.category}")
            print(f"  Description: {metadata.description}")
            print("\nUse 'show options' to view parameters")
        except Exception as e:
            print(f"Error loading scenario: {e}")
    
    def do_info(self, args: str) -> None:
        """Show detailed information about a scenario.
        
        Usage:
            info <scenario_name>
        
        Example:
            info join-replay-v1
        """
        if not args:
            print("Usage: info <scenario_name>")
            print("Type 'show scenarios' to see available scenarios")
            return
        
        scenario_name = args.strip()
        self._inspect_scenario(scenario_name)
    
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
        print(f"\nDescription:")
        print(f"  {metadata.description}")
        
        # Load scenario data to show default parameters
        try:
            from pathlib import Path
            scenario_path = Path(metadata.path)
            with open(scenario_path, 'r') as f:
                import json
                scenario_data = json.load(f)
            
            print(f"\nDefault Parameters:")
            print("-" * 70)
            print(f"{'Parameter Path':<40} {'Default Value':<30}")
            print("-" * 70)
            self._display_params(scenario_data)
            
            print(f"\nTo use this scenario:")
            print(f"  use {scenario_name}")
            print(f"  set <parameter> <value>")
            print(f"  run")
        except Exception as e:
            print(f"\nCould not load default parameters: {e}")
        
        print()
    
    def do_set(self, args: str) -> None:
        """Set a parameter value for the current scenario or logging config.
        
        Usage:
            set <parameter> <value>
        
        Examples:
            set target.host 192.168.1.10
            set attack.config.replay_count 5
            set gateway.radio.rssi -70
            set logging.level debug
            set logging.file logs/custom.log
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
        
        # Handle logging configuration specially
        if param_path.startswith("logging."):
            self._set_logging_param(param_path, value_str)
            return
        
        # Handle scenario parameters
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        try:
            # Record override in session
            self.session.set_parameter(param_path, value_str)
            
            # Also update in-memory for backward compatibility
            self._set_nested_value(self.session.scenario_data, param_path, value_str)
            print(f"✓ Set {param_path} = {value_str}")
        except KeyError as e:
            print(f"Error: Parameter not found: {e}")
        except ValueError as e:
            print(f"Error: Invalid value: {e}")
    
    def _set_nested_value(self, data: dict[str, Any], path: str, value_str: str) -> None:
        """Set a value in a nested dictionary using dot notation.
        
        Args:
            data: The dictionary to modify
            path: Dot-separated path (e.g., "target.host")
            value_str: String value to set (auto-converts to appropriate type)
        """
        keys = path.split('.')
        current = data
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in current:
                raise KeyError(f"'{key}' in path '{path}'")
            current = current[key]
            if not isinstance(current, dict):
                raise KeyError(f"'{key}' is not a dict in path '{path}'")
        
        # Get the final key
        final_key = keys[-1]
        if final_key not in current:
            raise KeyError(f"'{final_key}' in path '{path}'")
        
        # Get the original value to infer type
        original_value = current[final_key]
        
        # Convert value_str to appropriate type
        converted_value = self._convert_value(value_str, original_value)
        
        # Set the value
        current[final_key] = converted_value
    
    def _convert_value(self, value_str: str, original_value: Any) -> Any:
        """Convert string value to appropriate type based on original value.
        
        Args:
            value_str: String value to convert
            original_value: Original value to infer type from
        
        Returns:
            Converted value
        """
        # Handle None
        if value_str.lower() == 'none' or value_str.lower() == 'null':
            return None
        
        # Infer type from original value
        if isinstance(original_value, bool):
            if value_str.lower() in ('true', 'yes', '1'):
                return True
            elif value_str.lower() in ('false', 'no', '0'):
                return False
            else:
                raise ValueError(f"Cannot convert '{value_str}' to bool")
        
        elif isinstance(original_value, int):
            try:
                return int(value_str)
            except ValueError:
                raise ValueError(f"Cannot convert '{value_str}' to int")
        
        elif isinstance(original_value, float):
            try:
                return float(value_str)
            except ValueError:
                raise ValueError(f"Cannot convert '{value_str}' to float")
        
        else:
            # Default to string
            return value_str
    
    def _set_logging_param(self, param_path: str, value_str: str) -> None:
        """Set logging configuration parameter."""
        from sim_logging.json_logger import reconfigure_level
        
        # Extract parameter name (e.g., "logging.level" -> "level")
        param_name = param_path.split(".", 1)[1] if "." in param_path else param_path
        
        if param_name == "level":
            # Validate log level
            valid_levels = ["ERROR", "WARNING", "INFO", "DEBUG", "TRACE"]
            level = value_str.upper()
            
            if level not in valid_levels:
                print(f"Error: Invalid log level '{value_str}'")
                print(f"Valid levels: {', '.join(valid_levels)}")
                return
            
            # Reconfigure log level
            reconfigure_level(level)
            print(f"✓ Log level changed to: {level}")
        
        elif param_name == "file":
            print("Note: Log file cannot be changed during session")
            print("The current session log file will continue to be used")
        
        else:
            print(f"Error: Unknown logging parameter: {param_name}")
            print("Available: logging.level")
    
    def do_reset(self, args: str) -> None:
        """Reset parameters to default values.
        
        Usage:
            reset              - Reset all parameters to defaults
            reset <parameter>  - Reset specific parameter to default
        
        Examples:
            reset
            reset target.host
        """
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        if not args:
            # Reset all parameters by reloading from file
            try:
                with open(self.session.scenario_path, 'r') as f:
                    scenario_data = json.load(f)
                
                # Reload using session API
                self.session.load_scenario(
                    name=self.session.scenario_name or "",
                    path=self.session.scenario_path,
                    data=scenario_data
                )
                print("✓ Reset all parameters to defaults")
            except Exception as e:
                print(f"Error reloading scenario: {e}")
        else:
            # Reset specific parameter
            param_path = args.strip()
            try:
                # Load original value from file
                with open(self.session.scenario_path, 'r') as f:
                    original_scenario = json.load(f)
                
                # Get original value
                original_value = self._get_nested_value(original_scenario, param_path)
                
                # Set it back
                self._set_nested_value_direct(self.session.scenario_data, param_path, original_value)
                
                print(f"✓ Reset {param_path} to default: {original_value}")
            except KeyError as e:
                print(f"Error: Parameter not found: {e}")
            except Exception as e:
                print(f"Error: {e}")
    
    def _get_nested_value(self, data: dict[str, Any], path: str) -> Any:
        """Get a value from a nested dictionary using dot notation."""
        keys = path.split('.')
        current = data
        
        for key in keys:
            if key not in current:
                raise KeyError(f"'{key}' in path '{path}'")
            current = current[key]
        
        return current
    
    def _set_nested_value_direct(self, data: dict[str, Any], path: str, value: Any) -> None:
        """Set a value directly (without type conversion)."""
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                raise KeyError(f"'{key}' in path '{path}'")
            current = current[key]
        
        final_key = keys[-1]
        current[final_key] = value
    
    def do_validate(self, args: str) -> None:
        """Validate the current scenario configuration.
        
        Usage:
            validate
        """
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        print("Validating scenario configuration...")
        
        # Import validation lazily to avoid loading dependencies
        try:
            from lorawan.scenario.loader import load_attack_scenario
            import tempfile
            import json as json_module
            
            # Write current scenario to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json_module.dump(self.session.scenario_data, f, indent=2)
                temp_path = f.name
            
            try:
                # Try to load and validate
                attack_scenario = load_attack_scenario(temp_path)
                print("✓ Scenario configuration is valid")
                
                # Show summary
                print(f"\nValidation Summary:")
                print(f"  Schema: {self.session.scenario_data.get('schema_version', 'unknown')}")
                print(f"  Category: {self.session.scenario_data['scenario']['category']}")
                print(f"  Attack Type: {self.session.scenario_data['attack']['type']}")
                print(f"  Target: {self.session.scenario_data['target']['host']}:{self.session.scenario_data['target']['port']}")
                
            finally:
                # Clean up temp file
                import os
                os.unlink(temp_path)
                
        except ImportError as e:
            print(f"✗ Validation failed: Missing dependencies ({e})")
            print("  Run 'pip install -e .' to install required packages")
        except ValueError as e:
            print(f"✗ Validation failed: {e}")
        except KeyError as e:
            print(f"✗ Validation error: Missing required field {e}")
        except Exception as e:
            print(f"✗ Validation error: {e}")
    
    def do_run(self, args: str) -> None:
        """Execute the currently loaded attack scenario.
        
        Usage:
            run
        """
        if not self.session.is_scenario_loaded():
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        # Validate scenario before execution
        print("Validating scenario...")
        import tempfile
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                json.dump(self.session.scenario_data, tmp, indent=2)
                tmp_path = tmp.name
            
            from lorawan.scenario.loader import load_attack_scenario
            scenario = load_attack_scenario(tmp_path)
            
        except Exception as e:
            print(f"\n❌ Validation failed: {e}")
            return
        finally:
            import os
            if 'tmp_path' in locals():
                os.unlink(tmp_path)
        
        print("✓ Validation passed\n")
        
        # Execute attack
        print("=" * 60)
        print(f"Executing: {self.session.scenario_data.get('scenario', {}).get('title', self.session.scenario_name)}")
        print("=" * 60)
        
        try:
            # Configure logging for attack execution
            import logging
            from sim_logging.json_logger import configure_logging
            
            log_config = self.session.scenario_data.get('logging', {})
            log_level = log_config.get('level', 'INFO').upper()
            configure_logging(level=log_level)
            
            logger = logging.getLogger("lorawan_sim")
            
            # Import and run attack
            from attacks.runner import AttackRunner
            
            runner = AttackRunner(logger=logger)
            print(f"\n🚀 Starting attack execution...\n")
            
            results = runner.run(scenario)
            
            # Display results
            self._display_results(results)
            
            # Save results to file
            self._save_results(results)
            
            print("\n✓ Attack execution complete")
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Execution interrupted by user (Ctrl+C)")
            print("Cleaning up resources...")
            
        except Exception as e:
            print(f"\n❌ Attack execution failed: {e}")
            import traceback
            print("\nStack trace:")
            traceback.print_exc()
    
    def _display_results(self, results: dict[str, Any]) -> None:
        """Display attack execution results in formatted output."""
        print("\n" + "=" * 60)
        print("ATTACK RESULTS")
        print("=" * 60)
        
        # Success status
        success = results.get('success', False)
        status_symbol = "✓" if success else "✗"
        print(f"\nStatus: {status_symbol} {'SUCCESS' if success else 'FAILED'}")
        print(f"Message: {results.get('message', 'No message')}")
        
        # Metrics
        metrics = results.get('metrics', {})
        if metrics:
            print(f"\n{'Metrics':-^60}")
            for key, value in metrics.items():
                # Format metric name (snake_case to Title Case)
                formatted_key = key.replace('_', ' ').title()
                print(f"  {formatted_key:.<40} {value}")
        
        # Expected behavior (v1.0 scenarios)
        expected_behavior = results.get('expected_behavior')
        if expected_behavior:
            print(f"\n{'Expected Behavior':-^60}")
            print(f"  {expected_behavior}")
        
        # Success criteria (v1.0 scenarios)
        success_criteria = results.get('success_criteria')
        if success_criteria:
            print(f"\n{'Success Criteria':-^60}")
            for criterion in success_criteria:
                print(f"  • {criterion}")
        
        # Captured packets summary
        captured = results.get('captured_packets', {})
        if captured:
            if isinstance(captured, dict):
                uplinks = len(captured.get('uplinks', []))
                downlinks = len(captured.get('downlinks', []))
            else:
                # captured_packets is an integer count
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
        
        from pathlib import Path
        
        # Use session ID from Session object
        session_id = self.session.session_id or "default"
        
        # Create results directory structure: results/<session-id>/
        results_dir = Path("results") / session_id
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Use scenario filename as base
        scenario_name = self.session.scenario_path.stem
        results_path = results_dir / f"{scenario_name}.results.json"
        
        try:
            with open(results_path, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to: {results_path}")
        except Exception as e:
            print(f"\n⚠️  Failed to save results: {e}")
    
    def do_clear(self, args: str) -> None:
        """Clear the current scenario session.
        
        Usage:
            clear
        """
        if self.session.is_scenario_loaded():
            print(f"Cleared scenario: {self.session.scenario_name}")
            self.session.clear_scenario()
        
        self.prompt = "lorawan-sim > "
    
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
    do_r = do_run  # Alias for run
    
    def emptyline(self) -> None:
        """Do nothing on empty line."""
        pass


def start_shell() -> None:
    """Start the interactive shell."""
    try:
        shell = LoRaWANShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)


if __name__ == "__main__":
    start_shell()
