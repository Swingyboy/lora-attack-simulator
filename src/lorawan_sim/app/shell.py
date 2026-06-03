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
    
    # Current session state
    current_scenario: dict[str, Any] | None = None
    current_scenario_name: str | None = None
    current_scenario_path: Path | None = None
    
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the shell."""
        super().__init__(*args, **kwargs)
        
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
        """Show scenarios or options.
        
        Usage:
            show scenarios             - List all available attack scenarios
            show scenarios <category>  - Filter by category (replay, join_abuse, mac_abuse)
            show options              - Show current scenario parameters (requires active scenario)
        """
        if not args:
            print("Usage: show [scenarios|options]")
            return
        
        parts = args.split()
        if parts[0] == "scenarios":
            # Optional category filter
            category = parts[1] if len(parts) > 1 else None
            self._show_scenarios(category)
        elif parts[0] == "options":
            self._show_options()
        else:
            print(f"Unknown show command: {parts[0]}")
            print("Available: show scenarios [category], show options")
    
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
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        metadata = self.scenario_metadata[self.current_scenario_name]
        
        print(f"\nScenario: {self.current_scenario_name}")
        print(f"Title: {metadata.title}")
        print(f"Category: {metadata.category}")
        print("=" * 70)
        print(f"{'Parameter Path':<40} {'Current Value':<30}")
        print("-" * 70)
        
        # Display parameters with nested paths
        self._print_nested_dict(self.current_scenario, prefix="")
        
        print("\nUse 'set <param_path> <value>' to modify parameters")
        print("Use 'reset' to restore all defaults")
    
    def _print_nested_dict(self, data: dict[str, Any], prefix: str = "") -> None:
        """Recursively print nested dictionary with dot notation paths."""
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                # Recursively print nested dicts
                self._print_nested_dict(value, path)
            elif isinstance(value, list):
                # Show list length and type
                if value:
                    list_repr = f"[{len(value)} items]"
                else:
                    list_repr = "[]"
                print(f"{path:<40} {list_repr:<30}")
            else:
                # Show primitive values
                value_str = str(value)
                if len(value_str) > 27:
                    value_str = value_str[:27] + "..."
                print(f"{path:<40} {value_str:<30}")
    
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
                self.current_scenario = json.load(f)
            
            self.current_scenario_name = scenario_name
            self.current_scenario_path = metadata.path
            
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
        print()
    
    def do_set(self, args: str) -> None:
        """Set a parameter value for the current scenario.
        
        Usage:
            set <parameter> <value>
        
        Examples:
            set target.host 192.168.1.10
            set attack.config.replay_count 5
            set gateway.radio.rssi -70
        """
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        if not args:
            print("Usage: set <parameter> <value>")
            print("Example: set target.host 192.168.1.10")
            return
        
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            print("Error: Both parameter and value required")
            print("Usage: set <parameter> <value>")
            return
        
        param_path = parts[0]
        value_str = parts[1]
        
        try:
            # Navigate to the nested parameter and set value
            self._set_nested_value(self.current_scenario, param_path, value_str)
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
    
    def do_reset(self, args: str) -> None:
        """Reset parameters to default values.
        
        Usage:
            reset              - Reset all parameters to defaults
            reset <parameter>  - Reset specific parameter to default
        
        Examples:
            reset
            reset target.host
        """
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        if not args:
            # Reset all parameters by reloading from file
            try:
                with open(self.current_scenario_path, 'r') as f:
                    self.current_scenario = json.load(f)
                print("✓ Reset all parameters to defaults")
            except Exception as e:
                print(f"Error reloading scenario: {e}")
        else:
            # Reset specific parameter
            param_path = args.strip()
            try:
                # Load original value from file
                with open(self.current_scenario_path, 'r') as f:
                    original_scenario = json.load(f)
                
                # Get original value
                original_value = self._get_nested_value(original_scenario, param_path)
                
                # Set it back
                self._set_nested_value_direct(self.current_scenario, param_path, original_value)
                
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
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        print("Validating scenario configuration...")
        
        # Import validation lazily to avoid loading dependencies
        try:
            from lorawan_sim.domain.attack_scenario.loader import load_attack_scenario
            import tempfile
            import json as json_module
            
            # Write current scenario to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json_module.dump(self.current_scenario, f, indent=2)
                temp_path = f.name
            
            try:
                # Try to load and validate
                attack_scenario = load_attack_scenario(temp_path)
                print("✓ Scenario configuration is valid")
                
                # Show summary
                print(f"\nValidation Summary:")
                print(f"  Schema: {self.current_scenario.get('schema_version', 'unknown')}")
                print(f"  Category: {self.current_scenario['scenario']['category']}")
                print(f"  Attack Type: {self.current_scenario['attack']['type']}")
                print(f"  Target: {self.current_scenario['target']['host']}:{self.current_scenario['target']['port']}")
                
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
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        # Validate scenario before execution
        print("Validating scenario...")
        import tempfile
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                json.dump(self.current_scenario, tmp, indent=2)
                tmp_path = tmp.name
            
            from lorawan_sim.domain.attack_scenario.loader import load_attack_scenario
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
        print(f"Executing: {self.current_scenario.get('scenario', {}).get('title', self.current_scenario_name)}")
        print("=" * 60)
        
        try:
            # Configure logging for attack execution
            import logging
            from lorawan_sim.observability.logging.json_logger import configure_logging
            
            log_config = self.current_scenario.get('logging', {})
            log_level = log_config.get('level', 'INFO').upper()
            configure_logging(level=log_level)
            
            logger = logging.getLogger("lorawan_sim")
            
            # Import and run attack
            from lorawan_sim.attacks.runner import AttackRunner
            
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
            uplinks = len(captured.get('uplinks', []))
            downlinks = len(captured.get('downlinks', []))
            print(f"\n{'Captured Packets':-^60}")
            print(f"  Uplinks: {uplinks}")
            print(f"  Downlinks: {downlinks}")
        
        print("\n" + "=" * 60)
    
    def _save_results(self, results: dict[str, Any]) -> None:
        """Save execution results to .results.json file."""
        if not self.current_scenario_path:
            return
        
        # Save to same directory as scenario file
        results_path = self.current_scenario_path.with_suffix('.results.json')
        
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
        if self.current_scenario:
            print(f"Cleared scenario: {self.current_scenario_name}")
        
        self.current_scenario = None
        self.current_scenario_name = None
        self.current_scenario_path = None
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
