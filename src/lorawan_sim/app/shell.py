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
        
        print(f"\nCurrent scenario: {self.current_scenario_name}")
        print("Options display not yet implemented (Phase 3)")
    
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
        
        Example:
            set target.host 192.168.1.10
            set attack.config.replay_count 5
        """
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        if not args:
            print("Usage: set <parameter> <value>")
            return
        
        print("Parameter modification not yet implemented (Phase 3)")
    
    def do_reset(self, args: str) -> None:
        """Reset parameters to default values.
        
        Usage:
            reset              - Reset all parameters
            reset <parameter>  - Reset specific parameter
        """
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        print("Parameter reset not yet implemented (Phase 3)")
    
    def do_validate(self, args: str) -> None:
        """Validate the current scenario configuration.
        
        Usage:
            validate
        """
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        print("Scenario validation not yet implemented (Phase 3)")
    
    def do_run(self, args: str) -> None:
        """Execute the current scenario.
        
        Usage:
            run
        """
        if not self.current_scenario:
            print("No scenario loaded. Use 'use <scenario>' first.")
            return
        
        print("Attack execution not yet implemented (Phase 4)")
    
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
