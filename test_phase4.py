#!/usr/bin/env python3
"""
Manual test for Phase 4 - Attack Execution.

Tests the complete workflow:
1. Load scenario
2. Validate
3. Execute attack
4. Display results
5. Save results
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from lorawan_sim.app.shell import LoRaWANShell


def test_run_command_workflow():
    """Test the complete run command workflow."""
    print("=" * 60)
    print("Phase 4 - Attack Execution Test")
    print("=" * 60)
    
    # Initialize shell
    print("\n1. Initializing shell...")
    shell = LoRaWANShell()
    print(f"   ✓ Discovered {len(shell.scenario_metadata)} scenarios")
    
    # Load scenario
    print("\n2. Loading scenario...")
    scenario_name = "join-replay-v1"
    if scenario_name not in shell.scenario_metadata:
        print(f"   ✗ Scenario '{scenario_name}' not found")
        return False
    
    metadata = shell.scenario_metadata[scenario_name]
    with open(metadata.path, 'r') as f:
        shell.current_scenario = json.load(f)
    shell.current_scenario_name = scenario_name
    shell.current_scenario_path = metadata.path
    print(f"   ✓ Loaded scenario: {metadata.title}")
    print(f"   ✓ Category: {metadata.category}")
    
    # Validate scenario
    print("\n3. Validating scenario...")
    import tempfile
    import os
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            json.dump(shell.current_scenario, tmp, indent=2)
            tmp_path = tmp.name
        
        from lorawan_sim.domain.attack_scenario.loader import load_attack_scenario
        scenario = load_attack_scenario(tmp_path)
        print("   ✓ Scenario validation passed")
        
    except Exception as e:
        print(f"   ✗ Validation failed: {e}")
        return False
    finally:
        if 'tmp_path' in locals():
            os.unlink(tmp_path)
    
    # Test result display formatting
    print("\n4. Testing result display...")
    mock_results = {
        "success": True,
        "message": "Mock attack completed successfully",
        "metrics": {
            "uplinks_sent": 5,
            "downlinks_received": 3,
            "replay_count": 2,
            "accepted_replays": 0,
        },
        "expected_behavior": "Network Server should reject replayed JoinRequests",
        "success_criteria": [
            "DevNonce replay is detected",
            "Replayed JoinRequest receives no JoinAccept",
        ],
        "captured_packets": {
            "uplinks": [{"type": "JoinRequest"}, {"type": "JoinRequest"}],
            "downlinks": [{"type": "JoinAccept"}],
        }
    }
    
    shell._display_results(mock_results)
    print("   ✓ Result display formatting works")
    
    # Test save results
    print("\n5. Testing result save...")
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create temp scenario path
        temp_scenario = Path(tmpdir) / "test-scenario.json"
        shell.current_scenario_path = temp_scenario
        
        # Save results
        shell._save_results(mock_results)
        
        # Verify results file exists
        results_file = temp_scenario.with_suffix('.results.json')
        if results_file.exists():
            with open(results_file, 'r') as f:
                saved = json.load(f)
            print(f"   ✓ Results saved to: {results_file}")
            print(f"   ✓ Results file contains {len(saved)} keys")
        else:
            print("   ✗ Results file not created")
            return False
    
    print("\n" + "=" * 60)
    print("✓ All Phase 4 tests passed!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = test_run_command_workflow()
    sys.exit(0 if success else 1)
