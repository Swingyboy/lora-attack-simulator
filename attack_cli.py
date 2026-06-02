#!/usr/bin/env python3
"""
Simplified CLI for running LoRaWAN attacks.

Usage:
    python3 attack_cli.py join-replay
    python3 attack_cli.py join-flood --count 50
    python3 attack_cli.py replay --mode burst
    python3 attack_cli.py --help
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from lorawan_sim.attacks.runner import AttackRunner
from lorawan_sim.domain.attack_scenario.loader import load_attack_scenario
from lorawan_sim.domain.attack_scenario.schema import (
    AttackMeta,
    AttackScenarioConfig,
    DeviceConfig,
    GatewayConfig,
    JoinAbuseConfig,
    LoggingConfig,
    MACCommandConfig,
    ReplayConfig,
)
from lorawan_sim.domain.scenario.schema import (
    ActivationConfig,
    RadioMetadata,
    SemtechUdpConfig,
)


# Default configurations
DEFAULTS = {
    "gateway_eui": "0102030405060708",
    "device_eui": "0011223344556677",
    "join_eui": "0011223344556677",
    "app_key": "00112233445566770011223344556677",
    "host": "127.0.0.1",
    "port": 1700,
    "frequency": 868100000,
    "data_rate": "SF7BW125",
    "rssi": -60,
    "snr": 7.5,
}


def setup_logging():
    """Configure logging to display to console."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        stream=sys.stderr
    )


def create_scenario(attack_type: str, args: argparse.Namespace) -> AttackScenarioConfig:
    """Create attack scenario from CLI arguments."""
    
    # Normalize attack type to match schema expectations
    normalized_type = attack_type
    if attack_type in ("join-replay", "join-flood"):
        normalized_type = "join_abuse"
    
    # Build attack metadata
    attack_meta = AttackMeta(
        name=f"{attack_type}-cli",
        description=f"{attack_type} attack from CLI",
        attack_type=normalized_type,
        timeout_sec=args.timeout,
    )
    
    # Build gateway config
    gateway = GatewayConfig(
        gateway_eui=args.gateway_eui,
        semtech_udp=SemtechUdpConfig(
            host=args.host,
            port=args.port,
            pull_data_interval_sec=5,
        ),
        radio_metadata=RadioMetadata(
            frequency=args.frequency,
            data_rate=args.data_rate,
            rssi=args.rssi,
            snr=args.snr,
        ),
    )
    
    # Build device config
    device = DeviceConfig(
        name=f"cli-device-{attack_type}",
        lorawan_version="1.0.3",
        region="EU868",
        device_class="A",
        activation=ActivationConfig(
            mode="OTAA",
            dev_eui=args.device_eui,
            join_eui=args.join_eui,
            app_key=args.app_key,
        ),
    )
    
    # Build attack-specific config
    replay_config = None
    join_abuse_config = None
    mac_command_config = None
    
    if normalized_type == "replay":
        replay_config = ReplayConfig(
            mode=args.mode,
            delay_sec=args.delay,
            burst_count=args.burst_count,
            burst_interval_sec=args.burst_interval,
        )
    
    elif normalized_type == "join_abuse":
        # Determine mode from CLI attack_type
        if attack_type == "join-flood":
            mode = "flood"
        elif attack_type == "join-replay":
            mode = "replay"
        else:
            mode = args.mode
        
        join_abuse_config = JoinAbuseConfig(
            mode=mode,
            flood_count=args.count,
            flood_interval_sec=args.interval,
            virtual_devices=args.virtual_devices,
        )
    
    elif normalized_type == "mac_abuse":
        mac_command_config = MACCommandConfig(
            command_type=args.command,
            mode=args.mode,
            malformation_type=args.malformation_type,
        )
    
    # Build logging config
    logging_config = LoggingConfig(
        level="info",
        log_phy_payload=True,
        log_semtech_udp=True,
    )
    
    return AttackScenarioConfig(
        attack=attack_meta,
        gateway=gateway,
        device=device,
        replay=replay_config,
        join_abuse=join_abuse_config,
        mac_command=mac_command_config,
        logging=logging_config,
    )


def run_attack(attack_type: str, args: argparse.Namespace):
    """Run the attack."""
    setup_logging()
    
    logger = logging.getLogger("attack_cli")
    
    # Load from JSON if specified
    if args.from_json:
        logger.info(f"Loading scenario from: {args.from_json}")
        scenario = load_attack_scenario(args.from_json)
    else:
        logger.info(f"Creating scenario from CLI arguments...")
        scenario = create_scenario(attack_type, args)
    
    # Display configuration
    print("", file=sys.stderr)
    print("═" * 70, file=sys.stderr)
    print(f"  LoRaWAN Attack: {attack_type.upper()}", file=sys.stderr)
    print("═" * 70, file=sys.stderr)
    print(f"Target NS:     {scenario.gateway.semtech_udp.host}:{scenario.gateway.semtech_udp.port}", file=sys.stderr)
    print(f"Gateway EUI:   {scenario.gateway.gateway_eui}", file=sys.stderr)
    print(f"Device EUI:    {scenario.device.activation.dev_eui}", file=sys.stderr)
    print(f"Join EUI:      {scenario.device.activation.join_eui}", file=sys.stderr)
    
    if attack_type == "replay":
        print(f"Mode:          {scenario.replay.mode}", file=sys.stderr)
        print(f"Burst:         {scenario.replay.burst_count}x", file=sys.stderr)
    elif attack_type in ("join_abuse", "join-replay", "join-flood"):
        print(f"Mode:          {scenario.join_abuse.mode}", file=sys.stderr)
        print(f"Count:         {scenario.join_abuse.flood_count}", file=sys.stderr)
    elif attack_type == "mac_abuse":
        print(f"Command:       {scenario.mac_command.command_type}", file=sys.stderr)
        print(f"Mode:          {scenario.mac_command.mode}", file=sys.stderr)
    
    print("═" * 70, file=sys.stderr)
    print("", file=sys.stderr)
    
    # Run attack
    runner = AttackRunner(logger=logger)
    results = runner.run(scenario)
    
    # Display results
    print("", file=sys.stderr)
    print("═" * 70, file=sys.stderr)
    print("  ATTACK RESULTS", file=sys.stderr)
    print("═" * 70, file=sys.stderr)
    print(f"Success:       {'✓ YES' if results['success'] else '✗ NO'}", file=sys.stderr)
    print(f"Message:       {results['message']}", file=sys.stderr)
    print("", file=sys.stderr)
    print("Metrics:", file=sys.stderr)
    for key, value in results.get('metrics', {}).items():
        print(f"  {key:20s} {value}", file=sys.stderr)
    print(f"\nPackets:       {results.get('captured_packets', 0)} captured", file=sys.stderr)
    print("═" * 70, file=sys.stderr)
    print("", file=sys.stderr)
    
    # Output JSON to stdout for parsing
    print(json.dumps(results, indent=2))
    
    return 0 if results['success'] else 1


def main():
    parser = argparse.ArgumentParser(
        description="LoRaWAN Attack Simulator - Simplified CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Join replay attack with defaults
  python3 attack_cli.py join-replay
  
  # Join flood with custom count
  python3 attack_cli.py join-flood --count 50 --virtual-devices 5
  
  # Replay attack with burst mode
  python3 attack_cli.py replay --mode burst --burst-count 5
  
  # Use existing JSON scenario
  python3 attack_cli.py join-replay --from-json examples/attacks/join-replay.json
  
  # Custom target
  python3 attack_cli.py join-replay --host 192.168.1.100 --port 1700
        """
    )
    
    parser.add_argument(
        "attack_type",
        choices=["replay", "join-replay", "join-flood", "join_abuse", "mac_abuse"],
        help="Type of attack to perform"
    )
    
    parser.add_argument(
        "--from-json",
        help="Load scenario from JSON file (overrides CLI params)"
    )
    
    # Network Server target
    parser.add_argument("--host", default=DEFAULTS["host"], help="NS host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULTS["port"], help="NS port (default: 1700)")
    
    # Device/Gateway IDs
    parser.add_argument("--gateway-eui", default=DEFAULTS["gateway_eui"], help="Gateway EUI")
    parser.add_argument("--device-eui", default=DEFAULTS["device_eui"], help="Device EUI")
    parser.add_argument("--join-eui", default=DEFAULTS["join_eui"], help="Join EUI")
    parser.add_argument("--app-key", default=DEFAULTS["app_key"], help="Application Key")
    
    # Radio parameters
    parser.add_argument("--frequency", type=int, default=DEFAULTS["frequency"], help="Frequency in Hz")
    parser.add_argument("--data-rate", default=DEFAULTS["data_rate"], help="Data rate (e.g., SF7BW125)")
    parser.add_argument("--rssi", type=int, default=DEFAULTS["rssi"], help="RSSI value")
    parser.add_argument("--snr", type=float, default=DEFAULTS["snr"], help="SNR value")
    
    # Attack parameters
    parser.add_argument("--timeout", type=float, default=60.0, help="Attack timeout in seconds")
    
    # Replay attack parameters
    parser.add_argument("--mode", default="immediate", help="Attack mode (replay: immediate/delayed/burst, join: replay/flood)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay in seconds (replay attack)")
    parser.add_argument("--burst-count", type=int, default=1, help="Burst count (replay attack)")
    parser.add_argument("--burst-interval", type=float, default=0.1, help="Burst interval (replay attack)")
    
    # Join abuse parameters
    parser.add_argument("--count", type=int, default=10, help="Join request count (join attacks)")
    parser.add_argument("--interval", type=float, default=0.1, help="Join interval in seconds")
    parser.add_argument("--virtual-devices", type=int, default=1, help="Virtual device count (join flood)")
    
    # MAC abuse parameters
    parser.add_argument("--command", default="link_adr", help="MAC command type")
    parser.add_argument("--malformation-type", help="Malformation type (truncated/oversized/invalid/corrupted)")
    
    args = parser.parse_args()
    
    try:
        return run_attack(args.attack_type, args)
    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\n\nError: {e}", file=sys.stderr)
        logging.exception("Attack failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
