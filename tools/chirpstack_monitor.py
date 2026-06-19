"""ChirpStack network server log monitoring agent.

Streams logs from the ChirpStack Docker container, parses structured entries,
color-highlights by log level, and reports event statistics on exit.

Usage:
    python tools/chirpstack_monitor.py [options]

ChirpStack log format:
    <ISO8601Z>  <LEVEL> <module::path>: <message>  [key=value ...]
"""

from __future__ import annotations

import argparse
import re
import signal
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREY = "\033[90m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_CYAN = "\033[36m"
_MAGENTA = "\033[35m"

_LEVEL_COLOURS = {
    "TRACE": _GREY,
    "DEBUG": _GREY,
    "INFO": _GREEN,
    "WARN": _YELLOW,
    "WARNING": _YELLOW,
    "ERROR": _RED,
    "FATAL": _RED,
}

_LEVEL_ORDER = {"TRACE": 0, "DEBUG": 1, "INFO": 2, "WARN": 3, "WARNING": 3, "ERROR": 4, "FATAL": 5}

# ---------------------------------------------------------------------------
# Log line parser
# ---------------------------------------------------------------------------

# e.g. "2026-06-01T19:41:01.867275Z  INFO chirpstack::uplink: Frame received  dev_eui=1234"
_LOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+"
    r"(?P<module>\S+):\s+"
    r"(?P<rest>.*)$"
)

# key=value pairs in the rest of the message
_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')

# Events we care about for the summary
_EVENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("uplink_received", re.compile(r"uplink|frame received|rx_info", re.IGNORECASE)),
    ("device_join", re.compile(r"join|otaa|join_eui", re.IGNORECASE)),
    ("downlink_sent", re.compile(r"downlink|tx_info", re.IGNORECASE)),
    ("device_activated", re.compile(r"device activated|devaddr", re.IGNORECASE)),
    ("mqtt_connect", re.compile(r"connecting to mqtt|mqtt.*connect", re.IGNORECASE)),
    ("mqtt_disconnect", re.compile(r"mqtt.*disconnect|connection lost", re.IGNORECASE)),
]


@dataclass
class ParsedLine:
    raw: str
    ts: str = ""
    level: str = ""
    module: str = ""
    message: str = ""
    kvs: dict[str, str] = field(default_factory=dict)
    parsed: bool = False


def parse_line(raw: str) -> ParsedLine:
    line = raw.rstrip("\n")
    m = _LOG_RE.match(line)
    if not m:
        return ParsedLine(raw=line)
    kvs = dict(_KV_RE.findall(m.group("rest")))
    return ParsedLine(
        raw=line,
        ts=m.group("ts"),
        level=m.group("level"),
        module=m.group("module"),
        message=m.group("rest"),
        kvs=kvs,
        parsed=True,
    )


# ---------------------------------------------------------------------------
# Stats tracker
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self) -> None:
        self.started_at = datetime.now(tz=timezone.utc)
        self.counts: dict[str, int] = defaultdict(int)
        self.events: dict[str, int] = defaultdict(int)
        self.unparsed = 0
        self.total = 0

    def record(self, line: ParsedLine) -> None:
        self.total += 1
        if not line.parsed:
            self.unparsed += 1
            return
        self.counts[line.level] += 1
        for name, pattern in _EVENT_PATTERNS:
            if pattern.search(line.message):
                self.events[name] += 1

    def print_summary(self, use_color: bool) -> None:
        elapsed = datetime.now(tz=timezone.utc) - self.started_at
        h = int(elapsed.total_seconds() // 3600)
        m = int((elapsed.total_seconds() % 3600) // 60)
        s = int(elapsed.total_seconds() % 60)

        def c(colour: str, text: str) -> str:
            return f"{colour}{text}{_RESET}" if use_color else text

        print(f"\n{c(_BOLD, '─' * 50)}")
        print(c(_BOLD, f"  ChirpStack Monitor — Session Summary"))
        print(c(_BOLD, '─' * 50))
        print(f"  Duration   : {h:02d}h {m:02d}m {s:02d}s")
        print(f"  Total lines: {self.total}")
        print(f"  Unparsed   : {self.unparsed}")
        print()
        print(c(_BOLD, "  Log levels:"))
        for level in ["TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL"]:
            n = self.counts.get(level, 0)
            if n:
                colour = _LEVEL_COLOURS.get(level, "")
                print(f"    {c(colour, f'{level:<8}')} {n}")
        if self.events:
            print()
            print(c(_BOLD, "  Detected events:"))
            for name, count in sorted(self.events.items(), key=lambda x: -x[1]):
                print(f"    {name:<25} {count}")
        print(c(_BOLD, '─' * 50))


# ---------------------------------------------------------------------------
# Container discovery
# ---------------------------------------------------------------------------

def discover_container() -> Optional[str]:
    """Find the chirpstack container by Docker Compose service label."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=com.docker.compose.service=chirpstack",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        name = result.stdout.strip().splitlines()
        return name[0] if name else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

def format_line(line: ParsedLine, use_color: bool, show_module: bool) -> str:
    if not line.parsed:
        return line.raw

    colour = _LEVEL_COLOURS.get(line.level, "") if use_color else ""
    reset = _RESET if use_color else ""
    ts_col = _GREY if use_color else ""

    level_str = f"{colour}{line.level:<7}{reset}"
    ts_str = f"{ts_col}{line.ts}{reset}"
    module_str = f" {_CYAN}{line.module}{reset}" if (use_color and show_module) else (f" {line.module}" if show_module else "")

    return f"{ts_str}  {level_str}{module_str}: {line.message}"


# ---------------------------------------------------------------------------
# Main monitor loop
# ---------------------------------------------------------------------------

def run_monitor(args: argparse.Namespace) -> int:
    container = args.container or discover_container()
    if not container:
        print(
            "ERROR: Could not find ChirpStack container. "
            "Use --container <name> to specify it explicitly.",
            file=sys.stderr,
        )
        return 1

    use_color = args.color and sys.stdout.isatty()
    min_level = _LEVEL_ORDER.get(args.level.upper(), 0)
    grep_re = re.compile(args.grep, re.IGNORECASE) if args.grep else None

    stats = Stats()

    def _on_exit(_sig: int, _frame: object) -> None:
        stats.print_summary(use_color)
        sys.exit(0)

    signal.signal(signal.SIGINT, _on_exit)
    signal.signal(signal.SIGTERM, _on_exit)

    if use_color:
        print(f"{_BOLD}{_CYAN}Monitoring ChirpStack container: {container}{_RESET}")
        print(f"{_GREY}Press Ctrl+C to stop and show summary{_RESET}\n")
    else:
        print(f"Monitoring ChirpStack container: {container}")
        print("Press Ctrl+C to stop and show summary\n")

    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "logs", "-f", container],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                errors="replace",
            )
        except FileNotFoundError:
            print("ERROR: 'docker' command not found in PATH.", file=sys.stderr)
            return 1

        try:
            for raw in proc.stdout:  # type: ignore[union-attr]
                line = parse_line(raw)
                stats.record(line)

                # Level filter
                if line.parsed:
                    if _LEVEL_ORDER.get(line.level, 0) < min_level:
                        continue

                # Grep filter
                if grep_re and not grep_re.search(line.raw):
                    continue

                print(format_line(line, use_color, show_module=not args.hide_module))

            # Process exited
            proc.wait()
            if proc.returncode != 0:
                print(
                    f"\nERROR: 'docker logs' exited with code {proc.returncode}. "
                    "Container may have stopped.",
                    file=sys.stderr,
                )
                if not args.reconnect:
                    return proc.returncode

            if args.reconnect:
                if use_color:
                    print(f"{_YELLOW}Container stream ended, reconnecting...{_RESET}")
                else:
                    print("Container stream ended, reconnecting...")
                import time
                time.sleep(2)
            else:
                stats.print_summary(use_color)
                return 0

        except BrokenPipeError:
            break
        finally:
            if proc.poll() is None:
                proc.terminate()

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chirpstack-monitor",
        description="Real-time ChirpStack network server log monitor.",
    )
    parser.add_argument(
        "--container",
        metavar="NAME",
        default=None,
        help="Docker container name/ID. Auto-discovered if omitted.",
    )
    parser.add_argument(
        "--level",
        metavar="LEVEL",
        default="TRACE",
        choices=["TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL",
                 "trace", "debug", "info", "warn", "warning", "error", "fatal"],
        help="Minimum log level to display (default: TRACE, show all).",
    )
    parser.add_argument(
        "--grep",
        metavar="PATTERN",
        default=None,
        help="Only show lines matching this regex pattern (case-insensitive).",
    )
    parser.add_argument(
        "--no-color",
        dest="color",
        action="store_false",
        default=True,
        help="Disable ANSI colour output.",
    )
    parser.add_argument(
        "--hide-module",
        action="store_true",
        default=False,
        help="Hide the Rust module path from output.",
    )
    parser.add_argument(
        "--reconnect",
        action="store_true",
        default=False,
        help="Reconnect automatically if the container restarts.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run_monitor(args))


if __name__ == "__main__":
    main()
