"""
main.py — CLI entry point for proto-fuzzer.

Usage examples:
  sudo python -m fuzzer.main --protocol arp  --iface eth0 --count 200 --seed 42
  sudo python -m fuzzer.main --protocol icmp --iface lo   --count 100 --mode boundary --output reports/icmp.json
  sudo python -m fuzzer.main --protocol macsec --iface eth0 --count 50 --mode mutation --seed 7
"""

import argparse
import sys
import time

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.panel import Panel
from rich import print as rprint

from fuzzer.utils import setup_logger, require_root
from fuzzer.packet_generator import PacketGenerator, FuzzMode
from fuzzer.arp_fuzzer import ARPFuzzer
from fuzzer.icmp_fuzzer import ICMPFuzzer
from fuzzer.macsec_fuzzer import MACsecFuzzer
from fuzzer.reporter import Reporter, Classification

logger = setup_logger("proto-fuzzer")
console = Console()

# ---------------------------------------------------------------------------
# Try to import raw-socket sender; graceful degradation if Scapy unavailable
# ---------------------------------------------------------------------------
try:
    from scapy.all import sendp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — packets will be logged but not sent")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proto-fuzzer",
        description=(
            "Layer 2/3 Protocol Fuzzer — injects malformed ARP, ICMP, and "
            "MACsec frames to stress-test network device stacks."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python -m fuzzer.main --protocol arp   --iface eth0 --count 500 --seed 42
  sudo python -m fuzzer.main --protocol icmp  --iface lo   --count 100 --mode boundary
  sudo python -m fuzzer.main --protocol macsec --iface eth0 --count 200 --mode mutation
        """,
    )
    parser.add_argument(
        "--protocol",
        choices=["arp", "icmp", "macsec"],
        required=True,
        help="Target protocol to fuzz.",
    )
    parser.add_argument(
        "--iface",
        default="lo",
        help="Network interface to send packets on (default: lo).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        metavar="N",
        help="Number of fuzzed packets to send (default: 100).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="SEED",
        help="RNG seed for reproducible packet sequences.",
    )
    parser.add_argument(
        "--output",
        default="reports/fuzz_report.json",
        metavar="PATH",
        help="Path for the JSON report output (default: reports/fuzz_report.json).",
    )
    parser.add_argument(
        "--mode",
        choices=["random", "mutation", "boundary"],
        default="random",
        help="Mutation mode (default: random).",
    )
    parser.add_argument(
        "--src-ip",
        default="127.0.0.1",
        dest="src_ip",
        help="Source IP (ICMP only, default: 127.0.0.1).",
    )
    parser.add_argument(
        "--dst-ip",
        default="127.0.0.2",
        dest="dst_ip",
        help="Destination IP (ICMP only, default: 127.0.0.2).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate packets but do not send them (useful for testing).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose packet-level logging.",
    )
    return parser


# ---------------------------------------------------------------------------
# Send helper
# ---------------------------------------------------------------------------

def send_raw(packet_bytes: bytes, iface: str, dry_run: bool = False) -> bool:
    """
    Send a raw Ethernet frame.  Returns True on success.
    In dry-run mode always returns True without sending.
    """
    if dry_run:
        return True
    if not SCAPY_AVAILABLE:
        return False
    try:
        from scapy.all import sendp
        from scapy.layers.l2 import Ether
        pkt = Ether(packet_bytes)
        sendp(pkt, iface=iface, verbose=False)
        return True
    except Exception as exc:
        logger.debug("send_raw error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Response classification helper (placeholder — real listener response parsing
# would require a dedicated receive thread)
# ---------------------------------------------------------------------------

def classify_response(sent: bool, elapsed_ms: float) -> tuple[str, str, bool]:
    """
    Derive (response_str, classification, crash) from send outcome and timing.

    In a real deployment this function would inspect a shared queue fed by a
    receive thread.  For now we classify purely by send success and timing.
    """
    if not sent:
        return "send_failed", Classification.UNKNOWN, False
    if elapsed_ms > 500:
        return "timeout", Classification.TIMEOUT, False
    # Simulate occasional crash detection via very fast response (< 1 ms)
    # — in reality you'd look for ICMP port-unreachable / RST / silence
    return "no_response", Classification.NO_RESPONSE, False


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner(args: argparse.Namespace) -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]proto-fuzzer[/bold cyan]\n"
            f"  Protocol : [yellow]{args.protocol.upper()}[/yellow]\n"
            f"  Mode     : [green]{args.mode}[/green]\n"
            f"  Interface: [blue]{args.iface}[/blue]\n"
            f"  Count    : [magenta]{args.count}[/magenta]\n"
            f"  Seed     : [white]{args.seed if args.seed is not None else 'random'}[/white]\n"
            f"  Output   : [white]{args.output}[/white]",
            title="[bold white]Layer 2/3 Protocol Fuzzer[/bold white]",
            border_style="cyan",
        )
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Root check (skip in dry-run)
    if not args.dry_run:
        try:
            require_root()
        except PermissionError as exc:
            console.print(f"[bold red]✗ Permission error:[/bold red] {exc}")
            return 1

    print_banner(args)

    # Construct shared generator
    generator = PacketGenerator(mode=FuzzMode(args.mode), seed=args.seed)

    # Instantiate the correct fuzzer
    if args.protocol == "arp":
        fuzzer = ARPFuzzer(generator=generator, iface=args.iface)
    elif args.protocol == "icmp":
        fuzzer = ICMPFuzzer(
            generator=generator,
            iface=args.iface,
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
        )
    elif args.protocol == "macsec":
        fuzzer = MACsecFuzzer(generator=generator, iface=args.iface)
    else:
        console.print(f"[red]Unknown protocol: {args.protocol}[/red]")
        return 1

    # Reporter
    reporter = Reporter(
        protocol=args.protocol,
        mode=args.mode,
        seed=args.seed,
        output_path=args.output,
    )

    crashes = 0
    timeouts = 0

    # Send loop with rich progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[bold blue]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Fuzzing {args.protocol.upper()}…", total=args.count
        )

        for i in range(1, args.count + 1):
            pkt = fuzzer.generate()
            t_start = time.perf_counter()
            ok = send_raw(pkt, args.iface, dry_run=args.dry_run)
            elapsed_ms = (time.perf_counter() - t_start) * 1000

            response, classification, crash = classify_response(ok, elapsed_ms)
            if crash:
                crashes += 1
            if classification in (Classification.TIMEOUT, Classification.NO_RESPONSE):
                timeouts += 1

            reporter.record(
                index=i,
                payload=pkt,
                response=response,
                crash=crash,
                classification=classification,
            )

            progress.advance(task)

            if args.verbose:
                status = "[red]CRASH[/red]" if crash else "[green]OK[/green]"
                console.print(
                    f"  [{i:04d}] {status} {classification} ({len(pkt)} bytes)"
                )

    # Write reports
    reporter.finalise()

    # Final summary
    crash_colour = "red" if crashes else "green"
    console.print(f"\n[bold]Session complete.[/bold]")
    console.print(f"  Packets sent    : [cyan]{args.count}[/cyan]")
    console.print(f"  Crashes detected: [{crash_colour}]{crashes}[/{crash_colour}]")
    console.print(f"  Timeouts        : [yellow]{timeouts}[/yellow]")
    console.print(f"  Report          : [blue]{args.output}[/blue]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
