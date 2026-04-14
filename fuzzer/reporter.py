"""
reporter.py — Collects per-packet fuzzing results and writes structured reports.

JSON report schema:
{
  "session": {
    "protocol": "icmp",
    "mode": "boundary",
    "seed": 42,
    "total_packets": 100,
    "crashes_detected": 3,
    "timeouts": 12
  },
  "packets": [
    {
      "index": 1,
      "payload_hex": "...",
      "response": "timeout",
      "crash": false,
      "classification": "no_response"
    }
  ]
}
"""

import json
import os
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from fuzzer.utils import setup_logger

logger = setup_logger(__name__)


# ---------------------------------------------------------------------------
# Classification constants
# ---------------------------------------------------------------------------

class Classification:
    TIMEOUT = "timeout"
    RST = "rst"
    MALFORMED_RESPONSE = "malformed_response"
    NO_RESPONSE = "no_response"
    ICMP_ERROR = "icmp_error"
    VALID_RESPONSE = "valid_response"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PacketResult:
    index: int
    payload_hex: str
    response: str                       # raw description of what was received
    crash: bool = False
    classification: str = Classification.UNKNOWN
    extra: dict = field(default_factory=dict)   # optional extra metadata


@dataclass
class SessionInfo:
    protocol: str
    mode: str
    seed: Optional[int]
    total_packets: int = 0
    crashes_detected: int = 0
    timeouts: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------

class Reporter:
    """
    Accumulates :class:`PacketResult` objects and writes:
    * A JSON report at *output_path*
    * A human-readable ``summary.txt`` in the same directory
    """

    def __init__(
        self,
        protocol: str,
        mode: str,
        seed: Optional[int],
        output_path: str,
    ):
        self.session = SessionInfo(
            protocol=protocol,
            mode=mode,
            seed=seed,
        )
        self.output_path = output_path
        self.packets: list[PacketResult] = []

    # ------------------------------------------------------------------
    # Recording results
    # ------------------------------------------------------------------

    def record(
        self,
        index: int,
        payload: bytes,
        response: str,
        crash: bool = False,
        classification: str = Classification.UNKNOWN,
        extra: Optional[dict] = None,
    ) -> None:
        """Record the outcome of a single fuzzed packet."""
        result = PacketResult(
            index=index,
            payload_hex=payload.hex(),
            response=response,
            crash=crash,
            classification=classification,
            extra=extra or {},
        )
        self.packets.append(result)
        self.session.total_packets += 1
        if crash:
            self.session.crashes_detected += 1
        if classification in (Classification.TIMEOUT, Classification.NO_RESPONSE):
            self.session.timeouts += 1

        logger.debug(
            "[%04d] crash=%s class=%s response=%s",
            index,
            crash,
            classification,
            response[:80],
        )

    # ------------------------------------------------------------------
    # Output generation
    # ------------------------------------------------------------------

    def _build_report_dict(self) -> dict:
        """Build the canonical JSON-serialisable report dictionary."""
        return {
            "session": {
                "protocol": self.session.protocol,
                "mode": self.session.mode,
                "seed": self.session.seed,
                "total_packets": self.session.total_packets,
                "crashes_detected": self.session.crashes_detected,
                "timeouts": self.session.timeouts,
                "timestamp": self.session.timestamp,
            },
            "packets": [
                {
                    "index": p.index,
                    "payload_hex": p.payload_hex,
                    "response": p.response,
                    "crash": p.crash,
                    "classification": p.classification,
                    **({"extra": p.extra} if p.extra else {}),
                }
                for p in self.packets
            ],
        }

    def write_json(self) -> None:
        """Write the JSON report to *output_path*."""
        os.makedirs(os.path.dirname(os.path.abspath(self.output_path)), exist_ok=True)
        report = self._build_report_dict()
        with open(self.output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        logger.info("JSON report written → %s", self.output_path)

    def write_summary(self) -> str:
        """Write summary.txt alongside the JSON report; return the path."""
        summary_path = os.path.join(
            os.path.dirname(os.path.abspath(self.output_path)), "summary.txt"
        )
        crash_rate = (
            self.session.crashes_detected / self.session.total_packets * 100
            if self.session.total_packets
            else 0.0
        )
        timeout_rate = (
            self.session.timeouts / self.session.total_packets * 100
            if self.session.total_packets
            else 0.0
        )

        # Breakdown by classification
        class_counts: dict[str, int] = {}
        for p in self.packets:
            class_counts[p.classification] = class_counts.get(p.classification, 0) + 1

        lines = [
            "=" * 72,
            "  marvell-proto-fuzzer  —  Session Report",
            "=" * 72,
            f"  Protocol       : {self.session.protocol.upper()}",
            f"  Mode           : {self.session.mode}",
            f"  Seed           : {self.session.seed}",
            f"  Timestamp      : {self.session.timestamp}",
            "-" * 72,
            f"  Total packets  : {self.session.total_packets}",
            f"  Crashes        : {self.session.crashes_detected} ({crash_rate:.1f}%)",
            f"  Timeouts       : {self.session.timeouts} ({timeout_rate:.1f}%)",
            "-" * 72,
            "  Classification breakdown:",
        ]
        for cls, count in sorted(class_counts.items()):
            lines.append(f"    {cls:<30} {count:>6}")
        lines += [
            "=" * 72,
            "",
            "Crashed packet indices:",
        ]
        crash_indices = [str(p.index) for p in self.packets if p.crash]
        if crash_indices:
            lines.append("  " + ", ".join(crash_indices))
        else:
            lines.append("  None detected.")
        lines.append("")

        with open(summary_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        logger.info("Summary written → %s", summary_path)
        return summary_path

    def finalise(self) -> None:
        """Write both the JSON report and the summary file."""
        self.write_json()
        self.write_summary()

    # ------------------------------------------------------------------
    # Accessor helpers (used by tests)
    # ------------------------------------------------------------------

    def get_report(self) -> dict:
        """Return the report as a Python dict (for testing)."""
        return self._build_report_dict()

    def crash_count(self) -> int:
        return self.session.crashes_detected

    def timeout_count(self) -> int:
        return self.session.timeouts
