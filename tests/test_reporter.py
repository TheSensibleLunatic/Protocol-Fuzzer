"""
test_reporter.py — Unit tests for the Reporter module.

Tests:
- JSON schema of output report matches specification exactly
- summary.txt line count is non-zero and contains expected headings
- crash flag toggling increments crash counter correctly
- timeout classification increments timeout counter
- get_report() returns a consistent dict
- finalise() writes both files to disk
"""

import json
import os
import pytest

from fuzzer.reporter import Reporter, Classification, PacketResult


# ---------------------------------------------------------------------------
# Fixtures (use the shared reporter from conftest.py)
# ---------------------------------------------------------------------------

DUMMY_PAYLOAD = b"\xDE\xAD\xBE\xEF\x00\x01\x02\x03"


# ---------------------------------------------------------------------------
# JSON schema
# ---------------------------------------------------------------------------

class TestReporterJSONSchema:
    def test_empty_session_schema(self, reporter):
        """An empty reporter must still produce a fully valid JSON schema."""
        report = reporter.get_report()
        assert "session" in report
        assert "packets" in report
        session = report["session"]
        for key in ("protocol", "mode", "seed", "total_packets",
                    "crashes_detected", "timeouts"):
            assert key in session, f"Missing key: {key}"

    def test_session_values(self, reporter):
        """Session fields must reflect reporter constructor arguments."""
        report = reporter.get_report()["session"]
        assert report["protocol"] == "arp"
        assert report["mode"] == "random"
        assert report["seed"] == 42
        assert report["total_packets"] == 0
        assert report["crashes_detected"] == 0
        assert report["timeouts"] == 0

    def test_packet_entry_schema(self, reporter):
        """Each packet entry must have the required fields."""
        reporter.record(
            index=1,
            payload=DUMMY_PAYLOAD,
            response="timeout",
            crash=False,
            classification=Classification.TIMEOUT,
        )
        report = reporter.get_report()
        assert len(report["packets"]) == 1
        pkt = report["packets"][0]
        for key in ("index", "payload_hex", "response", "crash", "classification"):
            assert key in pkt, f"Missing packet key: {key}"

    def test_payload_hex_encoding(self, reporter):
        """payload_hex must be the hex representation of the payload bytes."""
        reporter.record(1, DUMMY_PAYLOAD, "no_response", False, Classification.NO_RESPONSE)
        report = reporter.get_report()
        assert report["packets"][0]["payload_hex"] == DUMMY_PAYLOAD.hex()

    def test_json_serialisable(self, reporter, tmp_report_dir):
        """write_json() must write valid JSON to disk."""
        reporter.record(1, DUMMY_PAYLOAD, "no_response", False, Classification.NO_RESPONSE)
        reporter.write_json()
        path = os.path.join(tmp_report_dir, "fuzz_report.json")
        assert os.path.isfile(path), "JSON report file must exist"
        with open(path, "r") as fh:
            loaded = json.load(fh)
        assert "session" in loaded
        assert "packets" in loaded

    def test_json_matches_schema_exactly(self, reporter, tmp_report_dir):
        """Written JSON must exactly conform to the documented schema."""
        reporter.record(
            index=1,
            payload=b"\xAB\xCD",
            response="no_response",
            crash=False,
            classification=Classification.NO_RESPONSE,
        )
        reporter.write_json()
        path = os.path.join(tmp_report_dir, "fuzz_report.json")
        with open(path) as fh:
            data = json.load(fh)
        s = data["session"]
        assert isinstance(s["total_packets"], int)
        assert isinstance(s["crashes_detected"], int)
        assert isinstance(s["timeouts"], int)
        p = data["packets"][0]
        assert isinstance(p["index"], int)
        assert isinstance(p["payload_hex"], str)
        assert isinstance(p["crash"], bool)


# ---------------------------------------------------------------------------
# Crash flag
# ---------------------------------------------------------------------------

class TestReporterCrashFlag:
    def test_crash_increments_counter(self, reporter):
        """Recording a crash must increment crashes_detected."""
        reporter.record(1, DUMMY_PAYLOAD, "crash!", True, Classification.UNKNOWN)
        assert reporter.crash_count() == 1

    def test_no_crash_does_not_increment(self, reporter):
        """Recording a non-crash must not increment crashes_detected."""
        reporter.record(1, DUMMY_PAYLOAD, "ok", False, Classification.NO_RESPONSE)
        assert reporter.crash_count() == 0

    def test_multiple_crashes(self, reporter):
        """Multiple crash records must be accurately counted."""
        for i in range(5):
            reporter.record(i, DUMMY_PAYLOAD, "crash!", True, Classification.UNKNOWN)
        reporter.record(6, DUMMY_PAYLOAD, "ok", False, Classification.NO_RESPONSE)
        assert reporter.crash_count() == 5

    def test_crash_flag_in_json(self, reporter):
        """Crash flag must appear correctly in JSON output."""
        reporter.record(1, DUMMY_PAYLOAD, "crash!", True, Classification.UNKNOWN)
        pkt = reporter.get_report()["packets"][0]
        assert pkt["crash"] is True


# ---------------------------------------------------------------------------
# Timeout classification
# ---------------------------------------------------------------------------

class TestReporterTimeout:
    def test_timeout_classification_increments(self, reporter):
        """Timeout classification must increment timeout counter."""
        reporter.record(1, DUMMY_PAYLOAD, "timeout", False, Classification.TIMEOUT)
        assert reporter.timeout_count() == 1

    def test_no_response_also_counted(self, reporter):
        """NO_RESPONSE classification must also increment timeout counter."""
        reporter.record(1, DUMMY_PAYLOAD, "no_response", False, Classification.NO_RESPONSE)
        assert reporter.timeout_count() == 1

    def test_valid_response_not_counted(self, reporter):
        """VALID_RESPONSE must not increment timeout counter."""
        reporter.record(1, DUMMY_PAYLOAD, "pong", False, Classification.VALID_RESPONSE)
        assert reporter.timeout_count() == 0


# ---------------------------------------------------------------------------
# summary.txt
# ---------------------------------------------------------------------------

class TestReporterSummary:
    def test_summary_written(self, reporter, tmp_report_dir):
        """write_summary() must create summary.txt."""
        reporter.record(1, DUMMY_PAYLOAD, "no_response", False, Classification.NO_RESPONSE)
        path = reporter.write_summary()
        assert os.path.isfile(path), "summary.txt must be created"

    def test_summary_non_empty(self, reporter):
        """summary.txt must contain at least 10 lines."""
        reporter.record(1, DUMMY_PAYLOAD, "no_response", False, Classification.NO_RESPONSE)
        path = reporter.write_summary()
        with open(path) as fh:
            lines = fh.readlines()
        assert len(lines) >= 10, "summary.txt must have at least 10 lines"

    def test_summary_contains_protocol(self, reporter):
        """summary.txt must mention the protocol name."""
        reporter.record(1, DUMMY_PAYLOAD, "no_response", False, Classification.NO_RESPONSE)
        path = reporter.write_summary()
        content = open(path).read()
        assert "ARP" in content.upper(), "summary.txt must mention the protocol"

    def test_summary_contains_packet_count(self, reporter):
        """summary.txt must show total packet count."""
        for i in range(1, 4):
            reporter.record(i, DUMMY_PAYLOAD, "no_response", False, Classification.NO_RESPONSE)
        path = reporter.write_summary()
        content = open(path).read()
        assert "3" in content, "summary.txt must show correct packet count"


# ---------------------------------------------------------------------------
# finalise()
# ---------------------------------------------------------------------------

class TestReporterFinalise:
    def test_finalise_creates_both_files(self, reporter, tmp_report_dir):
        """finalise() must create both the JSON report and summary.txt."""
        reporter.record(1, DUMMY_PAYLOAD, "ok", False, Classification.VALID_RESPONSE)
        reporter.finalise()
        assert os.path.isfile(os.path.join(tmp_report_dir, "fuzz_report.json"))
        assert os.path.isfile(os.path.join(tmp_report_dir, "summary.txt"))

    def test_total_packets_accurate(self, reporter):
        """total_packets must equal the number of record() calls."""
        for i in range(7):
            reporter.record(i + 1, DUMMY_PAYLOAD, "ok", False, Classification.VALID_RESPONSE)
        assert reporter.get_report()["session"]["total_packets"] == 7
