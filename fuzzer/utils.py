"""
utils.py — Shared helper utilities for proto-fuzzer.

Provides: hex dump printer, random MAC/IP generators, checksum corruptor,
and structured logging setup with colorlog.
"""

import os
import random
import struct
import logging
import socket

import colorlog


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logger(name: str = "proto-fuzzer", level: int = logging.DEBUG) -> logging.Logger:
    """Return a colorised logger for the given name."""
    handler = colorlog.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s [%(levelname)-8s]%(reset)s %(message)s",
            datefmt="%H:%M:%S",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        )
    )
    logger = colorlog.getLogger(name)
    if not logger.handlers:
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


logger = setup_logger()


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def require_root() -> None:
    """Abort with a clear message when the process does not have root privileges."""
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError(
                "This tool requires Administrator privileges on Windows. "
                "Run your terminal as Administrator."
            )
    else:
        if os.geteuid() != 0:
            raise PermissionError(
                "This tool requires root privileges. Please run with sudo."
            )


# ---------------------------------------------------------------------------
# Random address generators
# ---------------------------------------------------------------------------

def random_mac() -> str:
    """Return a random unicast MAC address string (colon-separated)."""
    octets = [random.randint(0x00, 0xFF) for _ in range(6)]
    # Ensure the first octet is unicast (LSB = 0) and globally unique (bit 1 = 0)
    octets[0] &= 0xFC
    return ":".join(f"{b:02x}" for b in octets)


def random_ip() -> str:
    """Return a random dotted-decimal IPv4 address string."""
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def random_bytes(length: int) -> bytes:
    """Return *length* random bytes."""
    return bytes(random.randint(0, 255) for _ in range(length))


def boundary_byte_values() -> list:
    """Return a list of interesting boundary byte values."""
    return [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]


def boundary_word_values() -> list:
    """Return a list of interesting 16-bit boundary values."""
    return [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]


# ---------------------------------------------------------------------------
# Checksum utilities
# ---------------------------------------------------------------------------

def internet_checksum(data: bytes) -> int:
    """Compute RFC-1071 Internet checksum over *data*."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def corrupt_checksum(original: int) -> int:
    """Return a deliberately wrong checksum by flipping all bits."""
    return (~original) & 0xFFFF


def corrupt_bytes(data: bytes, num_flips: int = 1) -> bytes:
    """Flip *num_flips* random bits within *data* and return the result."""
    if not data:
        return data
    ba = bytearray(data)
    for _ in range(num_flips):
        idx = random.randint(0, len(ba) - 1)
        bit = random.randint(0, 7)
        ba[idx] ^= (1 << bit)
    return bytes(ba)


# ---------------------------------------------------------------------------
# Hex dump
# ---------------------------------------------------------------------------

def hex_dump(data: bytes, indent: int = 0) -> str:
    """Return a formatted hex dump string similar to xxd/Wireshark style."""
    lines = []
    prefix = " " * indent
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)


def bytes_to_hex(data: bytes) -> str:
    """Return space-separated uppercase hex string."""
    return data.hex(" ").upper()


# ---------------------------------------------------------------------------
# Network helper
# ---------------------------------------------------------------------------

def iface_mac(iface: str) -> str:
    """
    Attempt to retrieve the MAC address of *iface*.
    Falls back to a random MAC if the interface cannot be queried.
    """
    try:
        import netifaces  # optional dependency
        addrs = netifaces.ifaddresses(iface)
        mac = addrs[netifaces.AF_LINK][0]["addr"]
        return mac
    except Exception:
        return random_mac()


def iface_ip(iface: str) -> str:
    """
    Attempt to retrieve the IPv4 address of *iface*.
    Falls back to '127.0.0.1' if the interface cannot be queried.
    """
    try:
        import netifaces  # optional dependency
        addrs = netifaces.ifaddresses(iface)
        ip = addrs[netifaces.AF_INET][0]["addr"]
        return ip
    except Exception:
        return "127.0.0.1"
