"""Educational byte-wise XOR helpers used by the simulator."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class XorResult:
    """Detailed representation of a byte-wise XOR operation."""

    plaintext: bytes
    key: bytes
    ciphertext: bytes

    @property
    def plaintext_bits(self) -> str:
        return format_bytes_binary(self.plaintext)

    @property
    def key_bits(self) -> str:
        return format_bytes_binary(self.key)

    @property
    def ciphertext_bits(self) -> str:
        return format_bytes_binary(self.ciphertext)

    @property
    def plaintext_hex(self) -> str:
        return self.plaintext.hex(" ").upper()

    @property
    def key_hex(self) -> str:
        return self.key.hex(" ").upper()

    @property
    def ciphertext_hex(self) -> str:
        return self.ciphertext.hex(" ").upper()

    @property
    def plaintext_ascii(self) -> str:
        return printable_ascii(self.plaintext)

    @property
    def key_ascii(self) -> str:
        return printable_ascii(self.key)

    @property
    def ciphertext_ascii(self) -> str:
        return printable_ascii(self.ciphertext)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """Return ``left XOR right``; both operands must have equal length."""

    if len(left) != len(right):
        raise ValueError("XOR membutuhkan operand dengan panjang byte yang sama.")
    return bytes(a ^ b for a, b in zip(left, right))


def format_bytes_binary(value: bytes) -> str:
    """Format bytes as space-separated 8-bit binary tokens."""

    return " ".join(f"{byte:08b}" for byte in value)


def printable_ascii(value: bytes) -> str:
    """Render printable ASCII and replace control/non-ASCII bytes with a dot."""

    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in value)


def parse_binary_tokens(value: str) -> bytes:
    """Parse space/comma-separated 8-bit tokens into bytes."""

    tokens = value.replace(",", " ").split()
    if not tokens:
        raise ValueError("Masukkan setidaknya satu token biner 8-bit.")
    if any(len(token) != 8 or any(bit not in "01" for bit in token) for token in tokens):
        raise ValueError("Setiap token harus tepat 8 bit, misalnya 10110010.")
    return bytes(int(token, 2) for token in tokens)


def xor_detail(plaintext: bytes, key: bytes) -> XorResult:
    """Compute XOR and return byte, binary, hex, and ASCII representations."""

    return XorResult(plaintext, key, xor_bytes(plaintext, key))


def journal_preset() -> XorResult:
    """Return the journal example: 10110010 XOR 01101001 = 11011011."""

    return xor_detail(bytes([0b10110010]), bytes([0b01101001]))
