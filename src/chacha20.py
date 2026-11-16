"""Pure-Python ChaCha20 implementation following RFC 8439."""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass

MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 64
KEY_SIZE = 32
NONCE_SIZE = 12
MAX_COUNTER = MASK32
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _validate_key_nonce(key: bytes, nonce: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError("Key ChaCha20 harus berukuran tepat 32 byte.")
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce ChaCha20 harus berukuran tepat 12 byte.")


def _validate_counter(counter: int) -> None:
    if not 0 <= counter <= MAX_COUNTER:
        raise ValueError("Block counter harus berada pada rentang 0 sampai 2^32-1.")


def rotate_left_32(value: int, shift: int) -> int:
    """Rotate a 32-bit integer left."""

    return ((value << shift) | (value >> (32 - shift))) & MASK32


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    """Apply one ChaCha quarter-round to four positions in ``state``."""

    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = rotate_left_32(state[d], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = rotate_left_32(state[b], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = rotate_left_32(state[d], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = rotate_left_32(state[b], 7)


def _words_from_bytes(value: bytes) -> list[int]:
    return [int.from_bytes(value[index : index + 4], "little") for index in range(0, len(value), 4)]


def initial_state(key: bytes, nonce: bytes, counter: int = 0) -> list[int]:
    """Build the 16-word ChaCha20 initial state."""

    _validate_key_nonce(key, nonce)
    _validate_counter(counter)
    return [*CONSTANTS, *_words_from_bytes(key), counter, *_words_from_bytes(nonce)]


def chacha20_block(key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    """Generate one 64-byte ChaCha20 block."""

    state = initial_state(key, nonce, counter)
    working = state.copy()
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    return b"".join(((word + original) & MASK32).to_bytes(4, "little") for word, original in zip(working, state))


def state_as_hex(state: list[int]) -> list[list[str]]:
    """Return a 4x4 matrix of eight-digit hexadecimal words."""

    if len(state) != 16:
        raise ValueError("State ChaCha20 harus berisi 16 word.")
    return [[f"{state[row * 4 + column]:08x}" for column in range(4)] for row in range(4)]


def crypt(data: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    """Encrypt or decrypt ``data`` with ChaCha20."""

    _validate_key_nonce(key, nonce)
    _validate_counter(counter)
    blocks = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE
    if blocks and counter + blocks - 1 > MAX_COUNTER:
        raise ValueError("Pesan terlalu panjang untuk rentang block counter yang tersedia.")
    output = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        block_counter = counter + offset // BLOCK_SIZE
        keystream = chacha20_block(key, nonce, block_counter)
        output.extend(byte ^ key_byte for byte, key_byte in zip(data[offset : offset + BLOCK_SIZE], keystream))
    return bytes(output)


def generate_key() -> bytes:
    """Generate a cryptographically secure random 256-bit key."""

    return secrets.token_bytes(KEY_SIZE)


def generate_nonce() -> bytes:
    """Generate a cryptographically secure random 96-bit nonce."""

    return secrets.token_bytes(NONCE_SIZE)


def encrypt_hex(plaintext: str, key: bytes, nonce: bytes, counter: int = 0) -> str:
    """Encrypt UTF-8 text and return uppercase hexadecimal ciphertext."""

    return crypt(plaintext.encode("utf-8"), key, nonce, counter).hex().upper()


def decrypt_hex(ciphertext_hex: str, key: bytes, nonce: bytes, counter: int = 0) -> str:
    """Decrypt hexadecimal ciphertext and decode it as UTF-8 text."""

    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError as error:
        raise ValueError("Ciphertext hex tidak valid.") from error
    try:
        return crypt(ciphertext, key, nonce, counter).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Hasil dekripsi bukan UTF-8 yang valid.") from error


def encrypt_base64(plaintext: str, key: bytes, nonce: bytes, counter: int = 0) -> str:
    """Encrypt UTF-8 text and return Base64 ciphertext."""

    return base64.b64encode(crypt(plaintext.encode("utf-8"), key, nonce, counter)).decode("ascii")


def decrypt_base64(ciphertext: str, key: bytes, nonce: bytes, counter: int = 0) -> str:
    """Decrypt Base64 ciphertext and decode it as UTF-8 text."""

    try:
        raw = base64.b64decode(ciphertext, validate=True)
    except ValueError as error:
        raise ValueError("Ciphertext Base64 tidak valid.") from error
    try:
        return crypt(raw, key, nonce, counter).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Hasil dekripsi bukan UTF-8 yang valid.") from error


@dataclass(frozen=True)
class ChaCha20Sample:
    """Inputs and outputs used to explain one ChaCha20 block."""

    key: bytes
    nonce: bytes
    counter: int
    initial_state: list[list[str]]
    block_hex: str


def sample_block(key: bytes, nonce: bytes, counter: int = 0) -> ChaCha20Sample:
    """Return state and block details for the first block."""

    state = initial_state(key, nonce, counter)
    return ChaCha20Sample(key, nonce, counter, state_as_hex(state), chacha20_block(key, nonce, counter).hex())
