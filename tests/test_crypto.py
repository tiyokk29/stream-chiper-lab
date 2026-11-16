import unittest

from src.chacha20 import chacha20_block, crypt, initial_state
from src.xor_cipher import journal_preset, parse_binary_tokens, xor_bytes


class XorCipherTests(unittest.TestCase):
    def test_journal_preset(self):
        result = journal_preset()
        self.assertEqual(result.ciphertext_bits, "11011011")

    def test_binary_parser(self):
        self.assertEqual(parse_binary_tokens("10110010, 01101001"), bytes([0xB2, 0x69]))

    def test_mismatched_xor_is_rejected(self):
        with self.assertRaises(ValueError):
            xor_bytes(b"a", b"ab")


class ChaCha20Tests(unittest.TestCase):
    def test_rfc8439_block_vector(self):
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        nonce = bytes.fromhex("000000090000004a00000000")
        expected = (
            "10f1e7e4d13b5915500fdd1fa32071c4"
            "c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2"
            "b5129cd1de164eb9cbd083e8a2503c4e"
        )
        self.assertEqual(chacha20_block(key, nonce, 1).hex(), expected)

    def test_round_trip(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        message = "Belajar stream cipher".encode()
        ciphertext = crypt(message, key, nonce)
        self.assertEqual(crypt(ciphertext, key, nonce), message)

    def test_initial_state_has_16_words(self):
        self.assertEqual(len(initial_state(bytes(32), bytes(12))), 16)


if __name__ == "__main__":
    unittest.main()
