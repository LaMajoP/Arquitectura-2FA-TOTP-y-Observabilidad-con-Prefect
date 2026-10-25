from __future__ import annotations

from unittest import TestCase

from totp import generate_totp, verify_totp


SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class TOTPPrimitiveTests(TestCase):
    def test_generates_the_rfc_6238_sha1_six_digit_vector(self) -> None:
        # RFC 6238 test time T=59 seconds uses moving factor 1.
        self.assertEqual(generate_totp(SECRET, 1), "287082")

    def test_verifies_previous_current_and_next_windows(self) -> None:
        timestamp = 120.0
        current_counter = 4

        for expected_window in (-1, 0, 1):
            code = generate_totp(SECRET, current_counter + expected_window)
            result = verify_totp(SECRET, code, timestamp=timestamp)
            self.assertTrue(result.valid)
            self.assertEqual(result.counter, current_counter + expected_window)
            self.assertEqual(result.window, expected_window)

    def test_rejects_an_invalid_code(self) -> None:
        valid_code = generate_totp(SECRET, 4)
        invalid_code = f"{(int(valid_code) + 1) % 1_000_000:06d}"

        result = verify_totp(SECRET, invalid_code, timestamp=120.0)

        self.assertFalse(result.valid)
        self.assertIsNone(result.counter)
        self.assertIsNone(result.window)
