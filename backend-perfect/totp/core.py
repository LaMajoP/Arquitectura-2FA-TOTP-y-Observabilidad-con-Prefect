"""Independent RFC 6238 TOTP implementation using only Python's standard library."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import struct
import time
from dataclasses import dataclass

TIME_STEP_SECONDS = 30
OTP_DIGITS = 6
OTP_MODULUS = 10**OTP_DIGITS
_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_UINT64_MAX = (1 << 64) - 1
_EXPECTED_PADDING = {0: 0, 2: 6, 4: 4, 5: 3, 7: 1}


@dataclass(frozen=True, slots=True)
class TOTPVerificationResult:
    """The outcome of a TOTP comparison without exposing secret material."""

    valid: bool
    counter: int | None
    window: int | None


def _decode_base32(secret: str) -> bytes:
    """Decode a strict, case-insensitive RFC 4648 Base32 secret."""
    if not isinstance(secret, str) or not secret:
        raise TypeError("Base32 secret must be a non-empty string.")
    if not secret.isascii():
        raise ValueError(
            "Base32 secret may contain only letters A-Z, digits 2-7, and optional trailing '=' padding."
        )

    normalized = secret.upper()
    padding_start = normalized.find("=")
    encoded = normalized if padding_start == -1 else normalized[:padding_start]
    padding = "" if padding_start == -1 else normalized[padding_start:]

    if not encoded or any(character not in _BASE32_ALPHABET for character in encoded):
        raise ValueError(
            "Base32 secret may contain only letters A-Z, digits 2-7, and optional trailing '=' padding."
        )
    if padding and any(character != "=" for character in padding):
        raise ValueError("Base32 padding must appear only at the end of the secret.")

    expected_padding = _EXPECTED_PADDING.get(len(encoded) % 8)
    if expected_padding is None:
        raise ValueError("Base32 secret has an invalid length.")
    if padding and len(padding) != expected_padding:
        raise ValueError("Base32 secret has invalid padding.")

    remaining_bits = (len(encoded) * 5) % 8
    if remaining_bits and (_BASE32_ALPHABET.index(encoded[-1]) & ((1 << remaining_bits) - 1)):
        raise ValueError("Base32 secret has non-zero unused bits.")

    # Add canonical padding when an unpadded provisioning secret was supplied.
    return base64.b32decode(encoded + "=" * expected_padding, casefold=False)


def generate_totp(secret: str, counter: int) -> str:
    """Generate one six-digit HMAC-SHA1 code for an unsigned 64-bit counter."""
    if isinstance(counter, bool) or not isinstance(counter, int):
        raise TypeError("TOTP counter must be an integer.")
    if not 0 <= counter <= _UINT64_MAX:
        raise ValueError("TOTP counter must fit in an unsigned 64-bit integer.")

    secret_bytes = _decode_base32(secret)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()

    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], byteorder="big") & 0x7FFFFFFF
    return f"{binary % OTP_MODULUS:0{OTP_DIGITS}d}"


def verify_totp(
    secret: str, code: str, timestamp: float | None = None
) -> TOTPVerificationResult:
    """Verify a code in the previous, current, or next 30-second time window."""
    if timestamp is None:
        timestamp = time.time()
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        raise TypeError("Timestamp must be a Unix timestamp in seconds.")
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError("Timestamp must be a finite, non-negative Unix timestamp in seconds.")

    if not isinstance(code, str) or len(code) != OTP_DIGITS or not code.isascii() or not code.isdigit():
        return TOTPVerificationResult(valid=False, counter=None, window=None)

    current_counter = math.floor(timestamp / TIME_STEP_SECONDS)
    for window in (-1, 0, 1):
        counter = current_counter + window
        if counter < 0:
            continue
        expected_code = generate_totp(secret, counter)
        if hmac.compare_digest(expected_code, code):
            return TOTPVerificationResult(valid=True, counter=counter, window=window)

    return TOTPVerificationResult(valid=False, counter=None, window=None)
