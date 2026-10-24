import * as Crypto from "expo-crypto";

import { decodeBase32 } from "./base32";

const TIME_STEP_SECONDS = 30n;
const TIME_STEP_MILLISECONDS = 30_000;
const OTP_MODULUS = 1_000_000;
const SHA1_BLOCK_SIZE = 64;
const UINT64_MAX = (1n << 64n) - 1n;

function assertTimestamp(timestamp: number): void {
  if (!Number.isFinite(timestamp) || timestamp < 0) {
    throw new RangeError("Timestamp must be a finite Unix timestamp in milliseconds.");
  }
  if (!Number.isSafeInteger(Math.floor(timestamp / 1000))) {
    throw new RangeError("Timestamp is outside JavaScript's precise TOTP range.");
  }
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;

  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

async function sha1(bytes: Uint8Array): Promise<Uint8Array> {
  // Expo's type accepts an ArrayBuffer-backed BufferSource. Copying here also
  // avoids depending on the typed-array backing store in Hermes or on web.
  const input = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(input).set(bytes);
  const digest = await Crypto.digest(Crypto.CryptoDigestAlgorithm.SHA1, input);
  return new Uint8Array(digest);
}

/**
 * HMAC-SHA1 composed from Expo's vetted SHA-1 primitive (RFC 2104).
 * Expo Crypto exposes a digest primitive, not an HMAC API.
 */
async function hmacSha1(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  let normalizedKey = key;
  if (normalizedKey.length > SHA1_BLOCK_SIZE) {
    normalizedKey = await sha1(normalizedKey);
  }

  const block = new Uint8Array(SHA1_BLOCK_SIZE);
  block.set(normalizedKey);

  const innerPadding = new Uint8Array(SHA1_BLOCK_SIZE);
  const outerPadding = new Uint8Array(SHA1_BLOCK_SIZE);
  for (let index = 0; index < SHA1_BLOCK_SIZE; index += 1) {
    innerPadding[index] = block[index] ^ 0x36;
    outerPadding[index] = block[index] ^ 0x5c;
  }

  const innerHash = await sha1(concatBytes(innerPadding, message));
  return sha1(concatBytes(outerPadding, innerHash));
}

function counterToBytes(counter: bigint): Uint8Array {
  if (counter < 0n || counter > UINT64_MAX) {
    throw new RangeError("TOTP counter must fit in an unsigned 64-bit integer.");
  }

  const bytes = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number((counter >> BigInt((7 - index) * 8)) & 0xffn);
  }
  return bytes;
}

/**
 * Generates a six-digit RFC 6238 TOTP code for a Base32 secret.
 *
 * `timestamp` is a Unix timestamp in milliseconds, matching JavaScript's
 * `Date.now()` convention. It defaults to the current device time.
 */
export async function generateTOTP(secret: string, timestamp = Date.now()): Promise<string> {
  assertTimestamp(timestamp);

  const secretBytes = decodeBase32(secret);
  const unixTime = BigInt(Math.floor(timestamp / 1000));
  const counter = unixTime / TIME_STEP_SECONDS;
  const hash = await hmacSha1(secretBytes, counterToBytes(counter));

  const offset = hash[19] & 0x0f;
  const binary =
    (((hash[offset] & 0x7f) << 24) |
      (hash[offset + 1] << 16) |
      (hash[offset + 2] << 8) |
      hash[offset + 3]) >>>
    0;

  return String(binary % OTP_MODULUS).padStart(6, "0");
}

/**
 * Returns the whole seconds remaining in the current 30-second TOTP window.
 * It derives the value from the supplied clock instead of maintaining state.
 */
export function secondsRemaining(timestamp = Date.now()): number {
  assertTimestamp(timestamp);
  const elapsedSeconds = Math.floor(timestamp / 1000);
  return TIME_STEP_MILLISECONDS / 1000 - (elapsedSeconds % (TIME_STEP_MILLISECONDS / 1000));
}
