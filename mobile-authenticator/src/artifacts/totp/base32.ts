/**
 * Decodes an RFC 4648 Base32 secret into its original bytes.
 *
 * Unpadded secrets are accepted because they are common in TOTP provisioning
 * URIs. If padding is supplied, it must be the canonical RFC 4648 padding.
 */
export function decodeBase32(secret: string): Uint8Array {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new TypeError("Base32 secret must be a non-empty string.");
  }
  if (!/^[A-Za-z2-7=]+$/.test(secret)) {
    throw new TypeError(
      "Base32 secret may contain only letters A-Z, digits 2-7, and optional trailing '=' padding."
    );
  }

  const normalized = secret.toUpperCase();
  const paddingStart = normalized.indexOf("=");
  const encoded = paddingStart === -1 ? normalized : normalized.slice(0, paddingStart);
  const padding = paddingStart === -1 ? "" : normalized.slice(paddingStart);

  if (!/^[A-Z2-7]+$/.test(encoded)) {
    throw new TypeError(
      "Base32 secret may contain only letters A-Z, digits 2-7, and optional trailing '=' padding."
    );
  }

  if (padding.length > 0 && !/^=+$/.test(padding)) {
    throw new TypeError("Base32 padding must appear only at the end of the secret.");
  }

  const remainder = encoded.length % 8;
  const expectedPaddingByRemainder: Record<number, number> = {
    0: 0,
    2: 6,
    4: 4,
    5: 3,
    7: 1,
  };
  const expectedPadding = expectedPaddingByRemainder[remainder];

  if (expectedPadding === undefined) {
    throw new TypeError("Base32 secret has an invalid length.");
  }

  if (padding.length > 0 && padding.length !== expectedPadding) {
    throw new TypeError("Base32 secret has invalid padding.");
  }

  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bufferedBits = 0;
  let bitCount = 0;
  const bytes: number[] = [];

  for (const character of encoded) {
    bufferedBits = (bufferedBits << 5) | alphabet.indexOf(character);
    bitCount += 5;

    if (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((bufferedBits >>> bitCount) & 0xff);
      // Retaining only pending bits prevents 32-bit overflow for long secrets.
      bufferedBits &= (1 << bitCount) - 1;
    }
  }

  // RFC 4648 requires unused bits in the final Base32 symbol to be zero.
  if (bitCount !== 0 && bufferedBits !== 0) {
    throw new TypeError("Base32 secret has non-zero unused bits.");
  }

  return Uint8Array.from(bytes);
}
