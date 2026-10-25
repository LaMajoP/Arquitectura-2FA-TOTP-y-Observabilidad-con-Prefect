export type OtpAuthEnrollment = {
  issuer: string;
  accountName: string;
  secret: string;
};

/** Build an RFC-compatible enrollment URI locally; no QR service sees the secret. */
export function createOtpAuthUri({ issuer, accountName, secret }: OtpAuthEnrollment): string {
  const label = `${issuer}:${accountName}`;
  const parameters = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${parameters.toString()}`;
}

export function normalizeBase32Secret(value: string): string {
  const secret = value.replace(/\s/g, "").toUpperCase();
  try {
    // Reuse the app's existing RFC 4648 decoder instead of maintaining another
    // Base32 validator beside the TOTP implementation.
    decodeBase32(secret);
  } catch {
    throw new Error("El secreto debe estar codificado en Base32.");
  }
  return secret;
}

/**
 * Accept only the algorithm, digit count and period implemented by this app's
 * own TOTP module. Invalid QR payloads never leave the device.
 */
export function parseOtpAuthUri(value: string): OtpAuthEnrollment {
  let uri: URL;
  try {
    uri = new URL(value);
  } catch {
    throw new Error("El código QR no contiene una URI otpauth válida.");
  }
  if (uri.protocol !== "otpauth:" || uri.hostname !== "totp") {
    throw new Error("El código QR no corresponde a una cuenta TOTP.");
  }

  const secret = uri.searchParams.get("secret");
  const label = decodeURIComponent(uri.pathname.replace(/^\//, ""));
  const separator = label.indexOf(":");
  const queryIssuer = uri.searchParams.get("issuer")?.trim();
  const issuer = queryIssuer || (separator >= 0 ? label.slice(0, separator).trim() : "");
  const accountName = (separator >= 0 ? label.slice(separator + 1) : label).trim();
  const algorithm = (uri.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
  const digits = uri.searchParams.get("digits") ?? "6";
  const period = uri.searchParams.get("period") ?? "30";

  if (!secret || !issuer || !accountName || algorithm !== "SHA1" || digits !== "6" || period !== "30") {
    throw new Error("El código QR usa parámetros TOTP que esta aplicación no admite.");
  }
  return { issuer, accountName, secret: normalizeBase32Secret(secret) };
}
import { decodeBase32 } from "../artifacts/totp/base32";

