import Constants from "expo-constants";

export type LoginResponse =
  | {
      status: "MFA_REQUIRED";
      pre_auth_token: string;
      expires_in: number;
    }
  | {
      status: "TOTP_ENROLLMENT_REQUIRED";
      provisioning_token: string;
      expires_in: number;
    };

type ApiErrorBody = { detail?: unknown };

/** A deliberately non-specific API error suitable for user-facing messages. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly retryAfterSeconds?: number,
  ) {
    super(apiMessageForStatus(status));
    this.name = "ApiError";
  }
}

function apiMessageForStatus(status: number): string {
  switch (status) {
    case 400:
      return "La solicitud no pudo completarse. Revisa los datos e inténtalo de nuevo.";
    case 401:
      return "No fue posible autenticar esta solicitud.";
    case 409:
      return "Esta operación ya no está disponible para el estado actual de la cuenta.";
    case 422:
      return "Revisa el formato de los datos ingresados.";
    case 429:
      return "Demasiados intentos. Espera antes de volver a intentarlo.";
    case 503:
      return "El servicio de autenticación no está disponible temporalmente.";
    default:
      return "No fue posible comunicarse con el servicio de autenticación.";
  }
}

/**
 * `EXPO_PUBLIC_API_URL` is intentionally only a public backend URL. It must
 * never contain a Supabase key, signing key, token, or other credential.
 */
export function getApiBaseUrl(): string {
  const configured =
    process.env.EXPO_PUBLIC_API_URL ??
    (Constants.expoConfig?.extra?.apiUrl as string | undefined) ??
    "http://localhost:8000";
  return configured.replace(/\/+$/, "");
}

async function parseBody(response: Response): Promise<ApiErrorBody | undefined> {
  try {
    return (await response.json()) as ApiErrorBody;
  } catch {
    return undefined;
  }
}

async function postJson<T>(
  path: string,
  body: unknown,
  bearerToken?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };
  if (bearerToken) headers.Authorization = `Bearer ${bearerToken}`;

  let response: Response;
  try {
    response = await fetch(`${getApiBaseUrl()}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
  } catch {
    // Do not include network implementation errors: they can expose URL data.
    throw new ApiError(0);
  }

  if (!response.ok) {
    // Consume a response body so a connection can be reused, but intentionally
    // do not surface server detail because auth errors must remain generic.
    await parseBody(response);
    const retryAfter = Number.parseInt(response.headers.get("Retry-After") ?? "", 10);
    throw new ApiError(
      response.status,
      Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
    );
  }
  return (await response.json()) as T;
}

export function register(email: string, password: string): Promise<{ status: "REGISTERED" }> {
  return postJson("/v1/auth/register", { email, password });
}

export function login(email: string, password: string): Promise<LoginResponse> {
  return postJson("/v1/auth/login", { email, password });
}

export function setupTotp(
  provisioningToken: string,
): Promise<{ status: "PENDING_VERIFICATION"; secret_base32: string }> {
  return postJson("/v1/totp/setup", {}, provisioningToken);
}

export function verifyTotpEnrollment(
  provisioningToken: string,
  code: string,
): Promise<{ status: "ACTIVE" }> {
  return postJson("/v1/totp/verify", { code }, provisioningToken);
}

export function verifyMfa(
  preAuthToken: string,
  method: "totp" | "backup_code",
  code: string,
): Promise<{ access_token: string; token_type: "Bearer"; expires_in: number }> {
  return postJson("/v1/auth/verify-mfa", {
    pre_auth_token: preAuthToken,
    method,
    code,
  });
}

export function generateBackupCodes(accessToken: string): Promise<{ backup_codes: string[] }> {
  return postJson("/v1/auth/backup-codes", {}, accessToken);
}
