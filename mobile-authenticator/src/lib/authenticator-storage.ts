import * as SecureStore from "expo-secure-store";
import { Platform } from "react-native";

export type AuthenticatorAccount = {
  id: string;
  issuer: string;
  accountName: string;
  secret: string;
};

const ACCOUNTS_KEY = "mfa.authenticator.accounts.v1";
let webMemoryAccounts: AuthenticatorAccount[] = [];

function isAccountArray(value: unknown): value is AuthenticatorAccount[] {
  return (
    Array.isArray(value) &&
    value.every(
      (account) =>
        typeof account === "object" &&
        account !== null &&
        typeof (account as AuthenticatorAccount).id === "string" &&
        typeof (account as AuthenticatorAccount).issuer === "string" &&
        typeof (account as AuthenticatorAccount).accountName === "string" &&
        typeof (account as AuthenticatorAccount).secret === "string",
    )
  );
}

/**
 * Native secrets use the platform encrypted key store through Expo SecureStore.
 * On web, this intentionally uses process memory only: never localStorage,
 * sessionStorage, IndexedDB, or a cookie for TOTP seeds.
 */
export async function loadAuthenticatorAccounts(): Promise<AuthenticatorAccount[]> {
  if (Platform.OS === "web") return webMemoryAccounts;

  const encoded = await SecureStore.getItemAsync(ACCOUNTS_KEY);
  if (!encoded) return [];
  try {
    const parsed: unknown = JSON.parse(encoded);
    return isAccountArray(parsed) ? parsed : [];
  } catch {
    // Treat an unreadable local value as empty instead of exposing its contents.
    return [];
  }
}

export async function saveAuthenticatorAccounts(accounts: AuthenticatorAccount[]): Promise<void> {
  if (Platform.OS === "web") {
    webMemoryAccounts = accounts;
    return;
  }
  await SecureStore.setItemAsync(ACCOUNTS_KEY, JSON.stringify(accounts));
}
