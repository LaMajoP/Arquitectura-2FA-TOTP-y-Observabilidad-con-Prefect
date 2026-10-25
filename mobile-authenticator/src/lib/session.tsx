import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

type AuthSession = {
  email: string | null;
  provisioningToken: string | null;
  preAuthToken: string | null;
  accessToken: string | null;
  setProvisioningSession: (email: string, token: string) => void;
  setPreAuthSession: (email: string, token: string) => void;
  setAccessSession: (token: string) => void;
  clearSession: () => void;
};

const SessionContext = createContext<AuthSession | null>(null);

/**
 * Auth flow tokens deliberately stay in React memory. A reload signs the user
 * out instead of leaving a JWT in browser storage; native persistence is not
 * needed for this short-lived, step-by-step flow.
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const [email, setEmail] = useState<string | null>(null);
  const [provisioningToken, setProvisioningToken] = useState<string | null>(null);
  const [preAuthToken, setPreAuthToken] = useState<string | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);

  const value = useMemo<AuthSession>(
    () => ({
      email,
      provisioningToken,
      preAuthToken,
      accessToken,
      setProvisioningSession: (nextEmail, token) => {
        setEmail(nextEmail);
        setProvisioningToken(token);
        setPreAuthToken(null);
        setAccessToken(null);
      },
      setPreAuthSession: (nextEmail, token) => {
        setEmail(nextEmail);
        setPreAuthToken(token);
        setProvisioningToken(null);
        setAccessToken(null);
      },
      setAccessSession: (token) => {
        setAccessToken(token);
        setProvisioningToken(null);
        setPreAuthToken(null);
      },
      clearSession: () => {
        setEmail(null);
        setProvisioningToken(null);
        setPreAuthToken(null);
        setAccessToken(null);
      },
    }),
    [accessToken, email, preAuthToken, provisioningToken],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): AuthSession {
  const session = useContext(SessionContext);
  if (!session) throw new Error("useSession must be used inside SessionProvider.");
  return session;
}
