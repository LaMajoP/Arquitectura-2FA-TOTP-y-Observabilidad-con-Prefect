import { router } from "expo-router";
import { useEffect, useState } from "react";

import { AuthScreen, Body, Card, Heading, Notice, PrimaryButton, SecondaryButton, TextField } from "../components/auth-ui";
import { ApiError, verifyMfa } from "../lib/api";
import { useSession } from "../lib/session";

type MfaMethod = "totp" | "backup_code";

export default function MfaVerifyScreen() {
  const session = useSession();
  const [method, setMethod] = useState<MfaMethod>("totp");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!session.preAuthToken) router.replace("/login");
  }, [session.preAuthToken]);

  async function submit(): Promise<void> {
    if (!session.preAuthToken) {
      router.replace("/login");
      return;
    }
    const normalized = method === "totp" ? code.replace(/\s/g, "") : code.trim();
    if ((method === "totp" && !/^\d{6}$/.test(normalized)) || (method === "backup_code" && !normalized)) {
      setError(method === "totp" ? "Ingresa un código TOTP de seis dígitos." : "Ingresa un código de respaldo.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await verifyMfa(session.preAuthToken, method, normalized);
      session.setAccessSession(result.access_token);
      setCode("");
      router.replace("/session");
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        setError("La verificación no pudo completarse. Si el token temporal venció, inicia sesión de nuevo.");
      } else if (caught instanceof ApiError) {
        setError(caught.message);
      } else {
        setError("No se pudo completar la verificación MFA.");
      }
    } finally {
      setLoading(false);
    }
  }

  function switchMethod(next: MfaMethod): void {
    setMethod(next);
    setCode("");
    setError(null);
  }

  return (
    <AuthScreen>
      <Card>
        <Heading>Verificación MFA</Heading>
        <Body>Completa el segundo factor antes de recibir una sesión autenticada.</Body>
        {error ? <Notice>{error}</Notice> : null}
        <SecondaryButton onPress={() => switchMethod(method === "totp" ? "backup_code" : "totp")}>
          {method === "totp" ? "Usar un código de respaldo" : "Usar un código TOTP"}
        </SecondaryButton>
        {method === "totp" ? (
          <TextField label="Código TOTP" value={code} onChangeText={setCode} keyboardType="number-pad" maxLength={6} textContentType="oneTimeCode" onSubmitEditing={submit} />
        ) : (
          <TextField label="Código de respaldo" value={code} onChangeText={setCode} autoCapitalize="none" autoCorrect={false} onSubmitEditing={submit} />
        )}
        <PrimaryButton onPress={submit} loading={loading}>Verificar</PrimaryButton>
        <SecondaryButton onPress={() => { session.clearSession(); router.replace("/login"); }}>Cancelar e iniciar de nuevo</SecondaryButton>
      </Card>
    </AuthScreen>
  );
}
