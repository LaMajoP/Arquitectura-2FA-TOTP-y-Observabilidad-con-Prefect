import { router } from "expo-router";
import { useEffect, useMemo, useState } from "react";

import { EnrollmentQr } from "../components/enrollment-qr";
import { AuthScreen, Body, Card, Heading, Notice, PrimaryButton, SecondaryButton, TextField } from "../components/auth-ui";
import { ApiError, setupTotp, verifyTotpEnrollment } from "../lib/api";
import { createOtpAuthUri } from "../lib/otpauth";
import { loadAuthenticatorAccounts, saveAuthenticatorAccounts, type AuthenticatorAccount } from "../lib/authenticator-storage";
import { useSession } from "../lib/session";

const ISSUER = "Arquitectura 2FA";

export default function TotpSetupScreen() {
  const session = useSession();
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [savedToAuthenticator, setSavedToAuthenticator] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!session.provisioningToken) router.replace("/login");
  }, [session.provisioningToken]);

  const uri = useMemo(
    () => (secret && session.email ? createOtpAuthUri({ issuer: ISSUER, accountName: session.email, secret }) : null),
    [secret, session.email],
  );

  async function createEnrollment(): Promise<void> {
    if (!session.provisioningToken) return;
    setLoading(true);
    setError(null);
    try {
      const enrollment = await setupTotp(session.provisioningToken);
      setSecret(enrollment.secret_base32);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "No se pudo iniciar la configuración TOTP.");
    } finally {
      setLoading(false);
    }
  }

  async function addToAuthenticator(): Promise<void> {
    if (!secret || !session.email) return;
    setError(null);
    try {
      const existing = await loadAuthenticatorAccounts();
      const account: AuthenticatorAccount = {
        id: `enrollment-${Date.now()}`,
        issuer: ISSUER,
        accountName: session.email,
        secret,
      };
      await saveAuthenticatorAccounts([...existing.filter((item) => item.secret !== secret), account]);
      setSavedToAuthenticator(true);
    } catch {
      setError("No se pudo guardar el secreto en el almacenamiento seguro del dispositivo.");
    }
  }

  async function verify(): Promise<void> {
    if (!session.provisioningToken) return;
    if (!/^\d{6}$/.test(code)) {
      setError("Ingresa el código de seis dígitos de tu Authenticator.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await verifyTotpEnrollment(session.provisioningToken, code);
      setSuccess(true);
      setCode("");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "No se pudo verificar el código.");
    } finally {
      setLoading(false);
    }
  }

  if (success) {
    return (
      <AuthScreen>
        <Card>
          <Heading>TOTP activado</Heading>
          <Notice kind="success">La inscripción se confirmó. Inicia sesión de nuevo para completar Step-Up.</Notice>
          <PrimaryButton onPress={() => { session.clearSession(); router.replace("/login"); }}>Ir a iniciar sesión</PrimaryButton>
        </Card>
      </AuthScreen>
    );
  }

  return (
    <AuthScreen>
      <Card>
        <Heading>Configurar TOTP</Heading>
        <Body>El secreto se muestra una sola vez. Escanea el QR con una app compatible o agrégalo manualmente.</Body>
        {error ? <Notice>{error}</Notice> : null}
        {!secret ? <PrimaryButton onPress={createEnrollment} loading={loading}>Generar inscripción segura</PrimaryButton> : null}
        {secret && uri ? (
          <>
            <EnrollmentQr value={uri} />
            <TextField label="Secreto Base32 para configuración manual" value={secret} editable={false} selectTextOnFocus />
            <SecondaryButton onPress={addToAuthenticator}>Guardar en este Authenticator</SecondaryButton>
            {savedToAuthenticator ? <Notice kind="success">El secreto se guardó en el Authenticator de este dispositivo.</Notice> : null}
            <TextField label="Código de seis dígitos" value={code} onChangeText={setCode} keyboardType="number-pad" maxLength={6} textContentType="oneTimeCode" />
            <PrimaryButton onPress={verify} loading={loading}>Verificar y activar</PrimaryButton>
          </>
        ) : null}
        <SecondaryButton onPress={() => { session.clearSession(); router.replace("/login"); }}>Cancelar</SecondaryButton>
      </Card>
    </AuthScreen>
  );
}
