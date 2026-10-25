import { router } from "expo-router";
import { useState } from "react";

import { ApiError, login } from "../lib/api";
import { useSession } from "../lib/session";
import { AuthScreen, Body, Card, Heading, Notice, PrimaryButton, SecondaryButton, TextField } from "../components/auth-ui";

export default function LoginScreen() {
  const session = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail || !password) {
      setError("Ingresa el correo electrónico y la contraseña.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await login(normalizedEmail, password);
      setPassword("");
      if (response.status === "MFA_REQUIRED") {
        session.setPreAuthSession(normalizedEmail, response.pre_auth_token);
        router.replace("/mfa-verify");
      } else {
        session.setProvisioningSession(normalizedEmail, response.provisioning_token);
        router.replace("/totp-setup");
      }
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "No se pudo iniciar sesión.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthScreen>
      <Card>
        <Heading>Iniciar sesión</Heading>
        <Body>Después de validar la contraseña, completa la inscripción TOTP o la verificación MFA.</Body>
        {error ? <Notice>{error}</Notice> : null}
        <TextField label="Correo electrónico" value={email} onChangeText={setEmail} keyboardType="email-address" autoComplete="email" />
        <TextField label="Contraseña" value={password} onChangeText={setPassword} secureTextEntry autoComplete="current-password" onSubmitEditing={submit} />
        <PrimaryButton onPress={submit} loading={loading}>Continuar</PrimaryButton>
        <SecondaryButton onPress={() => router.replace("/register")}>Crear una cuenta</SecondaryButton>
      </Card>
    </AuthScreen>
  );
}
