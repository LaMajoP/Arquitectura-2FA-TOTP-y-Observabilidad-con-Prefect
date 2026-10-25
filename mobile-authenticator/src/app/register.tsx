import { router } from "expo-router";
import { useState } from "react";

import { ApiError, register } from "../lib/api";
import { AuthScreen, Body, Card, Heading, Notice, PrimaryButton, SecondaryButton, TextField } from "../components/auth-ui";

export default function RegisterScreen() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(normalizedEmail)) {
      setError("Ingresa un correo electrónico válido.");
      return;
    }
    if (password.length < 12) {
      setError("La contraseña debe tener al menos 12 caracteres.");
      return;
    }
    if (password !== confirmation) {
      setError("La confirmación de contraseña no coincide.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      await register(normalizedEmail, password);
      router.replace("/login");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "No se pudo crear la cuenta.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthScreen>
      <Card>
        <Heading>Crear cuenta</Heading>
        <Body>La contraseña se envía solamente al backend por HTTPS y nunca se guarda en esta aplicación.</Body>
        {error ? <Notice>{error}</Notice> : null}
        <TextField label="Correo electrónico" value={email} onChangeText={setEmail} keyboardType="email-address" autoComplete="email" />
        <TextField label="Contraseña" value={password} onChangeText={setPassword} secureTextEntry autoComplete="new-password" />
        <TextField label="Confirmar contraseña" value={confirmation} onChangeText={setConfirmation} secureTextEntry autoComplete="new-password" onSubmitEditing={submit} />
        <PrimaryButton onPress={submit} loading={loading}>Registrarme</PrimaryButton>
        <SecondaryButton onPress={() => router.replace("/login")}>Ya tengo una cuenta</SecondaryButton>
      </Card>
    </AuthScreen>
  );
}
