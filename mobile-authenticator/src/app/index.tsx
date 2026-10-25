import { router } from "expo-router";

import { AuthScreen, Body, Card, Heading, PrimaryButton, SecondaryButton } from "../components/auth-ui";

export default function HomeScreen() {
  return (
    <AuthScreen>
      <Card>
        <Heading>Autenticación segura</Heading>
        <Body>Registra tu cuenta, activa TOTP y completa el segundo factor antes de abrir una sesión.</Body>
        <PrimaryButton onPress={() => router.push("/login")}>Iniciar sesión</PrimaryButton>
        <SecondaryButton onPress={() => router.push("/register")}>Crear cuenta</SecondaryButton>
      </Card>
      <Card>
        <Heading>Authenticator</Heading>
        <Body>Genera códigos TOTP sin conexión desde secretos guardados de forma segura en el dispositivo.</Body>
        <SecondaryButton onPress={() => router.push("/authenticator")}>Abrir Authenticator</SecondaryButton>
      </Card>
    </AuthScreen>
  );
}
