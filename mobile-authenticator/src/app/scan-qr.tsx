import { CameraView, useCameraPermissions } from "expo-camera";
import { router } from "expo-router";
import { useRef, useState } from "react";
import { StyleSheet, View } from "react-native";

import { AuthScreen, Body, Card, Heading, Notice, PrimaryButton, SecondaryButton } from "../components/auth-ui";
import { loadAuthenticatorAccounts, saveAuthenticatorAccounts, type AuthenticatorAccount } from "../lib/authenticator-storage";
import { parseOtpAuthUri } from "../lib/otpauth";

export default function ScanQrScreen() {
  const [permission, requestPermission] = useCameraPermissions();
  const [message, setMessage] = useState<string | null>(null);
  const [completed, setCompleted] = useState(false);
  const scanning = useRef(false);

  async function onBarcodeScanned({ data }: { data: string }): Promise<void> {
    if (scanning.current || completed) return;
    scanning.current = true;
    try {
      const enrollment = parseOtpAuthUri(data);
      const accounts = await loadAuthenticatorAccounts();
      const account: AuthenticatorAccount = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        ...enrollment,
      };
      await saveAuthenticatorAccounts([
        ...accounts.filter((item) => item.secret !== account.secret),
        account,
      ]);
      setCompleted(true);
      setMessage("La cuenta se guardó localmente. Ya puedes generar códigos sin conexión.");
    } catch {
      // Do not include QR contents or parser implementation errors in the UI.
      setMessage("No se pudo importar este QR. Usa una URI TOTP SHA1 de 6 dígitos y 30 segundos, o agrégala manualmente.");
      scanning.current = false;
    }
  }

  if (!permission) {
    return <AuthScreen><Card><Body>Comprobando permiso de cámara…</Body></Card></AuthScreen>;
  }

  if (!permission.granted) {
    return (
      <AuthScreen>
        <Card>
          <Heading>Escanear QR</Heading>
          <Body>La cámara se usa solo para leer el QR en este dispositivo. El secreto no se transmite a servicios externos.</Body>
          {message ? <Notice>{message}</Notice> : null}
          <PrimaryButton onPress={() => { void requestPermission(); }}>Permitir cámara</PrimaryButton>
          <SecondaryButton onPress={() => router.back()}>Volver</SecondaryButton>
        </Card>
      </AuthScreen>
    );
  }

  return (
    <AuthScreen>
      <Card>
        <Heading>Escanear QR TOTP</Heading>
        <Body>Enfoca un QR `otpauth://totp`. Solo se aceptan SHA1, 6 dígitos y 30 segundos.</Body>
        {message ? <Notice kind={completed ? "success" : "error"}>{message}</Notice> : null}
        {!completed ? <View style={styles.cameraFrame}><CameraView style={styles.camera} facing="back" barcodeScannerSettings={{ barcodeTypes: ["qr"] }} onBarcodeScanned={onBarcodeScanned} /></View> : null}
        <SecondaryButton onPress={() => router.replace("/authenticator")}>{completed ? "Ver Authenticator" : "Cancelar"}</SecondaryButton>
      </Card>
    </AuthScreen>
  );
}

const styles = StyleSheet.create({
  cameraFrame: { height: 330, overflow: "hidden", borderRadius: 12, backgroundColor: "#102a43" },
  camera: { flex: 1 },
});
