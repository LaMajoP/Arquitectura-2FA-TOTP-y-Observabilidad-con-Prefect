import { router } from "expo-router";
import { useEffect, useState } from "react";
import { StyleSheet, Text, View } from "react-native";

import { AuthScreen, Body, Card, Heading, Notice, PrimaryButton, SecondaryButton, colors } from "../components/auth-ui";
import { ApiError, generateBackupCodes } from "../lib/api";
import { useSession } from "../lib/session";

export default function AuthenticatedSessionScreen() {
  const session = useSession();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!session.accessToken) router.replace("/login");
  }, [session.accessToken]);

  async function createBackupCodes(): Promise<void> {
    if (!session.accessToken) return;
    setLoading(true);
    setError(null);
    try {
      const result = await generateBackupCodes(session.accessToken);
      setCodes(result.backup_codes);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        setError("Se necesita una verificación MFA reciente. Inicia sesión y completa MFA de nuevo.");
      } else {
        setError(caught instanceof ApiError ? caught.message : "No se pudieron generar códigos de respaldo.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthScreen>
      <Card>
        <Heading>Sesión autenticada</Heading>
        <Notice kind="success">Completaste la autenticación multifactor.</Notice>
        <Body>La sesión y su token viven solo en memoria de la aplicación.</Body>
        {error ? <Notice>{error}</Notice> : null}
        {!codes ? <PrimaryButton onPress={createBackupCodes} loading={loading}>Generar 10 códigos de respaldo</PrimaryButton> : null}
        {codes ? (
          <View style={styles.codeContainer}>
            <Notice kind="warning">Guárdalos ahora en un lugar seguro. Esta es la única vez que se muestran.</Notice>
            {codes.map((code) => <Text key={code} selectable style={styles.code}>{code}</Text>)}
          </View>
        ) : null}
        <SecondaryButton onPress={() => { session.clearSession(); router.replace("/login"); }}>Cerrar sesión</SecondaryButton>
      </Card>
    </AuthScreen>
  );
}

const styles = StyleSheet.create({
  codeContainer: { gap: 8 },
  code: { color: colors.text, fontFamily: "monospace", fontSize: 16, paddingVertical: 6, textAlign: "center", backgroundColor: "#f0f4f8", borderRadius: 6 },
});
