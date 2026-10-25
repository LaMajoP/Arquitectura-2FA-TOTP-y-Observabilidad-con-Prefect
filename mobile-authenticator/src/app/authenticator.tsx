import { router } from "expo-router";
import { useCallback, useEffect, useState } from "react";
import { Platform, StyleSheet, Text, View } from "react-native";

import { AuthScreen, Body, Card, Heading, Notice, PrimaryButton, SecondaryButton, TextField, colors } from "../components/auth-ui";
import { generateTOTP, secondsRemaining } from "../artifacts/totp";
import { loadAuthenticatorAccounts, saveAuthenticatorAccounts, type AuthenticatorAccount } from "../lib/authenticator-storage";
import { normalizeBase32Secret } from "../lib/otpauth";

type DisplayAccount = AuthenticatorAccount & { code: string };

export default function AuthenticatorScreen() {
  const [accounts, setAccounts] = useState<AuthenticatorAccount[]>([]);
  const [displayAccounts, setDisplayAccounts] = useState<DisplayAccount[]>([]);
  const [issuer, setIssuer] = useState("Arquitectura 2FA");
  const [accountName, setAccountName] = useState("");
  const [secret, setSecret] = useState("");
  const [remaining, setRemaining] = useState(30);
  const [error, setError] = useState<string | null>(null);

  const updateCodes = useCallback(async (nextAccounts: AuthenticatorAccount[], timestamp = Date.now()) => {
    setRemaining(secondsRemaining(timestamp));
    const generated = await Promise.all(
      nextAccounts.map(async (account) => ({ ...account, code: await generateTOTP(account.secret, timestamp) })),
    );
    setDisplayAccounts(generated);
  }, []);

  useEffect(() => {
    let active = true;
    loadAuthenticatorAccounts()
      .then((stored) => {
        if (!active) return;
        setAccounts(stored);
        return updateCodes(stored);
      })
      .catch(() => active && setError("No se pudo leer el almacenamiento seguro del dispositivo."));
    return () => { active = false; };
  }, [updateCodes]);

  useEffect(() => {
    let active = true;
    const refresh = () => {
      if (!active) return;
      updateCodes(accounts).catch(() => active && setError("No se pudo generar un código TOTP local."));
    };
    refresh();
    const interval = setInterval(refresh, 500);
    return () => { active = false; clearInterval(interval); };
  }, [accounts, updateCodes]);

  async function addAccount(): Promise<void> {
    if (!issuer.trim() || !accountName.trim() || !secret.trim()) {
      setError("Ingresa emisor, cuenta y secreto Base32.");
      return;
    }
    try {
      const account: AuthenticatorAccount = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        issuer: issuer.trim(),
        accountName: accountName.trim(),
        secret: normalizeBase32Secret(secret),
      };
      const next = [...accounts, account];
      await saveAuthenticatorAccounts(next);
      setAccounts(next);
      setSecret("");
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "No se pudo guardar la cuenta de Authenticator.");
    }
  }

  async function removeAccount(id: string): Promise<void> {
    const next = accounts.filter((account) => account.id !== id);
    try {
      await saveAuthenticatorAccounts(next);
      setAccounts(next);
    } catch {
      setError("No se pudo actualizar el almacenamiento seguro del dispositivo.");
    }
  }

  return (
    <AuthScreen>
      <Card>
        <Heading>Authenticator offline</Heading>
        <Body>Los códigos se calculan localmente con la implementación TOTP existente. No se envía el secreto a ningún servicio.</Body>
        {Platform.OS === "web" ? <Notice kind="warning">En web los secretos solo viven en memoria y se eliminan al recargar o cerrar esta pestaña.</Notice> : null}
        {error ? <Notice>{error}</Notice> : null}
        {displayAccounts.map((account) => (
          <View key={account.id} style={styles.account}>
            <Text style={styles.accountName}>{account.issuer} · {account.accountName}</Text>
            <Text accessibilityLabel={`Código actual para ${account.accountName}`} selectable style={styles.code}>{account.code}</Text>
            <Text style={styles.remaining}>Cambia en {remaining} s</Text>
            <SecondaryButton onPress={() => removeAccount(account.id)}>Eliminar cuenta</SecondaryButton>
          </View>
        ))}
      </Card>
      <Card>
        <Heading>Añadir cuenta manualmente</Heading>
        <TextField label="Emisor" value={issuer} onChangeText={setIssuer} />
        <TextField label="Nombre de cuenta" value={accountName} onChangeText={setAccountName} autoCapitalize="none" />
        <TextField label="Secreto Base32" value={secret} onChangeText={setSecret} autoCapitalize="characters" autoCorrect={false} />
        <PrimaryButton onPress={addAccount}>Guardar y generar código</PrimaryButton>
        <SecondaryButton onPress={() => router.push("/scan-qr")}>Escanear un QR TOTP</SecondaryButton>
      </Card>
    </AuthScreen>
  );
}

const styles = StyleSheet.create({
  account: { gap: 5, paddingVertical: 12, borderBottomWidth: 1, borderColor: "#d9e2ec" },
  accountName: { color: colors.text, fontSize: 15, fontWeight: "600" },
  code: { color: colors.text, fontSize: 36, fontFamily: "monospace", fontWeight: "700", letterSpacing: 3 },
  remaining: { color: colors.muted, fontSize: 14 },
});
