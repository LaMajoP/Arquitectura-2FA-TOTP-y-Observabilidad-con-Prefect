import QRCode from "react-native-qrcode-svg";
import { Platform, StyleSheet, Text, View } from "react-native";

import { colors } from "./auth-ui";

/** Renders the URI locally; the Base32 seed is never sent to a QR web service. */
export function EnrollmentQr({ value }: { value: string }) {
  return (
    <View accessibilityLabel="Código QR de inscripción TOTP" style={styles.container}>
      <QRCode value={value} size={220} color="#102a43" backgroundColor="#ffffff" />
      {Platform.OS === "web" ? (
        <Text style={styles.caption}>En web el secreto se conserva solo mientras esta pestaña siga abierta.</Text>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { alignItems: "center", gap: 10, padding: 12, backgroundColor: "#fff", borderRadius: 12 },
  caption: { color: colors.muted, fontSize: 13, lineHeight: 18, textAlign: "center" },
});
