import type { ReactNode } from "react";
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
  type TextInputProps,
  type ViewStyle,
} from "react-native";

export const colors = {
  background: "#f7f9fc",
  surface: "#ffffff",
  primary: "#075985",
  primaryPressed: "#0c4a6e",
  text: "#102a43",
  muted: "#486581",
  border: "#bcccdc",
  error: "#b42318",
  warningBackground: "#fff7d6",
  success: "#067647",
};

export function AuthScreen({ children }: { children: ReactNode }) {
  return (
    <KeyboardAvoidingView
      style={styles.root}
      behavior={Platform.select({ ios: "padding", default: undefined })}>
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        <View style={styles.content}>{children}</View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

export function Card({ children, style }: { children: ReactNode; style?: ViewStyle }) {
  return <View style={[styles.card, style]}>{children}</View>;
}

export function Heading({ children }: { children: ReactNode }) {
  return <Text style={styles.heading}>{children}</Text>;
}

export function Body({ children }: { children: ReactNode }) {
  return <Text style={styles.body}>{children}</Text>;
}

export function Notice({ children, kind = "error" }: { children: ReactNode; kind?: "error" | "warning" | "success" }) {
  const style = kind === "error" ? styles.error : kind === "success" ? styles.success : styles.warning;
  return <Text accessibilityRole="alert" style={[styles.notice, style]}>{children}</Text>;
}

export function TextField({ label, ...props }: TextInputProps & { label: string }) {
  return (
    <View style={styles.field}>
      <Text style={styles.label}>{label}</Text>
      <TextInput
        accessibilityLabel={label}
        style={styles.input}
        placeholderTextColor="#627d98"
        autoCapitalize="none"
        autoCorrect={false}
        {...props}
      />
    </View>
  );
}

export function PrimaryButton({
  children,
  onPress,
  disabled = false,
  loading = false,
  accessibilityLabel,
}: {
  children: ReactNode;
  onPress: () => void;
  disabled?: boolean;
  loading?: boolean;
  accessibilityLabel?: string;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel}
      accessibilityState={{ disabled: disabled || loading }}
      disabled={disabled || loading}
      onPress={onPress}
      style={({ pressed }) => [styles.button, pressed && !disabled && styles.buttonPressed, (disabled || loading) && styles.buttonDisabled]}>
      {loading ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>{children}</Text>}
    </Pressable>
  );
}

export function SecondaryButton({ children, onPress, accessibilityLabel }: { children: ReactNode; onPress: () => void; accessibilityLabel?: string }) {
  return (
    <Pressable accessibilityRole="button" accessibilityLabel={accessibilityLabel} onPress={onPress} style={styles.secondaryButton}>
      <Text style={styles.secondaryButtonText}>{children}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  scroll: { flexGrow: 1, padding: 20, alignItems: "center" },
  content: { width: "100%", maxWidth: 520, gap: 16, paddingVertical: 20 },
  card: { backgroundColor: colors.surface, borderRadius: 16, padding: 20, gap: 14, shadowColor: "#102a43", shadowOpacity: 0.08, shadowRadius: 12, elevation: 2 },
  heading: { color: colors.text, fontSize: 26, lineHeight: 32, fontWeight: "700" },
  body: { color: colors.muted, fontSize: 16, lineHeight: 23 },
  field: { gap: 6 },
  label: { color: colors.text, fontSize: 15, fontWeight: "600" },
  input: { borderWidth: 1, borderColor: colors.border, borderRadius: 10, color: colors.text, backgroundColor: "#fff", paddingHorizontal: 12, paddingVertical: 12, fontSize: 16 },
  button: { alignItems: "center", justifyContent: "center", minHeight: 48, borderRadius: 10, backgroundColor: colors.primary, paddingHorizontal: 16 },
  buttonPressed: { backgroundColor: colors.primaryPressed },
  buttonDisabled: { opacity: 0.55 },
  buttonText: { color: "#fff", fontSize: 16, fontWeight: "700" },
  secondaryButton: { alignItems: "center", padding: 10 },
  secondaryButtonText: { color: colors.primary, fontSize: 16, fontWeight: "600" },
  notice: { borderRadius: 10, padding: 12, fontSize: 14, lineHeight: 20 },
  error: { color: colors.error, backgroundColor: "#ffebe9" },
  warning: { color: "#7a4d00", backgroundColor: colors.warningBackground },
  success: { color: colors.success, backgroundColor: "#d1fadf" },
});
