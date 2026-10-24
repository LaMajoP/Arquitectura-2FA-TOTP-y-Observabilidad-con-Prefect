import { Link } from "expo-router";
import { View, Text } from "react-native";

export default function HomeScreen() {
  return (
    <View style={{ flex: 1, justifyContent: "center", padding: 24 }}>
      <Link href="/totp-check">
        <Text style={{ fontSize: 22 }}>
          Abrir comprobación TOTP
        </Text>
      </Link>
    </View>
  );
}