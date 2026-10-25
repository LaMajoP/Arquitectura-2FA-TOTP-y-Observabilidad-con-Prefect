import { Stack } from "expo-router";

import { SessionProvider } from "../lib/session";

export default function RootLayout() {
  // Root layouts stay mounted while Stack routes change, so this provider keeps
  // the in-memory JWT state throughout the MFA-to-session transition.
  return (
    <SessionProvider>
      <Stack screenOptions={{ headerShown: false }} />
    </SessionProvider>
  );
}
