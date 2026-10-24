# TOTP artifact

Import the public API from the artifact, never from its internal files:

```ts
import { generateTOTP, secondsRemaining } from "@/artifacts/totp";

const code = await generateTOTP(base32Secret); // six digits, current device time
const testCode = await generateTOTP(base32Secret, 1_234_567_890_000); // milliseconds
const remaining = secondsRemaining();
```

The calculation is local and offline. It only needs the device clock, the
Base32 secret, and Expo Crypto's SHA-1 primitive.
