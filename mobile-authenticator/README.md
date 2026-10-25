# Cliente Expo: TOTP, QR y Step-Up MFA

Esta aplicación Expo Router usa el backend FastAPI real; no contiene una clave
de Supabase ni implementa otro algoritmo TOTP. El cálculo offline reutiliza
`src/artifacts/totp/` sin modificarlo.

## Pantallas y flujo

- `/register`: correo, contraseña, confirmación y validación local básica.
- `/login`: recibe un `provisioning_token` o `pre_auth_token` temporal y lo
  mantiene solo en memoria.
- `/totp-setup`: solicita la inscripción, muestra QR `otpauth://` y secreto
  Base32 una sola vez, y confirma el primer código contra el backend.
- `/authenticator`: importa una cuenta por QR o Base32 y genera TOTP offline.
- `/mfa-verify`: permite seleccionar `totp` o `backup_code` y llama a
  `/v1/auth/verify-mfa`.
- `/session`: confirma MFA, permite cerrar sesión y generar los diez códigos de
  respaldo durante la ventana de autenticación reciente.

El cliente transforma de manera genérica las respuestas `400`, `401`, `409`,
`422`, `429` y `503`; no presenta detalles que ayuden a enumerar cuentas,
códigos, tokens o estados internos.

## QR, escaneo y almacenamiento

El QR se genera en el dispositivo con `react-native-qrcode-svg`; su URI incluye
emisor, nombre de cuenta, secreto, `SHA1`, seis dígitos y período de 30 segundos.
No se utiliza una API externa para convertir secretos en imágenes. El escáner
con `expo-camera` pide permiso de cámara al usarlo y acepta únicamente URIs
`otpauth://totp` de esos mismos parámetros.

En Android e iOS, las semillas del Authenticator se cifran en el almacén seguro
del dispositivo mediante `expo-secure-store`. En web, por diseño, las semillas
solo viven en memoria y se eliminan al recargar/cerrar la pestaña: no se usan
`localStorage`, `sessionStorage`, IndexedDB ni cookies. Contraseñas y tokens de
sesión también se mantienen en memoria, por lo que un reinicio obliga a
autenticarse nuevamente.

## Configuración y ejecución

1. Desde `mobile-authenticator`, copie `.env.example` como `.env` y configure
   `EXPO_PUBLIC_API_URL`. Es una URL pública, nunca una clave.
2. Instale versiones compatibles con Expo SDK 58:

   ```bash
   npx expo install expo-camera expo-secure-store react-native-svg react-native-qrcode-svg
   ```

3. Inicie la aplicación:

   ```bash
   npx expo start
   ```

   Use `npx expo start --web` para el navegador. Para un emulador Android use
   `http://10.0.2.2:8000` como URL de desarrollo; para un dispositivo físico
   use la IP LAN del equipo solo en una red de desarrollo de confianza. En
   producción la URL debe ser HTTPS.

Para permitir la aplicación web, configure en el backend una lista exacta de
orígenes, por ejemplo `CORS_ALLOWED_ORIGINS=http://localhost:8081`. No use `*`.
En desarrollo local HTTP, el backend debe tener `TOTP_REQUIRE_HTTPS=false`;
manténgalo en `true` en todo entorno desplegado.

La cámara se configura mediante el plugin de Expo en `app.json`. Tras agregar
el módulo a un binario ya instalado, cree una nueva development build o use el
flujo de Expo apropiado para que la configuración nativa de permisos se aplique.

## Límites conocidos

La interfaz no sustituye pruebas de integración: fases 2–4 siguen pendientes de
validación real con Supabase. La app no muestra ni recupera códigos de respaldo
una segunda vez, no persiste sesiones y no implementa exportación de semillas.
Un usuario debe mantener la hora del dispositivo razonablemente sincronizada
para que los códigos offline coincidan con el backend.
