# Backend: activación TOTP cifrada

Este backend conserva el cálculo TOTP existente en `totp/core.py`. Los dos
endpoints nuevos solamente almacenan un secreto de aprovisionamiento cifrado y
validan el primer código antes de activar su estado.

## Preparación manual

1. Ejecute, en orden, [`sql/001_totp_secure_storage.sql`](sql/001_totp_secure_storage.sql)
   y [`sql/002_totp_verify_rate_limit.sql`](sql/002_totp_verify_rate_limit.sql)
   una vez en el SQL Editor de Supabase. Son aditivos y no usan Supabase MFA.
2. Copie `.env.example` a `.env` y asigne valores reales. El archivo `.env` está
   ignorado por Git; no reutilice el `SUPABASE_KEY` de cliente para el backend.
3. Genere la clave AES independiente en un entorno seguro:

   ```bash
   python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode('ascii'))"
   ```

   Guarde la salida completa solo como `TOTP_ENCRYPTION_KEY` en un gestor de
   secretos o en las variables del servidor. Base64 representa los 32 bytes de
   la clave, no es el método de protección. Perder esa clave impide descifrar
   configuraciones existentes; cambiarla requiere una futura migración de claves.
4. Instale únicamente las dependencias de `requirements.txt` en su entorno de
   Python y ejecute el backend desde este directorio. En producción use HTTPS.
   Si TLS termina en un proxy, configúrelo para transmitir de manera confiable el
   esquema HTTPS al servidor ASGI. `TOTP_REQUIRE_HTTPS=false` solo es apropiado
   para desarrollo local aislado.

Los JWT de su futuro flujo de login deben ser HMAC (`HS256`, `HS384` o `HS512`),
tener `exp`, `sub` (UUID), `iss` y `aud`, y coincidir con las variables JWT.
El `sub` validado determina el usuario: ninguno de los endpoints acepta un
`user_id` enviado por el cliente. La clave JWT y `TOTP_ENCRYPTION_KEY` deben ser
secretos distintos.

## Endpoints

Ambos requieren `Authorization: Bearer <JWT válido>` y transporte HTTPS cuando
`TOTP_REQUIRE_HTTPS=true`.

- `POST /v1/totp/setup`: crea `PENDING_VERIFICATION`, cifra y persiste el
  secreto, y devuelve `secret_base32` solamente en esa respuesta. Incluye
  `Cache-Control: no-store`. Una cuenta con estado pendiente o activo recibe
  `409`; nunca se reemplaza un TOTP activo silenciosamente.
- `POST /v1/totp/verify` con `{"code":"123456"}`: recupera el registro del
  usuario autenticado, lo descifra solo en memoria del backend, llama a
  `verify_totp()` existente y hace la transición condicional a `ACTIVE`. Cada
  usuario puede comprobar cinco códigos; después del quinto se bloquean nuevas
  verificaciones durante 15 minutos y responden `429` con `Retry-After`. Ambos valores se pueden
  ajustar con `TOTP_VERIFY_MAX_ATTEMPTS` y `TOTP_VERIFY_LOCK_SECONDS`. El
  contador está en Supabase, por lo que se comparte entre procesos e instancias
  del backend. Una sola solicitud puede completar la transición a `ACTIVE`; una
  verificación válida concurrente que pierde la transición recibe `409`.

No hay endpoint para recuperar el secreto y las respuestas de verificación no
lo incluyen. Si se pierde esa única respuesta antes de activar la cuenta, esta
entrega mínima no permite regenerarla: será necesaria una futura operación
administrativa de reinicio, fuera del alcance actual.

## Límites actuales

No incluye login ni emisión de JWT/MFA final, Step-Up completo, QR, códigos de
respaldo, anti-replay, rotación de claves, interfaz gráfica o Prefect. Las
operaciones de datos usan la clave `service_role` exclusivamente en el backend;
no la exponga a una app móvil o web.
