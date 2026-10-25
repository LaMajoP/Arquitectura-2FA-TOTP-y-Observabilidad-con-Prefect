# Backend: registro, login y Step-Up TOTP

El cálculo TOTP permanece en `totp/core.py` y no se ha reimplementado. El
backend cifra los secretos de aprovisionamiento con AES-256-GCM, conserva las
contraseñas exclusivamente como hashes Argon2id y usa Supabase solo desde el
servidor con la clave `service_role`.

## Preparación manual

1. En el SQL Editor de Supabase ejecute una vez y en orden
   [`sql/001_totp_secure_storage.sql`](sql/001_totp_secure_storage.sql),
   [`sql/002_totp_verify_rate_limit.sql`](sql/002_totp_verify_rate_limit.sql)
   y [`sql/003_password_login_and_step_up.sql`](sql/003_password_login_and_step_up.sql).
   La tercera migración es aditiva: añade las credenciales de contraseña a
   `app_users` y un límite compartido para login/Step-Up, sin alterar ni borrar
   datos de las dos fases anteriores.
2. Copie `.env.example` como `.env` y asigne secretos reales. `JWT_SECRET_KEY`,
   `TOTP_ENCRYPTION_KEY` y `AUTH_RATE_LIMIT_KEY` son secretos independientes.
   `AUTH_RATE_LIMIT_KEY` tiene al menos 32 bytes aleatorios y sirve para guardar
   en Supabase únicamente HMACs de los sujetos limitados, no correos en claro.
3. Genere la clave AES independiente en un entorno seguro:

   ```bash
   python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode('ascii'))"
   ```

   Guarde la salida completa solamente como `TOTP_ENCRYPTION_KEY`. Perderla
   impide descifrar los TOTP existentes; cambiarla requiere una futura rotación.
4. Instale las dependencias de `requirements.txt`. `argon2-cffi` implementa
   Argon2id con sal aleatoria por contraseña. Nunca copie `.env`, claves,
   contraseñas, JWT ni secretos TOTP a logs, clientes o control de versiones.
5. Mantenga `TOTP_REQUIRE_HTTPS=true` en producción. Si TLS termina en un
   proxy, este debe propagar de manera confiable el esquema HTTPS al ASGI.
   `false` es exclusivamente para desarrollo local aislado.

## Flujo de autenticación

1. `POST /v1/auth/register` recibe `email` y una contraseña de al menos 12
   caracteres. Crea un UUID y almacena en `app_users` el correo normalizado y
   solo el hash Argon2id; no inicia sesión.
2. `POST /v1/auth/login` recibe correo y contraseña. Una cuenta inexistente y
   una contraseña incorrecta producen la misma respuesta `401`. Hay cinco
   comprobaciones fallidas por correo (identificado por HMAC) y después un
   bloqueo compartido de 15 minutos, configurable mediante
   `AUTH_LOGIN_MAX_ATTEMPTS` y `AUTH_LOGIN_LOCK_SECONDS`.
3. Si las credenciales son correctas y TOTP está `ACTIVE`, login devuelve
   `status: "MFA_REQUIRED"` y un `pre_auth_token` de cinco minutos. No devuelve
   un JWT de acceso ni un claim de MFA verificado.
4. Si no existe TOTP o sigue `PENDING_VERIFICATION`, login devuelve
   `status: "TOTP_ENROLLMENT_REQUIRED"` y un `provisioning_token` limitado.
   Este es el único token que puede usar los endpoints de activación existentes:
   `POST /v1/totp/setup` y `POST /v1/totp/verify` con
   `Authorization: Bearer <provisioning_token>`. Sus rutas y transiciones de
   fase 2 se mantienen; solo se restringe explícitamente su tipo de JWT.
   Tras la transición a `ACTIVE`, inicie sesión otra vez para obtener el
   `pre_auth_token` y completar el Step-Up; la activación no emite una sesión.
5. `POST /v1/auth/verify-mfa` recibe `pre_auth_token` y `code` de seis dígitos.
   Valida firma, `iss`, `aud`, `exp`, UUID `sub`, UUID `jti`, `token_type` y
   `mfa_verified:false`; recupera el secreto cifrado, lo descifra únicamente en
   backend y llama al `verify_totp()` preexistente. Al acertar responde un
   `access_token` con `token_type: "access"` y `mfa_verified:true`.

Los tres JWT contienen `sub`, `iss`, `aud`, `iat`, `exp`, `jti`, `token_type`
y `mfa_verified`, pero son incompatibles por diseño:

| Token | Estado MFA | Uso permitido |
| --- | --- | --- |
| `provisioning` | `false` | Solo `/v1/totp/setup` y `/v1/totp/verify` |
| `pre_auth` | `false` | Solo `/v1/auth/verify-mfa` |
| `access` | `true` | Endpoints que exijan una sesión MFA completa |

La firma HMAC se verifica con un algoritmo configurado explícitamente
(`HS256`, `HS384` o `HS512`); editar claims manualmente invalida el JWT. Los JWT
no se almacenan en la base de datos. Las respuestas que devuelven tokens o el
único secreto de aprovisionamiento llevan `Cache-Control: no-store`.

El Step-Up también tiene una cuota compartida de cinco verificaciones por UUID
y bloqueo de 15 minutos (`TOTP_VERIFY_MAX_ATTEMPTS` y
`TOTP_VERIFY_LOCK_SECONDS`). El estado de ambos límites vive en Supabase y se
serializa con bloqueos de fila, así que se aplica entre procesos e instancias.

## Ejemplos de cuerpos

```json
POST /v1/auth/register
{"email":"persona@example.com","password":"una-contraseña-larga-y-unica"}
```

```json
POST /v1/auth/login
{"email":"persona@example.com","password":"una-contraseña-larga-y-unica"}
```

```json
POST /v1/auth/verify-mfa
{"pre_auth_token":"<token temporal>","code":"123456"}
```

## Limitación conocida: anti-replay pendiente

Esta fase no registra ni consume el contador TOTP validado. Por ello, durante
la ventana TOTP aceptada, un código válido puede reutilizarse si un atacante ya
posee un `pre_auth_token` vigente. La cuota limita intentos, pero **no es una
protección definitiva contra replay**. La fase de anti-replay deberá almacenar
atómicamente el último contador aceptado por usuario antes de presentar este
Step-Up como resistente a reutilización de códigos.

No se incluyen todavía códigos de respaldo, rotación de claves, QR, Prefect ni
una interfaz gráfica.
