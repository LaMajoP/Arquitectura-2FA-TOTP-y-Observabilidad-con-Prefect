# Backend: registro, login y Step-Up MFA

El cálculo TOTP permanece en `totp/core.py` y no se ha reimplementado. El
backend cifra los secretos de aprovisionamiento con AES-256-GCM, conserva las
contraseñas exclusivamente como hashes Argon2id y usa Supabase solo desde el
servidor con la clave `service_role`.

## Preparación manual

1. En el SQL Editor de Supabase ejecute una vez y en orden
   [`sql/001_totp_secure_storage.sql`](sql/001_totp_secure_storage.sql),
   [`sql/002_totp_verify_rate_limit.sql`](sql/002_totp_verify_rate_limit.sql),
   [`sql/003_password_login_and_step_up.sql`](sql/003_password_login_and_step_up.sql)
   y [`sql/004_mfa_strategies_and_anti_replay.sql`](sql/004_mfa_strategies_and_anti_replay.sql).
   La tercera migración es aditiva: añade las credenciales de contraseña a
   `app_users` y un límite compartido para login/Step-Up, sin alterar ni borrar
   datos de las dos fases anteriores. La cuarta añade las estrategias MFA,
   anti-replay TOTP, consumo único de `pre_auth`, códigos de respaldo y el
   registro concurrente de intentos por reserva individual.
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
5. `POST /v1/auth/verify-mfa` recibe `pre_auth_token`, `method` y `code`.
   `method` puede ser `"totp"` (valor compatible por defecto) o
   `"backup_code"`. La estrategia TOTP recupera y descifra el secreto solo en
   backend y llama al `verify_totp()` preexistente; la estrategia de respaldo
   compara únicamente hashes Argon2id. Un procedimiento SQL confirma en una
   sola transacción el factor, el contador o código consumido y el UUID `jti`.
   Al acertar responde un `access_token` con `mfa_verified:true`.
6. `POST /v1/auth/backup-codes` requiere `Authorization: Bearer <access_token>`
   con MFA completo emitido por un Step-Up realizado recientemente (cinco
   minutos por defecto, `AUTH_BACKUP_CODE_RECENT_MFA_SECONDS`). Si la ventana
   venció, el usuario debe iniciar sesión y completar MFA de nuevo. Revoca
   atómicamente los códigos vigentes y devuelve diez nuevos códigos de alta
   entropía una sola vez con `Cache-Control: no-store`.

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
serializa con bloqueos de fila. Un fallo conserva su consumo; un éxito libera
solo su propia reserva y nunca borra los fallos o reservas concurrentes, por lo
que el límite se aplica entre procesos e instancias. El bloqueo conserva el ID
de la reserva que lo activó: otro éxito concurrente no puede levantarlo antes
del plazo configurado.

## Anti-replay y códigos de respaldo

El estado TOTP guarda el mayor contador aceptado por usuario. La confirmación
atómica rechaza el mismo contador y cualquier contador inferior, de modo que
aceptar `C` o `C+1` también impide reutilizar una ventana anterior. El `jti` del
`pre_auth_token` se registra junto con el consumo del factor y no puede volver
a generar una sesión antes de que expire el JWT. Una verificación MFA inválida
no registra ese `jti`.

Los códigos de respaldo tienen 128 bits aleatorios y formato URL-safe. Se
entregan solo en la respuesta de generación; Supabase conserva únicamente sus
hashes Argon2id. Un código se marca usado dentro de la misma transacción que
consume el `pre_auth`; regenerar los códigos revoca los anteriores de forma
atómica.

## Prefect: flujo MFA observable

`POST /v1/auth/verify-mfa` ejecuta el flujo real `mfa_step_up`, no una copia de
demostración. El flujo se ejecuta en el mismo proceso del backend y conserva la
autoridad de seguridad en los servicios y funciones SQL existentes:

1. `validate_pre_auth_state` valida firma, caducidad, emisor, audiencia,
   propósito `pre_auth` y `mfa_verified:false`.
2. `check_anti_replay_cache` consulta el estado persistido de consumo de `jti`
   como señal de observación. Es intencionalmente solo orientativo: la función
   SQL de confirmación es la única autoridad para evitar carreras.
3. `execute_mfa_strategy` invoca la estrategia TOTP o `backup_code` existente.
   La estrategia y `confirm_mfa_step_up` mantienen en una transacción el
   consumo de contador/código, el `jti` y la reserva de límite de intentos.
4. `issue_elevated_session` firma el JWT `access` únicamente después de esa
   confirmación atómica.

Todas las tareas y el flow llevan `retries=0`. Un secreto, código, JWT,
contraseña o UUID de usuario no es argumento ni resultado de Prefect: el único
argumento es un UUID de correlación aleatorio. El contexto sensible vive solo
en memoria durante la solicitud y se elimina al terminar. Los resultados que
Prefect puede ver son estados seguros (`ok`, `authentication_failed`,
`rate_limited` o `storage_error`). Esto hace que una reiniciación del backend no
deje una sesión parcial en memoria: una petición posterior vuelve a validar el
JWT y el estado persistido de Supabase.

Los eventos JSON estructurados se emiten en el logger `mfa.observability` y en
el run de Prefect: `mfa_authentication_started`, `mfa_verification_succeeded`,
`mfa_code_invalid`, `mfa_totp_replay_detected`, `mfa_pre_auth_reused`,
`mfa_rate_limit_reached`, `mfa_supabase_error`, `mfa_prefect_unavailable` y
`mfa_flow_finished` (incluye `duration_ms`). Llevan `correlation_id` y método,
pero no correo, token, secreto o código. Los detalles de replay se usan solo
para observabilidad; la respuesta HTTP sigue siendo genérica.

Por defecto `PREFECT_MFA_FAILURE_MODE=fail_closed`: si la orquestación no puede
iniciar o ejecutar el flow, `/verify-mfa` responde `503` y no habilita acceso.
`direct_fallback` es una decisión explícita de disponibilidad; usa exactamente
la misma validación JWT, `StepUpService` y confirmación SQL, sin observabilidad
de Prefect. Ninguno de los dos modos puede emitir dos sesiones: si el error
ocurre después de confirmar SQL, el factor o `jti` puede quedar consumido y el
cliente debe iniciar login otra vez. Ese comportamiento conservador evita
debilitar el anti-replay.

Para desarrollo local reproducible, en terminales separados:

```bash
cd backend-perfect
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
prefect server start
```

```bash
cd backend-perfect
source .venv/bin/activate
export PREFECT_API_URL=http://127.0.0.1:4200/api
uvicorn main:app --reload
```

Abra `http://127.0.0.1:4200` para consultar flow runs, task runs, duración,
estado y errores. No se usa un deployment ni worker remoto: el registro de
contexto seguro es deliberadamente local al proceso web. Si no se configura un
servidor Prefect, la instalación de Prefect puede usar su modo efímero, pero no
hay una consola local durable; para inspección se debe iniciar `prefect server`.
No se requiere AWS ni infraestructura de pago.

La interfaz web necesita una lista de orígenes CORS explícitos mediante
`CORS_ALLOWED_ORIGINS`, por ejemplo `http://localhost:8081`. El backend no
habilita CORS cuando la variable está vacía y rechaza `*`, rutas o esquemas
distintos de HTTP(S). Las aplicaciones Android/iOS nativas no dependen de CORS.

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
{"pre_auth_token":"<token temporal>","method":"totp","code":"123456"}
```

```json
POST /v1/auth/verify-mfa
{"pre_auth_token":"<token temporal>","method":"backup_code","code":"<codigo-de-respaldo>"}
```

```http
POST /v1/auth/backup-codes
Authorization: Bearer <access_token con mfa_verified:true>
```

```json
{"backup_codes":["<codigo-1>","<codigo-2>","..."]}
```

Guarde esa respuesta fuera de la aplicación: no existe un endpoint para volver
a listar códigos, hashes, códigos usados o códigos revocados.

## Límites pendientes

No se incluyen rotación de claves, restablecimiento administrativo de MFA ni
eliminación programada de hashes históricos de respaldo. La limpieza de `jti`
expirados ocurre al confirmar MFA; para instalaciones con muy poca actividad
puede añadirse una futura tarea operativa que invoque una limpieza equivalente.
Prefect mejora trazabilidad, pero no sustituye métricas, alertas, retención de
logs ni pruebas de integración reales con Supabase.
