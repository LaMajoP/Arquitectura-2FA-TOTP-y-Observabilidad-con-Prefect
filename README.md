# Arquitectura 2FA TOTP y observabilidad con Prefect

Este repositorio contiene una aplicación Expo y el backend FastAPI que realiza
registro, TOTP, Step-Up MFA, anti-replay, códigos de respaldo y observabilidad
con Prefect.

## Estructura

- [`backend-perfect`](backend-perfect/README.md) es el backend FastAPI y
  Prefect referido como `backend-prefect` en la guía de laboratorio. Se conserva
  su nombre para no romper los comandos, imports y rutas de las migraciones ya
  existentes; no es un backend distinto.
- [`mobile-authenticator`](mobile-authenticator/README.md) es la aplicación
  Expo Router para web, Android e iOS.

## Inicio local

1. Prepare un proyecto Supabase propio. No se incluye `supabase/config.toml` ni
   una instancia local en este repositorio, por lo que debe iniciar o seleccionar
   esa instancia según su instalación de Supabase. Ejecute manualmente, una sola
   vez y en orden, las migraciones `backend-perfect/sql/001` a `004` en un
   proyecto de pruebas; nunca contra producción sin revisión.
2. Siga la preparación de variables de entorno y el inicio del servidor Prefect
   y FastAPI en el [README del backend](backend-perfect/README.md#preparación-manual).
   Para ver los runs use `prefect server start` y abra
   `http://127.0.0.1:4200`; para el backend use `uvicorn main:app --reload` con
   `PREFECT_API_URL=http://127.0.0.1:4200/api`.
3. Configure `mobile-authenticator/.env` con `EXPO_PUBLIC_API_URL` y ejecute
   `npx expo start`. La guía para navegador, emulador y dispositivo físico está
   en el [README móvil](mobile-authenticator/README.md#configuración-y-ejecución).

No incluya `service_role`, claves JWT, claves AES, secretos Base32, contraseñas
ni tokens en la aplicación Expo, los logs o el control de versiones.
