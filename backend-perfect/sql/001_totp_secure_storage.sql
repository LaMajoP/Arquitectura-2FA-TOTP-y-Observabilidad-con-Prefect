-- Secure, additive schema for application-owned TOTP enrollment.
-- Run this once in the Supabase SQL Editor using a project administrator.
-- It deliberately does not use Supabase Auth MFA tables or functions.

DO $$
BEGIN
    CREATE TYPE public.totp_status AS ENUM ('PENDING_VERIFICATION', 'ACTIVE');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END
$$;

-- This lightweight account table maps the UUID in the application's verified JWT
-- subject to the encrypted TOTP configuration. Do not store TOTP plaintext here.
CREATE TABLE IF NOT EXISTS public.app_users (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.totp_credentials (
    user_id uuid PRIMARY KEY REFERENCES public.app_users(id) ON DELETE RESTRICT,
    status public.totp_status NOT NULL DEFAULT 'PENDING_VERIFICATION',
    secret_ciphertext text NOT NULL,
    secret_nonce text NOT NULL,
    secret_tag text NOT NULL,
    encryption_key_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    CONSTRAINT totp_credentials_activation_state_check CHECK (
        (status = 'PENDING_VERIFICATION' AND activated_at IS NULL)
        OR (status = 'ACTIVE' AND activated_at IS NOT NULL)
    )
);

CREATE OR REPLACE FUNCTION public.set_totp_credentials_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'set_totp_credentials_updated_at'
          AND tgrelid = 'public.totp_credentials'::regclass
    ) THEN
        CREATE TRIGGER set_totp_credentials_updated_at
        BEFORE UPDATE ON public.totp_credentials
        FOR EACH ROW
        EXECUTE FUNCTION public.set_totp_credentials_updated_at();
    END IF;
END
$$;

-- Defense in depth: no browser role can list or retrieve encrypted fields.
ALTER TABLE public.app_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.totp_credentials ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.app_users FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.totp_credentials FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.app_users TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.totp_credentials TO service_role;
REVOKE ALL ON FUNCTION public.set_totp_credentials_updated_at() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_totp_credentials_updated_at() TO service_role;
