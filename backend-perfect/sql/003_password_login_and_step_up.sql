-- Add password authentication and shared, backend-only authentication limits.
-- Run after 001_totp_secure_storage.sql and 002_totp_verify_rate_limit.sql.
-- This migration is additive: phase-2 users without password credentials stay
-- valid app_users rows and are not deleted or modified destructively.

ALTER TABLE public.app_users
    ADD COLUMN IF NOT EXISTS email text,
    ADD COLUMN IF NOT EXISTS password_hash text;

-- Password accounts are stored in the same UUID table used by TOTP. Existing
-- phase-2 accounts are permitted to have both new columns NULL. New accounts
-- must have both fields, an application-normalized email, and a nonempty hash.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'app_users_password_account_fields_check'
          AND conrelid = 'public.app_users'::regclass
    ) THEN
        ALTER TABLE public.app_users
            ADD CONSTRAINT app_users_password_account_fields_check CHECK (
                (email IS NULL AND password_hash IS NULL)
                OR (
                    email IS NOT NULL
                    AND password_hash IS NOT NULL
                    AND email = lower(email)
                    AND length(email) BETWEEN 3 AND 320
                    AND length(password_hash) > 0
                )
            ) NOT VALID;
    END IF;
END
$$;

ALTER TABLE public.app_users
    VALIDATE CONSTRAINT app_users_password_account_fields_check;

-- The API writes lower-case normalized email values. Indexing lower(email)
-- still protects uniqueness should another trusted writer use different case.
CREATE UNIQUE INDEX IF NOT EXISTS app_users_normalized_email_unique_idx
    ON public.app_users (lower(email))
    WHERE email IS NOT NULL;

-- subject_key is HMAC-SHA-256 generated in the backend from the normalized
-- email or UUID. It is not a password, JWT, TOTP secret, or plaintext email.
CREATE TABLE IF NOT EXISTS public.auth_rate_limit_attempts (
    scope text NOT NULL,
    subject_key text NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, subject_key),
    CONSTRAINT auth_rate_limit_attempts_scope_check CHECK (scope IN ('LOGIN', 'MFA')),
    CONSTRAINT auth_rate_limit_attempts_subject_key_check
        CHECK (subject_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT auth_rate_limit_attempts_nonnegative_count CHECK (attempt_count >= 0)
);

ALTER TABLE public.auth_rate_limit_attempts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.auth_rate_limit_attempts FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.auth_rate_limit_attempts TO service_role;

-- Reserve an authentication check before its password/TOTP validation. The row
-- lock serializes attempts for the same opaque subject across all API workers.
CREATE OR REPLACE FUNCTION public.consume_auth_rate_limit_attempt(
    p_scope text,
    p_subject_key text,
    p_max_attempts integer,
    p_lock_seconds integer
)
RETURNS TABLE (allowed boolean, locked_until timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    attempt_state public.auth_rate_limit_attempts%ROWTYPE;
    v_now timestamptz := clock_timestamp();
    new_locked_until timestamptz;
BEGIN
    IF p_scope NOT IN ('LOGIN', 'MFA')
       OR p_subject_key !~ '^[0-9a-f]{64}$'
       OR p_max_attempts NOT BETWEEN 1 AND 20
       OR p_lock_seconds NOT BETWEEN 60 AND 86400 THEN
        RAISE EXCEPTION 'Invalid authentication rate-limit input';
    END IF;

    INSERT INTO public.auth_rate_limit_attempts (scope, subject_key)
    VALUES (p_scope, p_subject_key)
    ON CONFLICT (scope, subject_key) DO NOTHING;

    SELECT *
    INTO attempt_state
    FROM public.auth_rate_limit_attempts
    WHERE scope = p_scope AND subject_key = p_subject_key
    FOR UPDATE;

    IF attempt_state.locked_until IS NOT NULL
       AND attempt_state.locked_until > v_now THEN
        RETURN QUERY SELECT false, attempt_state.locked_until;
        RETURN;
    END IF;

    IF attempt_state.locked_until IS NOT NULL THEN
        attempt_state.attempt_count := 0;
    END IF;

    IF attempt_state.attempt_count >= p_max_attempts THEN
        new_locked_until := v_now + make_interval(secs => p_lock_seconds);
        UPDATE public.auth_rate_limit_attempts
        SET locked_until = new_locked_until,
            updated_at = v_now
        WHERE scope = p_scope AND subject_key = p_subject_key;
        RETURN QUERY SELECT false, new_locked_until;
        RETURN;
    END IF;

    IF attempt_state.attempt_count + 1 = p_max_attempts THEN
        new_locked_until := v_now + make_interval(secs => p_lock_seconds);
    ELSE
        new_locked_until := NULL;
    END IF;

    UPDATE public.auth_rate_limit_attempts
    SET attempt_count = attempt_state.attempt_count + 1,
        locked_until = new_locked_until,
        updated_at = v_now
    WHERE scope = p_scope AND subject_key = p_subject_key;

    RETURN QUERY SELECT true, NULL::timestamptz;
END;
$$;

-- Successful validation clears only the matching scope; a success in LOGIN can
-- never clear MFA failures, and vice versa. DELETE remains encapsulated here.
CREATE OR REPLACE FUNCTION public.clear_auth_rate_limit_attempts(
    p_scope text,
    p_subject_key text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_scope NOT IN ('LOGIN', 'MFA')
       OR p_subject_key !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'Invalid authentication rate-limit input';
    END IF;

    DELETE FROM public.auth_rate_limit_attempts
    WHERE scope = p_scope AND subject_key = p_subject_key;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_auth_rate_limit_attempt(text, text, integer, integer)
    FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_auth_rate_limit_attempt(text, text, integer, integer)
    TO service_role;
REVOKE ALL ON FUNCTION public.clear_auth_rate_limit_attempts(text, text)
    FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.clear_auth_rate_limit_attempts(text, text)
    TO service_role;
