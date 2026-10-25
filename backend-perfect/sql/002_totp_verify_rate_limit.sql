-- Shared, transaction-safe allowance for initial TOTP code verification.
-- Run this after 001_totp_secure_storage.sql in the Supabase SQL Editor.
-- It permits N code checks and then immediately blocks further requests for
-- the configured duration. The backend is the only caller and supplies N and
-- the duration.

CREATE TABLE IF NOT EXISTS public.totp_verification_attempts (
    user_id uuid PRIMARY KEY REFERENCES public.app_users(id) ON DELETE CASCADE,
    attempt_count integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT totp_verification_attempts_nonnegative_count CHECK (attempt_count >= 0)
);

ALTER TABLE public.totp_verification_attempts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.totp_verification_attempts FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.totp_verification_attempts TO service_role;

-- PostgreSQL serializes concurrent calls for an account using SELECT ... FOR
-- UPDATE. Reserving an attempt before checking the code prevents a burst of
-- parallel requests from evading the limit across workers or server instances.
CREATE OR REPLACE FUNCTION public.consume_totp_verification_attempt(
    p_user_id uuid,
    p_max_attempts integer,
    p_lock_seconds integer
)
RETURNS TABLE (allowed boolean, locked_until timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    attempt_state public.totp_verification_attempts%ROWTYPE;
    v_now timestamptz := clock_timestamp();
    new_locked_until timestamptz;
BEGIN
    IF p_max_attempts NOT BETWEEN 1 AND 20
       OR p_lock_seconds NOT BETWEEN 60 AND 86400 THEN
        RAISE EXCEPTION 'Invalid TOTP verification rate-limit configuration';
    END IF;

    INSERT INTO public.totp_verification_attempts (user_id)
    VALUES (p_user_id)
    ON CONFLICT (user_id) DO NOTHING;

    SELECT *
    INTO attempt_state
    FROM public.totp_verification_attempts
    WHERE user_id = p_user_id
    FOR UPDATE;

    IF attempt_state.locked_until IS NOT NULL
       AND attempt_state.locked_until > v_now THEN
        RETURN QUERY SELECT false, attempt_state.locked_until;
        RETURN;
    END IF;

    -- A completed lock starts a fresh allowance window.
    IF attempt_state.locked_until IS NOT NULL THEN
        attempt_state.attempt_count := 0;
    END IF;

    -- This is only reachable if a prior inconsistent row has the maximum count
    -- without a lock. Recover safely by beginning a lock without a code check.
    IF attempt_state.attempt_count >= p_max_attempts THEN
        new_locked_until := v_now + make_interval(secs => p_lock_seconds);
        UPDATE public.totp_verification_attempts
        SET locked_until = new_locked_until,
            updated_at = v_now
        WHERE user_id = p_user_id;

        RETURN QUERY SELECT false, new_locked_until;
        RETURN;
    END IF;

    -- The current request is one of the allowed code checks. If it consumes
    -- the last one, begin the lock now so parallel later requests cannot also
    -- inspect their code. Its successful response still remains possible.
    IF attempt_state.attempt_count + 1 = p_max_attempts THEN
        new_locked_until := v_now + make_interval(secs => p_lock_seconds);
    ELSE
        new_locked_until := NULL;
    END IF;

    UPDATE public.totp_verification_attempts
    SET attempt_count = attempt_state.attempt_count + 1,
        locked_until = new_locked_until,
        updated_at = v_now
    WHERE user_id = p_user_id;

    RETURN QUERY SELECT true, NULL::timestamptz;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_totp_verification_attempt(uuid, integer, integer)
    FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_totp_verification_attempt(uuid, integer, integer)
    TO service_role;
