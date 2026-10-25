"""Prefect-backed, non-persistent observability for the real MFA Step-Up path."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

from prefect import flow, get_run_logger, task

from .auth import AuthenticatedUser, AuthorizationError, IssuedToken, TokenIssuer, authenticate_token
from .auth_service import (
    AuthenticationRateLimitError,
    AuthenticationStorageError,
    MFAAuthenticationError,
    MFAReplayDetectedError,
    PreAuthTokenReusedError,
    StepUpService,
)
from .config import Settings
from .database import DatabaseError, SupabaseTOTPRepository


_logger = logging.getLogger("mfa.observability")


class PrefectMFAUnavailableError(RuntimeError):
    """Prefect could not execute the MFA flow and fail-closed mode is active."""


class MFAFlowAuthenticationError(RuntimeError):
    """A generic MFA failure that preserves the public HTTP contract."""


class MFAFlowRateLimitError(RuntimeError):
    """The shared MFA allowance has been exhausted."""

    def __init__(self, locked_until: datetime) -> None:
        super().__init__("MFA authentication is temporarily locked.")
        self.locked_until = locked_until


class MFAFlowStorageError(RuntimeError):
    """Protected MFA persistence is unavailable."""


class ReplayAttackDetected(RuntimeError):
    """Supabase confirmed a reused pre-auth token or TOTP time counter."""

    def __init__(self, evidence: str) -> None:
        super().__init__("MFA replay was detected.")
        self.evidence = evidence


@dataclass(frozen=True, slots=True)
class SafeTaskResult:
    """A non-sensitive status that Prefect may retain transiently."""

    status: str
    locked_until: datetime | None = None


@dataclass(slots=True)
class _MFAFlowContext:
    """Sensitive input kept only in backend-process memory for one flow run."""

    correlation_id: str
    raw_pre_auth_token: str
    method: str
    credential: str
    settings: Settings
    repository: SupabaseTOTPRepository
    step_up_service: StepUpService
    authenticated_user: AuthenticatedUser | None = None
    pre_auth_seen: bool = False
    replay_evidence: str | None = None
    issued_session: IssuedToken | None = None
    started_at: float = field(default_factory=time.perf_counter)


class _MFAFlowContextRegistry:
    """Thread-safe local handoff that prevents secrets from becoming flow inputs."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._contexts: dict[str, _MFAFlowContext] = {}

    def add(self, context: _MFAFlowContext) -> None:
        with self._lock:
            self._contexts[context.correlation_id] = context

    def get(self, correlation_id: str) -> _MFAFlowContext:
        with self._lock:
            try:
                return self._contexts[correlation_id]
            except KeyError as exc:
                raise PrefectMFAUnavailableError("MFA flow context is unavailable.") from exc

    def remove(self, correlation_id: str) -> _MFAFlowContext | None:
        with self._lock:
            return self._contexts.pop(correlation_id, None)


_contexts = _MFAFlowContextRegistry()


def _observe(event: str, correlation_id: str, *, method: str | None = None, **details: object) -> None:
    """Emit structured observability without user IDs, credentials, or tokens."""
    payload: dict[str, object] = {"event": event, "correlation_id": correlation_id}
    if method is not None:
        payload["method"] = method
    payload.update(details)
    serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    _logger.info("mfa_event=%s", serialized)
    try:
        get_run_logger().info("mfa_event=%s", serialized)
    except Exception:
        # Standard backend logging remains available outside a Prefect task run.
        pass


@task(name="validate_pre_auth_state", retries=0, persist_result=False, log_prints=False)
def validate_pre_auth_state(correlation_id: str) -> SafeTaskResult:
    context = _contexts.get(correlation_id)
    _observe("mfa_authentication_started", correlation_id, method=context.method)
    try:
        context.authenticated_user = authenticate_token(
            context.raw_pre_auth_token,
            context.settings,
            expected_token_type="pre_auth",
            expected_mfa_verified=False,
        )
    except AuthorizationError:
        _observe("mfa_pre_auth_invalid", correlation_id, method=context.method)
        return SafeTaskResult(status="authentication_failed")

    if (
        context.authenticated_user.token_id is None
        or context.authenticated_user.token_expires_at is None
    ):
        _observe("mfa_pre_auth_invalid", correlation_id, method=context.method)
        return SafeTaskResult(status="authentication_failed")
    return SafeTaskResult(status="ok")


@task(name="check_anti_replay_cache", retries=0, persist_result=False, log_prints=False)
def check_anti_replay_cache(correlation_id: str) -> SafeTaskResult:
    """Fail observability only after Supabase has supplied replay evidence."""
    context = _contexts.get(correlation_id)
    user = context.authenticated_user
    if user is None or user.token_id is None:
        return SafeTaskResult(status="authentication_failed")

    # A TOTP replay is known only after strategy validation and the atomic SQL
    # confirmation. The flow invokes this task a second time in that case so
    # Prefect marks this dedicated anti-replay task as Failed.
    if context.replay_evidence is not None:
        _observe(
            "mfa_replay_attack_detected",
            correlation_id,
            method=context.method,
            evidence=context.replay_evidence,
        )
        raise ReplayAttackDetected(context.replay_evidence)

    try:
        context.pre_auth_seen = context.repository.is_pre_auth_token_consumed(user.user_id, user.token_id)
    except DatabaseError:
        _observe("mfa_supabase_error", correlation_id, method=context.method, stage="anti_replay_hint")
        return SafeTaskResult(status="storage_error")
    if context.pre_auth_seen:
        context.replay_evidence = "pre_auth_jti"
        _observe(
            "mfa_pre_auth_reused",
            correlation_id,
            method=context.method,
            evidence=context.replay_evidence,
        )
        raise ReplayAttackDetected(context.replay_evidence)
    return SafeTaskResult(status="ok")


@task(name="execute_mfa_strategy", retries=0, persist_result=False, log_prints=False)
def execute_mfa_strategy(correlation_id: str) -> SafeTaskResult:
    """Run the existing strategy plus its atomic Supabase confirmation unchanged."""
    context = _contexts.get(correlation_id)
    user = context.authenticated_user
    if user is None or user.token_id is None or user.token_expires_at is None:
        return SafeTaskResult(status="authentication_failed")
    try:
        validation = context.step_up_service.verify(
            user.user_id,
            method=context.method,
            credential=context.credential,
            pre_auth_token_id=user.token_id,
            pre_auth_expires_at=user.token_expires_at,
        )
    except PreAuthTokenReusedError:
        context.replay_evidence = "pre_auth_jti"
        _observe(
            "mfa_pre_auth_reused",
            correlation_id,
            method=context.method,
            evidence=context.replay_evidence,
        )
        return SafeTaskResult(status="replay_detected")
    except MFAReplayDetectedError:
        context.replay_evidence = "totp_counter"
        _observe(
            "mfa_totp_replay_detected",
            correlation_id,
            method=context.method,
            evidence=context.replay_evidence,
        )
        return SafeTaskResult(status="replay_detected")
    except AuthenticationRateLimitError as exc:
        _observe("mfa_rate_limit_reached", correlation_id, method=context.method)
        return SafeTaskResult(status="rate_limited", locked_until=exc.locked_until)
    except MFAAuthenticationError:
        _observe("mfa_code_invalid", correlation_id, method=context.method)
        return SafeTaskResult(status="authentication_failed")
    except AuthenticationStorageError:
        _observe("mfa_supabase_error", correlation_id, method=context.method, stage="strategy")
        return SafeTaskResult(status="storage_error")

    if validation.totp_window is not None:
        window_label = {-1: "C-1", 0: "C", 1: "C+1"}.get(validation.totp_window)
        if window_label is not None:
            _observe(
                "mfa_totp_window_validated",
                correlation_id,
                method=context.method,
                totp_window=window_label,
            )
    _observe("mfa_verification_succeeded", correlation_id, method=context.method)
    return SafeTaskResult(status="ok")


@task(name="issue_elevated_session", retries=0, persist_result=False, log_prints=False)
def issue_elevated_session(correlation_id: str) -> SafeTaskResult:
    """Issue the access JWT only after the strategy's atomic confirmation."""
    context = _contexts.get(correlation_id)
    user = context.authenticated_user
    if user is None:
        return SafeTaskResult(status="authentication_failed")
    context.issued_session = TokenIssuer(context.settings).issue_access_token(user.user_id)
    _observe("mfa_elevated_session_issued", correlation_id, method=context.method)
    return SafeTaskResult(status="ok")


@flow(name="mfa_step_up", retries=0, persist_result=False, log_prints=False)
def mfa_step_up_flow(correlation_id: str) -> SafeTaskResult:
    """The real MFA workflow; only the opaque correlation ID is a flow argument."""
    context = _contexts.get(correlation_id)
    final_result = SafeTaskResult(status="storage_error")
    try:
        for stage in (validate_pre_auth_state, check_anti_replay_cache, execute_mfa_strategy):
            result = stage(correlation_id)
            if result.status == "replay_detected":
                # Do not redo any MFA validation. This invocation only turns
                # already-confirmed Supabase replay evidence into a Failed task
                # run named check_anti_replay_cache.
                final_result = SafeTaskResult(status="replay_detected")
                return check_anti_replay_cache(correlation_id)
            if result.status != "ok":
                final_result = result
                return result
        result = issue_elevated_session(correlation_id)
        if result.status != "ok":
            final_result = result
            return result
        final_result = SafeTaskResult(status="ok")
        return final_result
    except ReplayAttackDetected:
        final_result = SafeTaskResult(status="replay_detected")
        raise
    finally:
        duration_ms = round((time.perf_counter() - context.started_at) * 1000, 2)
        _observe(
            "mfa_flow_finished",
            correlation_id,
            method=context.method,
            status=final_result.status,
            duration_ms=duration_ms,
        )


class MFAFlowOrchestrator:
    """Bridge FastAPI to Prefect while preserving the existing public errors."""

    def __init__(
        self,
        settings: Settings,
        repository: SupabaseTOTPRepository,
        step_up_service: StepUpService,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._step_up_service = step_up_service

    def complete(
        self,
        *,
        pre_auth_token: str,
        method: str,
        credential: str,
    ) -> IssuedToken:
        correlation_id = str(uuid4())
        context = _MFAFlowContext(
            correlation_id=correlation_id,
            raw_pre_auth_token=pre_auth_token,
            method=method,
            credential=credential,
            settings=self._settings,
            repository=self._repository,
            step_up_service=self._step_up_service,
        )
        _contexts.add(context)
        try:
            try:
                result = mfa_step_up_flow(correlation_id)
            except ReplayAttackDetected as exc:
                # The failed Prefect task is intentional and is not an
                # orchestration outage. Preserve the generic HTTP auth result.
                raise MFAFlowAuthenticationError("MFA authentication cannot be completed.") from exc
            except Exception as exc:
                _observe("mfa_prefect_unavailable", correlation_id, method=method)
                if self._settings.prefect_mfa_failure_mode == "direct_fallback":
                    return self._complete_direct(context)
                raise PrefectMFAUnavailableError("MFA orchestration is unavailable.") from exc

            if result.status == "authentication_failed":
                raise MFAFlowAuthenticationError("MFA authentication cannot be completed.")
            if result.status == "rate_limited":
                if result.locked_until is None:
                    raise MFAFlowStorageError("MFA rate-limit state is invalid.")
                raise MFAFlowRateLimitError(result.locked_until)
            if result.status != "ok" or context.issued_session is None:
                raise MFAFlowStorageError("MFA authentication storage is unavailable.")
            return context.issued_session
        finally:
            _contexts.remove(correlation_id)

    def _complete_direct(self, context: _MFAFlowContext) -> IssuedToken:
        """Explicit availability fallback using the same secure, atomic service path."""
        try:
            user = authenticate_token(
                context.raw_pre_auth_token,
                context.settings,
                expected_token_type="pre_auth",
                expected_mfa_verified=False,
            )
        except AuthorizationError as exc:
            raise MFAFlowAuthenticationError("MFA authentication cannot be completed.") from exc
        if user.token_id is None or user.token_expires_at is None:
            raise MFAFlowAuthenticationError("MFA authentication cannot be completed.")
        try:
            context.step_up_service.verify(
                user.user_id,
                method=context.method,
                credential=context.credential,
                pre_auth_token_id=user.token_id,
                pre_auth_expires_at=user.token_expires_at,
            )
        except AuthenticationRateLimitError as exc:
            raise MFAFlowRateLimitError(exc.locked_until) from exc
        except MFAAuthenticationError as exc:
            raise MFAFlowAuthenticationError("MFA authentication cannot be completed.") from exc
        except AuthenticationStorageError as exc:
            raise MFAFlowStorageError("MFA authentication storage is unavailable.") from exc
        return TokenIssuer(context.settings).issue_access_token(user.user_id)
