from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from app.auth import AuthenticatedUser, TOKEN_TYPE_ACCESS, TokenIssuer, authenticate_token
from app.auth_service import MFAReplayDetectedError
from app.config import Settings
from app.mfa_strategies import MFAValidationResult
from app.prefect_mfa import (
    MFAFlowAuthenticationError,
    MFAFlowOrchestrator,
    ReplayAttackDetected,
    _MFAFlowContext,
    _contexts,
    check_anti_replay_cache,
    execute_mfa_strategy,
    mfa_step_up_flow,
)


def make_settings() -> Settings:
    return Settings(
        supabase_url="https://example.supabase.co",
        supabase_service_role_key="service-role-key",
        jwt_signing_key="x" * 32,
        jwt_algorithm="HS256",
        jwt_issuer="https://issuer.example.test",
        jwt_audience="totp-api",
        auth_rate_limit_key=b"y" * 32,
        totp_encryption_key=b"z" * 32,
        totp_encryption_key_version="v1",
        require_https=False,
        totp_verify_max_attempts=5,
        totp_verify_lock_seconds=900,
        login_max_attempts=5,
        login_lock_seconds=900,
        pre_auth_token_ttl_seconds=300,
        provisioning_token_ttl_seconds=900,
        access_token_ttl_seconds=3600,
        backup_code_recent_mfa_seconds=300,
        prefect_mfa_failure_mode="fail_closed",
    )


class ReplayRepository:
    def __init__(self, *, pre_auth_consumed: bool = False) -> None:
        self.pre_auth_consumed = pre_auth_consumed

    def is_pre_auth_token_consumed(self, user_id: object, token_id: object) -> bool:
        return self.pre_auth_consumed


class ReplayStepUpService:
    def verify(self, *args: object, **kwargs: object) -> MFAValidationResult:
        raise MFAReplayDetectedError("MFA authentication cannot be completed.")


class SuccessfulStepUpService:
    def verify(self, *args: object, **kwargs: object) -> MFAValidationResult:
        return MFAValidationResult(method="totp", totp_counter=100, totp_window=-1)


class PrefectMFAReplayTests(TestCase):
    def setUp(self) -> None:
        self.settings = make_settings()
        self.user_id = uuid4()
        self.pre_auth = TokenIssuer(self.settings).issue_pre_auth_token(self.user_id)

    def _add_context(
        self,
        *,
        repository: ReplayRepository | None = None,
        step_up_service: object | None = None,
    ) -> _MFAFlowContext:
        correlation_id = str(uuid4())
        context = _MFAFlowContext(
            correlation_id=correlation_id,
            raw_pre_auth_token=self.pre_auth.token,
            method="totp",
            credential="123456",
            settings=self.settings,
            repository=repository or ReplayRepository(),  # type: ignore[arg-type]
            step_up_service=step_up_service or ReplayStepUpService(),  # type: ignore[arg-type]
        )
        _contexts.add(context)
        self.addCleanup(_contexts.remove, correlation_id)
        return context

    def test_check_task_is_failed_when_supabase_confirms_replay_evidence(self) -> None:
        context = self._add_context()
        context.authenticated_user = AuthenticatedUser(
            user_id=self.user_id,
            token_id=uuid4(),
            token_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        context.replay_evidence = "totp_counter"

        state = check_anti_replay_cache(context.correlation_id, return_state=True)

        self.assertTrue(state.is_failed())
        with self.assertRaises(ReplayAttackDetected):
            state.result(raise_on_failure=True)

    def test_replayed_totp_fails_flow_at_the_anti_replay_task(self) -> None:
        context = self._add_context(step_up_service=ReplayStepUpService())

        state = mfa_step_up_flow(context.correlation_id, return_state=True)

        self.assertTrue(state.is_failed())
        with self.assertRaises(ReplayAttackDetected):
            state.result(raise_on_failure=True)
        self.assertEqual(context.replay_evidence, "totp_counter")
        self.assertIsNone(context.issued_session)

    def test_orchestrator_returns_generic_auth_failure_for_replay(self) -> None:
        orchestrator = MFAFlowOrchestrator(
            self.settings,
            ReplayRepository(),  # type: ignore[arg-type]
            ReplayStepUpService(),  # type: ignore[arg-type]
        )

        with self.assertRaises(MFAFlowAuthenticationError):
            orchestrator.complete(
                pre_auth_token=self.pre_auth.token,
                method="totp",
                credential="123456",
            )

    def test_access_token_is_issued_only_after_successful_mfa(self) -> None:
        orchestrator = MFAFlowOrchestrator(
            self.settings,
            ReplayRepository(),  # type: ignore[arg-type]
            SuccessfulStepUpService(),  # type: ignore[arg-type]
        )

        issued = orchestrator.complete(
            pre_auth_token=self.pre_auth.token,
            method="totp",
            credential="123456",
        )

        authenticated = authenticate_token(
            issued.token,
            self.settings,
            expected_token_type=TOKEN_TYPE_ACCESS,
            expected_mfa_verified=True,
        )
        self.assertEqual(authenticated.user_id, self.user_id)

    def test_prefect_event_payload_excludes_mfa_credentials(self) -> None:
        context = self._add_context(step_up_service=SuccessfulStepUpService())
        context.authenticated_user = AuthenticatedUser(
            user_id=self.user_id,
            token_id=uuid4(),
            token_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )

        with patch("app.prefect_mfa._logger.info") as backend_log, patch(
            "app.prefect_mfa.get_run_logger"
        ) as prefect_logger:
            result = execute_mfa_strategy.fn(context.correlation_id)

        self.assertEqual(result.status, "ok")
        rendered_logs = repr([*backend_log.call_args_list, *prefect_logger.return_value.info.call_args_list])
        self.assertNotIn(context.raw_pre_auth_token, rendered_logs)
        self.assertNotIn(context.credential, rendered_logs)
        self.assertNotIn(str(self.user_id), rendered_logs)
