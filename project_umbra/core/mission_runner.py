"""
Project Umbra Background Mission Execution Manager.
Orchestrates asynchronous agent runs in background tasks, hooks real-time telemetry
to SSEBroadcasters and Database Repositories, and handles cancellations & timeouts.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import inspect
import logging
from typing import Any, Callable, TYPE_CHECKING
import uuid

if TYPE_CHECKING:
    from project_umbra.api.sse import SSEBroadcaster

from project_umbra.config import settings
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.production import build_production_agent
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentRunSummary,
    AgentTelemetryEvent,
    TargetIdentityInput,
    TelemetryEventType,
)
from project_umbra.storage.base import BasePersistenceRepository

logger = logging.getLogger("project_umbra.mission_runner")


class MissionExecutionManager:
    """
    Central background task orchestrator for Project Umbra.
    Manages running asyncio tasks, attaches real-time telemetry streaming hooks,
    persists intermediate and final results, and provides cancellation and timeout safety.
    """

    def __init__(
        self,
        repository: BasePersistenceRepository,
        sse_broadcaster: SSEBroadcaster,
        agent_factory: Callable[..., ProjectUmbraAgent] | None = None,
        default_timeout_seconds: float = 300.0,
    ) -> None:
        self.repository = repository
        self.sse_broadcaster = sse_broadcaster
        self.agent_factory = agent_factory or build_production_agent
        self.default_timeout_seconds = default_timeout_seconds

        self._active_tasks: dict[str, asyncio.Task[AgentRunSummary]] = {}
        self._active_agents: dict[str, ProjectUmbraAgent] = {}
        self._task_metadata: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    @property
    def active_mission_count(self) -> int:
        return len(self._active_tasks)

    def is_mission_active(self, scan_id: str) -> bool:
        task = self._active_tasks.get(scan_id)
        return task is not None and not task.done()

    async def start_mission(
        self,
        target_input: TargetIdentityInput,
        scan_id: str | None = None,
        timeout_seconds: float | None = None,
        max_budget: int | None = None,
        api_key: str | None = None,
    ) -> str:
        """
        Starts an autonomous investigation and action-planning mission in a background task.
        Pre-persists initial state to the database and returns the unique scan_id immediately.
        """
        run_id = scan_id or f"scan_{uuid.uuid4().hex[:10]}"
        timeout = timeout_seconds or self.default_timeout_seconds
        started_at = datetime.now(timezone.utc)

        # 1. Instantiate the fully composed agent. A request budget must never
        # bypass the production dependency factory.
        effective_budget = settings.AGENT_MAX_STEP_BUDGET if max_budget is None else max_budget
        factory_parameters = inspect.signature(self.agent_factory).parameters
        accepts_kwargs = any(
            param.kind == inspect.Parameter.VAR_KEYWORD
            for param in factory_parameters.values()
        )
        factory_kwargs: dict[str, Any] = {}
        if accepts_kwargs or "max_budget" in factory_parameters:
            factory_kwargs["max_budget"] = effective_budget
        if accepts_kwargs or "api_key" in factory_parameters:
            factory_kwargs["api_key"] = api_key
        agent = self.agent_factory(**factory_kwargs)
        if "max_budget" not in factory_kwargs:
            agent.max_budget = effective_budget

        # 2. Pre-persist initial run summary record
        initial_summary = AgentRunSummary(
            run_id=run_id,
            target_id=f"tgt_{run_id[:8]}",
            target_name=target_input.full_name,
            started_at=started_at,
            completed_at=started_at,
            final_state=AgentLifecycleState.INITIALIZED,
            total_steps_executed=0,
            budget_allocated=agent.max_budget,
            budget_remaining=agent.max_budget,
            vectors_analyzed=0,
            dorks_executed=0,
            brokers_scanned=0,
            exposures_found=0,
            pii_entities_sanitized=0,
            remediations_generated=0,
            execution_state_log=[],
        )
        try:
            await self.repository.save_scan(initial_summary)
        except Exception:
            try:
                await agent.close()
            except Exception as close_err:
                logger.warning(
                    "Failed to close mission dependencies after initial persistence failure (%s)",
                    type(close_err).__name__,
                )
            raise

        async with self._lock:
            self._active_agents[run_id] = agent
            self._task_metadata[run_id] = {
                "scan_id": run_id,
                "target_name": target_input.full_name,
                "started_at": started_at,
                "timeout_seconds": timeout,
            }

            # 3. Spawn background asyncio.Task
            task = asyncio.create_task(
                self._run_mission_worker(
                    scan_id=run_id,
                    target_input=target_input,
                    agent=agent,
                    timeout_seconds=timeout,
                    started_at=started_at,
                ),
                name=f"mission_{run_id}",
            )
            self._active_tasks[run_id] = task

        logger.info("Dispatched background mission %s", run_id)
        return run_id

    async def _run_mission_worker(
        self,
        scan_id: str,
        target_input: TargetIdentityInput,
        agent: ProjectUmbraAgent,
        timeout_seconds: float,
        started_at: datetime,
    ) -> AgentRunSummary:
        """
        Internal worker coroutine executing the agent with timeout, cancellation,
        SSE streaming, and real-time database persistence hooks.
        """
        async def telemetry_hook(event: AgentTelemetryEvent) -> None:
            # 1. Real-time SSE Broadcaster
            try:
                self.sse_broadcaster.publish(scan_id, event)
            except Exception as sse_err:
                logger.warning(
                    "Failed to broadcast SSE telemetry for scan %s (%s)",
                    scan_id,
                    type(sse_err).__name__,
                )

            # 2. Real-time Persistence Hook
            try:
                await self.repository.save_telemetry_event(scan_id, event)

            except Exception as db_err:
                logger.error(
                    "Failed to persist intermediate telemetry for scan %s (%s)",
                    scan_id,
                    type(db_err).__name__,
                )

        summary: AgentRunSummary | None = None
        try:
            async with asyncio.timeout(timeout_seconds):
                summary = await agent.run_mission(
                    target_input=target_input,
                    scan_id=scan_id,
                    event_callback=telemetry_hook,
                )

            # Persist completed mission summary
            await self.repository.save_scan(summary)

            for finding in summary.findings:
                await self.repository.save_finding(scan_id, finding)

            logger.info(f"Mission {scan_id} completed successfully in state {summary.final_state.value}")
            return summary

        except asyncio.TimeoutError:
            logger.error(f"Mission {scan_id} timed out after {timeout_seconds} seconds")
            completed_at = datetime.now(timezone.utc)
            timeout_event = AgentTelemetryEvent(
                scan_id=scan_id,
                event_type=TelemetryEventType.SCAN_FAILED,
                state=AgentLifecycleState.FAILED,
                message=f"Mission timed out after {timeout_seconds} seconds.",
                step_number=agent._step_count,
                budget_remaining=0,
                payload={"error": "TIMEOUT", "timeout_seconds": timeout_seconds},
            )
            self.sse_broadcaster.publish(scan_id, timeout_event)

            partial_summary = AgentRunSummary(
                run_id=scan_id,
                target_id=f"tgt_{scan_id[:8]}",
                target_name=target_input.full_name,
                started_at=started_at,
                completed_at=completed_at,
                final_state=AgentLifecycleState.FAILED,
                total_steps_executed=agent._step_count,
                budget_allocated=agent.max_budget,
                budget_remaining=0,
                vectors_analyzed=0,
                dorks_executed=0,
                brokers_scanned=0,
                exposures_found=0,
                pii_entities_sanitized=0,
                remediations_generated=0,
                execution_state_log=agent._execution_log,
            )
            await self.repository.save_scan(partial_summary)
            return partial_summary

        except asyncio.CancelledError:
            logger.warning(f"Mission {scan_id} was cancelled by client/system")
            completed_at = datetime.now(timezone.utc)
            cancel_event = AgentTelemetryEvent(
                scan_id=scan_id,
                event_type=TelemetryEventType.SCAN_FAILED,
                state=AgentLifecycleState.FAILED,
                message="Mission was cancelled by user request.",
                step_number=agent._step_count,
                budget_remaining=max(0, agent.max_budget - agent._step_count),
                payload={"error": "CANCELLED"},
            )
            self.sse_broadcaster.publish(scan_id, cancel_event)

            cancel_summary = AgentRunSummary(
                run_id=scan_id,
                target_id=f"tgt_{scan_id[:8]}",
                target_name=target_input.full_name,
                started_at=started_at,
                completed_at=completed_at,
                final_state=AgentLifecycleState.FAILED,
                total_steps_executed=agent._step_count,
                budget_allocated=agent.max_budget,
                budget_remaining=max(0, agent.max_budget - agent._step_count),
                vectors_analyzed=0,
                dorks_executed=0,
                brokers_scanned=0,
                exposures_found=0,
                pii_entities_sanitized=0,
                remediations_generated=0,
                execution_state_log=agent._execution_log,
            )
            await self.repository.save_scan(cancel_summary)
            raise

        except Exception as unhandled_err:
            logger.error(
                "Mission %s failed due to unexpected %s",
                scan_id,
                type(unhandled_err).__name__,
            )
            completed_at = datetime.now(timezone.utc)
            fail_event = AgentTelemetryEvent(
                scan_id=scan_id,
                event_type=TelemetryEventType.SCAN_FAILED,
                state=AgentLifecycleState.FAILED,
                message="Mission encountered an unexpected runtime failure.",
                step_number=agent._step_count,
                budget_remaining=0,
                payload={"error": "RUNTIME_FAILURE", "error_type": type(unhandled_err).__name__},
            )
            self.sse_broadcaster.publish(scan_id, fail_event)

            fail_summary = AgentRunSummary(
                run_id=scan_id,
                target_id=f"tgt_{scan_id[:8]}",
                target_name=target_input.full_name,
                started_at=started_at,
                completed_at=completed_at,
                final_state=AgentLifecycleState.FAILED,
                total_steps_executed=agent._step_count,
                budget_allocated=agent.max_budget,
                budget_remaining=0,
                vectors_analyzed=0,
                dorks_executed=0,
                brokers_scanned=0,
                exposures_found=0,
                pii_entities_sanitized=0,
                remediations_generated=0,
                execution_state_log=agent._execution_log,
            )
            await self.repository.save_scan(fail_summary)
            return fail_summary

        finally:
            try:
                await agent.close()
            except Exception as close_err:
                logger.warning(
                    "Failed to close mission dependencies for %s (%s)",
                    scan_id,
                    type(close_err).__name__,
                )

            async with self._lock:
                self._active_tasks.pop(scan_id, None)
                self._active_agents.pop(scan_id, None)
                self._task_metadata.pop(scan_id, None)

            self.sse_broadcaster.publish_eof(scan_id)

    async def cancel_mission(self, scan_id: str) -> bool:
        """
        Cancels an ongoing background mission task.
        Returns True if task was active and cancelled; False if not found or already complete.
        """
        async with self._lock:
            task = self._active_tasks.get(scan_id)
            if task and not task.done():
                task.cancel()
                logger.info(f"Signaled cancellation for mission {scan_id}")
                return True
            return False

    async def get_mission(self, scan_id: str) -> AgentRunSummary | None:
        """Retrieves scan summary from repository."""
        return await self.repository.get_scan(scan_id)

    async def list_missions(self, limit: int = 50, offset: int = 0) -> list[AgentRunSummary]:
        """Lists historical mission runs."""
        return await self.repository.list_scans(limit=limit, offset=offset)

    async def shutdown(self) -> None:
        """Gracefully cancels all active tasks on server shutdown."""
        async with self._lock:
            tasks_to_cancel = [t for t in self._active_tasks.values() if not t.done()]
            for t in tasks_to_cancel:
                t.cancel()

        if tasks_to_cancel:
            logger.info(f"Awaiting termination of {len(tasks_to_cancel)} active mission tasks on shutdown")
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
        self._active_tasks.clear()
        self._active_agents.clear()
        self._task_metadata.clear()
