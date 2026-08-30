"""
Project Umbra Autonomous OSINT Investigation & Action-Planning Agent Core.
Integrates Google GenAI SDK, explicit PII classification, FSM State Transitions, Step Budget Controller,
Loop Prevention, and Live SSE Telemetry Event Streaming.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from project_umbra.config import settings
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentRunSummary,
    AgentStepRecord,
    AgentTelemetryEvent,
    BrokerScanResult,
    BrokerScanTarget,
    DorkQuery,
    DorkSynthesisResult,
    ExecutionProvenance,
    ExtractedEntityProfile,
    IdentityDecompositionResult,
    PIISanitizationResult,
    SuppressionActionPlan,
    SuppressionPayload,
    SuppressionStatus,
    TargetIdentityInput,
    TelemetryEventType,
)


class BudgetExhaustedException(Exception):
    """Raised internally when step budget is depleted."""
    pass


class ProjectUmbraAgent:
    """
    Autonomous OSINT investigation and approval-gated action-planning agent.
    Governed by an explicit step-budgeted Finite State Machine (FSM)
    with strict loop prevention and graceful budget exhaustion recovery.
    """

    DEFAULT_BROKER_TARGETS = [
        BrokerScanTarget(
            broker_id="truepeoplesearch",
            broker_name="TruePeopleSearch",
            base_url="https://www.truepeoplesearch.com",
            opt_out_url="https://www.truepeoplesearch.com/removal",
            search_url_template="https://www.truepeoplesearch.com/results?name={name}&citystatezip={location}",
        ),
        BrokerScanTarget(
            broker_id="fastpeoplesearch",
            broker_name="FastPeopleSearch",
            base_url="https://www.fastpeoplesearch.com",
            opt_out_url="https://www.fastpeoplesearch.com/removal",
            search_url_template="https://www.fastpeoplesearch.com/name/{name}_{location}",
        ),
        BrokerScanTarget(
            broker_id="radaris",
            broker_name="Radaris",
            base_url="https://radaris.com",
            opt_out_url="https://radaris.com/control/privacy",
            search_url_template="https://radaris.com/p/{name}",
        ),
        BrokerScanTarget(
            broker_id="nuwber",
            broker_name="Nuwber",
            base_url="https://nuwber.com",
            opt_out_url="https://nuwber.com/removal/link",
            search_url_template="https://nuwber.com/person/{name}",
        ),
        BrokerScanTarget(
            broker_id="whitepages",
            broker_name="Whitepages",
            base_url="https://www.whitepages.com",
            opt_out_url="https://www.whitepages.com/suppression-requests",
            search_url_template="https://www.whitepages.com/name/{name}/{location}",
        ),
    ]

    def __init__(
        self,
        gemini_client: Any | None = None,
        decomposer: Any | None = None,
        dork_synthesizer: Any | None = None,
        serp_scanner: Any | None = None,
        browser_scanner: Any | None = None,
        extractor: Any | None = None,
        gemma_sanitizer: Any | None = None,
        suppression_engine: Any | None = None,
        max_budget: int = 25,
        broker_targets: list[BrokerScanTarget] | None = None,
    ) -> None:
        self.client = gemini_client
        self.decomposer = decomposer
        self.dork_synthesizer = dork_synthesizer
        self.serp_scanner = serp_scanner
        self.browser_scanner = browser_scanner
        self.extractor = extractor
        self.gemma_sanitizer = gemma_sanitizer
        if suppression_engine is None:
            from project_umbra.tools.suppression_engine import SuppressionEngine
            self.suppression_engine = SuppressionEngine()
        else:
            self.suppression_engine = suppression_engine
        self.max_budget = max_budget
        self.broker_targets = broker_targets or self.DEFAULT_BROKER_TARGETS

        # Internal Execution State
        self._step_count = 0
        self._action_call_counts: dict[str, int] = {}
        self._execution_log: list[AgentStepRecord] = []
        self._tool_provenance: dict[str, ExecutionProvenance] = {}
        self._models_used: set[str] = set()
        self._model_invocations: list[dict[str, Any]] = []
        self._closed = False

    async def close(self) -> None:
        """Close mission-scoped scanner resources without dispatching actions."""
        if self._closed:
            return
        self._closed = True
        close_errors: list[BaseException] = []
        for dependency in (self.browser_scanner, self.suppression_engine):
            close = getattr(dependency, "close", None)
            if close is None:
                continue
            try:
                result = close()
                if asyncio.iscoroutine(result):
                    await result
            except BaseException as exc:
                close_errors.append(exc)
        if self.client is not None:
            async_client = getattr(self.client, "aio", None)
            async_close = getattr(async_client, "aclose", None)
            if async_close is not None:
                try:
                    result = async_close()
                    if asyncio.iscoroutine(result):
                        await result
                except BaseException as exc:
                    close_errors.append(exc)
            sync_close = getattr(self.client, "close", None)
            if sync_close is not None:
                try:
                    result = sync_close()
                    if asyncio.iscoroutine(result):
                        await result
                except BaseException as exc:
                    close_errors.append(exc)
        if close_errors:
            raise close_errors[0]

    async def run_mission(
        self,
        target_input: TargetIdentityInput,
        scan_id: str | None = None,
        event_callback: Callable[[AgentTelemetryEvent], Awaitable[None]] | None = None,
    ) -> AgentRunSummary:
        """
        Executes the full end-to-end autonomous mission cycle.
        """
        run_id = scan_id or f"scan_{uuid.uuid4().hex[:10]}"
        target_id = f"tgt_{uuid.uuid4().hex[:8]}"
        started_at = datetime.now(timezone.utc)
        current_state = AgentLifecycleState.INITIALIZED
        self._step_count = 0
        self._action_call_counts.clear()
        self._execution_log.clear()
        self._tool_provenance.clear()
        self._models_used.clear()
        self._model_invocations.clear()

        # Telemetry Emission Helper
        async def emit_telemetry(
            event_type: TelemetryEventType,
            state: AgentLifecycleState,
            message: str,
            payload: dict[str, Any] | None = None,
        ) -> None:
            budget_rem = max(0, self.max_budget - self._step_count)
            event = AgentTelemetryEvent(
                scan_id=run_id,
                event_type=event_type,
                state=state,
                message=message,
                step_number=self._step_count,
                budget_remaining=budget_rem,
                payload=payload or {},
            )
            if event_callback:
                try:
                    await event_callback(event)
                except Exception:
                    pass  # Non-blocking telemetry delivery

        # Step Accounting Helper
        def record_step(
            state: AgentLifecycleState,
            thought: str | None = None,
            tool_name: str | None = None,
            tool_input: dict[str, Any] | None = None,
            tool_output_summary: str | None = None,
            duration_ms: float = 0.0,
            provenance: ExecutionProvenance = ExecutionProvenance.LIVE,
        ) -> int:
            self._step_count += 1
            budget_rem = max(0, self.max_budget - self._step_count)
            rec = AgentStepRecord(
                step_number=self._step_count,
                state=state,
                thought=thought,
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output_summary=tool_output_summary,
                step_duration_ms=duration_ms,
                budget_remaining=budget_rem,
                provenance=provenance,
            )
            self._execution_log.append(rec)
            if tool_name:
                self._tool_provenance[tool_name] = provenance
            return budget_rem

        # Loop Detection Helper
        def check_loop(tool_name: str, args: dict[str, Any]) -> bool:
            sig = f"{tool_name}:{json.dumps(args, sort_keys=True, default=str)}"
            count = self._action_call_counts.get(sig, 0) + 1
            self._action_call_counts[sig] = count
            return count > 2  # Max 2 repeated calls allowed

        # -------------------------------------------------------------
        # Mission Lifecycle Loop
        # -------------------------------------------------------------
        decomposition_res: IdentityDecompositionResult | None = None
        dork_res: DorkSynthesisResult | None = None
        serp_findings: list[Any] = []
        broker_findings: list[BrokerScanResult] = []
        extracted_profiles: list[ExtractedEntityProfile] = []
        sanitization_res: PIISanitizationResult | None = None
        remediation_plan: SuppressionActionPlan | None = None

        await emit_telemetry(
            TelemetryEventType.SCAN_INITIATED,
            AgentLifecycleState.INITIALIZED,
            f"Autonomous scan initiated for authorized target reference: {target_id}",
            {
                "target_id": target_id,
                "identity_vector_counts": {
                    "aliases": len(target_input.aliases),
                    "emails": int(bool(target_input.primary_email)) + len(target_input.secondary_emails),
                    "phones": len(target_input.phone_numbers),
                    "locations": int(bool(target_input.current_city)) + len(target_input.known_addresses),
                    "usernames": len(target_input.usernames),
                },
                "provenance": ExecutionProvenance.LIVE.value,
                "execution_contract": "investigation_and_action_plan_only",
                "external_actions_dispatched": 0,
            },
        )

        try:
            # =========================================================
            # Phase 1: Identity Decomposition
            # =========================================================
            if self._step_count >= self.max_budget:
                raise BudgetExhaustedException()

            current_state = AgentLifecycleState.DECOMPOSING_IDENTITY
            await emit_telemetry(
                TelemetryEventType.STATE_TRANSITION,
                current_state,
                "Decomposing target identity into multi-dimensional investigative vectors",
            )

            t0 = time.perf_counter()
            if self.decomposer:
                if asyncio.iscoroutinefunction(getattr(self.decomposer, "decompose", None)):
                    decomposition_res = await self.decomposer.decompose(target_input, target_id=target_id)
                else:
                    decomposition_res = self.decomposer.decompose(target_input, target_id=target_id)
            else:
                from project_umbra.core.decomposer import IdentityDecomposer
                decomposition_res = IdentityDecomposer().decompose(target_input, target_id=target_id)

            dur = (time.perf_counter() - t0) * 1000
            record_step(
                current_state,
                thought=f"Extracted {len(decomposition_res.vectors)} investigative vectors across 5 categories.",
                tool_name="identity_decomposer",
                tool_input={"target_id": target_id},
                tool_output_summary=f"Generated {len(decomposition_res.vectors)} vectors.",
                duration_ms=dur,
            )
            await emit_telemetry(
                TelemetryEventType.TOOL_COMPLETE,
                current_state,
                f"Identity decomposed into {len(decomposition_res.vectors)} vectors.",
                {"vector_count": len(decomposition_res.vectors)},
            )

            # =========================================================
            # Phase 2: Precision Dork Synthesis
            # =========================================================
            if self._step_count >= self.max_budget:
                raise BudgetExhaustedException()

            current_state = AgentLifecycleState.SYNTHESIZING_DORKS
            await emit_telemetry(
                TelemetryEventType.STATE_TRANSITION,
                current_state,
                "Synthesizing precision Google search dorks across 7 taxonomies",
            )

            t0 = time.perf_counter()
            if self.dork_synthesizer:
                if asyncio.iscoroutinefunction(getattr(self.dork_synthesizer, "synthesize", None)):
                    dork_res = await self.dork_synthesizer.synthesize(decomposition_res)
                else:
                    dork_res = self.dork_synthesizer.synthesize(decomposition_res)
            else:
                from project_umbra.core.dork_synthesizer import PrecisionDorkSynthesizer
                dork_res = PrecisionDorkSynthesizer().synthesize(decomposition_res)

            dur = (time.perf_counter() - t0) * 1000
            record_step(
                current_state,
                thought=f"Synthesized {len(dork_res.dorks)} precision dorks targeting pastebins, leaks, and broker profiles.",
                tool_name="dork_synthesizer",
                tool_input={"vector_count": len(decomposition_res.vectors)},
                tool_output_summary=f"Synthesized {len(dork_res.dorks)} search dorks.",
                duration_ms=dur,
            )
            for d in dork_res.dorks[:3]:
                await emit_telemetry(
                    TelemetryEventType.DORK_DISCOVERED,
                    current_state,
                    f"Synthesized authorized search dork in {d.category.value}",
                    {
                        "dork_id": d.dork_id,
                        "category": d.category.value,
                        "risk_level": d.risk_level.value,
                    },
                )

            # =========================================================
            # Phase 3: SERP & Broker Scanning
            # =========================================================
            # 3.1 SERP Scanning
            if self._step_count < self.max_budget:
                current_state = AgentLifecycleState.SCANNING_SERP
                await emit_telemetry(
                    TelemetryEventType.STATE_TRANSITION,
                    current_state,
                    "Executing prioritized search dorks against SERP engine",
                )
                t0 = time.perf_counter()
                prioritized_dorks = dork_res.dorks[:5]
                if self.serp_scanner:
                    for dork in prioritized_dorks:
                        if self._step_count >= self.max_budget:
                            break
                        if check_loop("serp_scanner", {"dork_id": dork.dork_id}):
                            await emit_telemetry(
                                TelemetryEventType.LOOP_DETECTED,
                                current_state,
                                f"Loop detected for dork {dork.dork_id}, suppressing repeated scan",
                            )
                            continue
                        findings = await self.serp_scanner.execute_dork(
                            dork,
                            target_name=target_input.full_name,
                            target_input=target_input,
                        )
                        serp_findings.extend(findings)
                        serp_provenance = getattr(
                            self.serp_scanner,
                            "last_provenance",
                            findings[0].provenance if findings else ExecutionProvenance.LIVE,
                        )
                        serp_tool_name = {
                            ExecutionProvenance.LIVE: "serp_scanner",
                            ExecutionProvenance.CONTROLLED_FIXTURE: "controlled_serp_fixture",
                            ExecutionProvenance.FALLBACK: "serp_fixture_fallback",
                        }[ExecutionProvenance(serp_provenance)]
                        record_step(
                            current_state,
                            tool_name=serp_tool_name,
                            tool_input={"dork_id": dork.dork_id},
                            tool_output_summary=f"Found {len(findings)} SERP results.",
                            provenance=ExecutionProvenance(serp_provenance),
                        )
                        await emit_telemetry(
                            TelemetryEventType.TOOL_COMPLETE,
                            current_state,
                            f"Search query completed with {len(findings)} findings",
                            {
                                "tool": serp_tool_name,
                                "dork_id": dork.dork_id,
                                "finding_count": len(findings),
                                "provenance": ExecutionProvenance(serp_provenance).value,
                            },
                        )
                        provider_invocation = getattr(self.serp_scanner, "last_model_invocation", None)
                        if (
                            ExecutionProvenance(serp_provenance) == ExecutionProvenance.LIVE
                            and isinstance(provider_invocation, dict)
                        ):
                            invocation = {**provider_invocation, "dork_id": dork.dork_id}
                            self._model_invocations.append(invocation)
                            requested_model = invocation.get("requested_model")
                            if isinstance(requested_model, str):
                                self._models_used.add(requested_model)
                else:
                    self._tool_provenance["serp_scanner"] = ExecutionProvenance.FALLBACK
                dur = (time.perf_counter() - t0) * 1000

            # 3.2 Data Broker Stealth Scanning
            if self._step_count < self.max_budget:
                current_state = AgentLifecycleState.SCANNING_BROKERS
                await emit_telemetry(
                    TelemetryEventType.STATE_TRANSITION,
                    current_state,
                    "Scanning configured broker sources; every result reports live, controlled-fixture, or fallback provenance",
                )
                location = f"{target_input.current_city or ''} {target_input.current_state or ''}".strip() or None
                for broker in self.broker_targets:
                    if self._step_count >= self.max_budget:
                        break
                    if check_loop("browser_scanner", {"broker_id": broker.broker_id}):
                        await emit_telemetry(
                            TelemetryEventType.LOOP_DETECTED,
                            current_state,
                            f"Loop detected for broker {broker.broker_id}, suppressing repeated scan",
                        )
                        continue

                    t0 = time.perf_counter()
                    if self.browser_scanner:
                        b_res = await self.browser_scanner.scan_broker(broker, target_input)
                    else:
                        # Fallback simulation
                        phone_val = target_input.phone_numbers[0] if target_input.phone_numbers else "555-0199"
                        email_val = target_input.primary_email or "user@example.com"
                        b_res = BrokerScanResult(
                            broker_id=broker.broker_id,
                            target_name=target_input.full_name,
                            target_location=location,
                            is_exposed=True,
                            profile_url=f"{broker.base_url}/p/{target_input.full_name.replace(' ', '-')}",
                            extracted_text=f"Exposed record for {target_input.full_name} at {location}. Phone: {phone_val}. Email: {email_val}",
                            is_simulated=True,
                            provenance=ExecutionProvenance.FALLBACK,
                        )
                    broker_findings.append(b_res)
                    dur = (time.perf_counter() - t0) * 1000
                    browser_tool_name = {
                        ExecutionProvenance.LIVE: "browser_scanner",
                        ExecutionProvenance.CONTROLLED_FIXTURE: "controlled_broker_fixture",
                        ExecutionProvenance.FALLBACK: "broker_fixture_fallback",
                    }[b_res.provenance]
                    record_step(
                        current_state,
                        tool_name=browser_tool_name,
                        tool_input={"broker": broker.broker_id, "target_id": target_id},
                        tool_output_summary=f"Scanned {broker.broker_name}. Exposed: {b_res.is_exposed}",
                        duration_ms=dur,
                        provenance=b_res.provenance,
                    )
                    if b_res.is_exposed:
                        await emit_telemetry(
                            TelemetryEventType.BROKER_EXPOSURE_DETECTED,
                            current_state,
                            f"Exposure detected on {broker.broker_name} for the authorized target",
                            {
                                "broker": broker.broker_id,
                                "provenance": b_res.provenance.value,
                                "is_simulated": b_res.is_simulated,
                            },
                        )
                    else:
                        await emit_telemetry(
                            TelemetryEventType.TOOL_COMPLETE,
                            current_state,
                            f"Broker scan completed for {broker.broker_name}; no exposure matched",
                            {
                                "tool": browser_tool_name,
                                "broker": broker.broker_id,
                                "provenance": b_res.provenance.value,
                                "is_simulated": b_res.is_simulated,
                            },
                        )

            # =========================================================
            # Phase 4: Structural Extraction
            # =========================================================
            if self._step_count >= self.max_budget:
                raise BudgetExhaustedException()

            current_state = AgentLifecycleState.EXTRACTING_EXPOSURES
            await emit_telemetry(
                TelemetryEventType.STATE_TRANSITION,
                current_state,
                "Extracting structured entity profiles; provider and model provenance are reported per result",
            )
            for b_res in broker_findings:
                if not b_res.is_exposed or not (b_res.extracted_text or b_res.raw_html):
                    continue
                if self._step_count >= self.max_budget:
                    break

                t0 = time.perf_counter()
                if self.extractor:
                    prof = await self.extractor.extract_entities(
                        raw_content=b_res.raw_html or b_res.extracted_text or "",
                        source_url=b_res.profile_url or b_res.broker_id,
                        target_id=target_id,
                        source_broker=b_res.broker_id,
                        target_hint=target_input.full_name,
                    )
                else:
                    prof = ExtractedEntityProfile(
                        target_id=target_id,
                        source_url=b_res.profile_url or "",
                        source_broker=b_res.broker_id,
                        matched_names=[target_input.full_name],
                        phone_numbers=target_input.phone_numbers or ["555-0199"],
                        email_addresses=[target_input.primary_email] if target_input.primary_email else [],
                        current_address=target_input.known_addresses[0] if target_input.known_addresses else None,
                        removal_url=b_res.profile_url,
                        confidence_score=0.95,
                        provenance=ExecutionProvenance.FALLBACK,
                        extraction_provider="deterministic_agent_fallback",
                    )
                extracted_profiles.append(prof)
                dur = (time.perf_counter() - t0) * 1000
                extractor_tool_name = (
                    "gemini_structured_extractor"
                    if prof.extraction_provider == "google_genai_sdk"
                    else "deterministic_extractor_fallback"
                )
                record_step(
                    current_state,
                    tool_name=extractor_tool_name,
                    tool_input={"source_broker": b_res.broker_id},
                    tool_output_summary=f"Extracted entity profile with confidence {prof.confidence_score}",
                    duration_ms=dur,
                    provenance=prof.provenance,
                )
                if prof.extraction_model:
                    self._models_used.add(prof.extraction_model)
                    self._model_invocations.append(
                        {
                            "provider": prof.extraction_provider,
                            "operation": "structured_extraction",
                            "requested_model": prof.extraction_model,
                            "model": prof.extraction_model,
                            "model_version": prof.model_version,
                            "response_id": prof.model_response_id,
                            "usage": prof.model_usage,
                            "source_broker": b_res.broker_id,
                        }
                    )
                await emit_telemetry(
                    TelemetryEventType.TOOL_COMPLETE,
                    current_state,
                    f"Structured extraction completed for {b_res.broker_id}",
                    {
                        "tool": extractor_tool_name,
                        "source_broker": b_res.broker_id,
                        "provenance": prof.provenance.value,
                        "provider": prof.extraction_provider,
                        "requested_model": prof.extraction_model,
                        "confidence": prof.confidence_score,
                        "response_id": prof.model_response_id,
                        "model_version": prof.model_version,
                        "usage": prof.model_usage,
                    },
                )

            # =========================================================
            # Phase 5: Gemma 2 PII Token Sanitization
            # =========================================================
            if self._step_count >= self.max_budget:
                raise BudgetExhaustedException()

            current_state = AgentLifecycleState.SANITIZING_PII
            await emit_telemetry(
                TelemetryEventType.STATE_TRANSITION,
                current_state,
                "Classifying and sanitizing sensitive PII tokens",
            )
            combined_text = "\n".join(
                [f"Target: {p.matched_names} Addr: {p.current_address} Phones: {p.phone_numbers} Emails: {p.email_addresses}" for p in extracted_profiles]
            ) or f"Target: {target_input.full_name} Email: {target_input.primary_email}"

            t0 = time.perf_counter()
            if self.gemma_sanitizer:
                if asyncio.iscoroutinefunction(getattr(self.gemma_sanitizer, "classify_and_sanitize", None)):
                    sanitization_res = await self.gemma_sanitizer.classify_and_sanitize(combined_text)
                elif hasattr(self.gemma_sanitizer, "sanitize_and_classify_async"):
                    sanitization_res = await self.gemma_sanitizer.sanitize_and_classify_async(combined_text)
                else:
                    sanitization_res = self.gemma_sanitizer.classify_and_sanitize(combined_text)
            else:
                from project_umbra.classifiers.heuristics import FastPIISanitizer
                sanitization_res = FastPIISanitizer().sanitize(combined_text)
                sanitization_res.provenance = ExecutionProvenance.FALLBACK
                sanitization_res.classifier_provider = "deterministic_heuristic"
                sanitization_res.classifier_model = None

            dur = (time.perf_counter() - t0) * 1000
            classifier_tool_name = (
                "gemma_pii_classifier"
                if sanitization_res.classifier_provider == "google_genai_sdk"
                else "heuristic_pii_classifier"
            )
            record_step(
                current_state,
                thought=f"Sanitized {sanitization_res.total_pii_count} PII entities. Masked {len(sanitization_res.redaction_map)} unique tokens.",
                tool_name=classifier_tool_name,
                tool_input={"text_length": len(combined_text)},
                tool_output_summary=f"Sanitized {sanitization_res.total_pii_count} tokens.",
                duration_ms=dur,
                provenance=sanitization_res.provenance,
            )
            if sanitization_res.classifier_model:
                self._models_used.add(sanitization_res.classifier_model)
            await emit_telemetry(
                TelemetryEventType.PII_SANITIZED,
                current_state,
                f"{sanitization_res.classifier_provider} sanitized {sanitization_res.total_pii_count} PII entities with overall risk score {sanitization_res.overall_risk_score}/100",
                {
                    "pii_summary": {
                        "critical_pii_count": sanitization_res.critical_pii_count,
                        "total_pii_count": sanitization_res.total_pii_count,
                        "overall_risk_score": sanitization_res.overall_risk_score,
                        "redacted_token_count": len(sanitization_res.redaction_map),
                    },
                    "provenance": sanitization_res.provenance.value,
                    "provider": sanitization_res.classifier_provider,
                    "model": sanitization_res.classifier_model,
                },
            )

            # =========================================================
            # Phase 6: Approval-Gated Action Plan Generation
            # =========================================================
            if self._step_count >= self.max_budget:
                raise BudgetExhaustedException()

            current_state = AgentLifecycleState.GENERATING_REMEDIATIONS
            await emit_telemetry(
                TelemetryEventType.STATE_TRANSITION,
                current_state,
                "Preparing approval-gated CCPA/GDPR action packages and broker opt-out links",
            )
            t0 = time.perf_counter()
            if self.suppression_engine:
                if asyncio.iscoroutinefunction(getattr(self.suppression_engine, "generate_remediation_plan", None)):
                    remediation_plan = await self.suppression_engine.generate_remediation_plan(target_input, extracted_profiles, target_id=target_id)
                elif hasattr(self.suppression_engine, "compile_plan"):
                    remediation_plan = self.suppression_engine.compile_plan(target_input, extracted_profiles, target_id=target_id)
                else:
                    remediation_plan = self.suppression_engine.generate_remediation_plan(target_input, extracted_profiles)
            else:
                from project_umbra.tools.suppression_engine import SuppressionEngine
                remediation_plan = SuppressionEngine().compile_plan(target_input, extracted_profiles, target_id=target_id)

            dur = (time.perf_counter() - t0) * 1000
            record_step(
                current_state,
                thought=f"Prepared {len(remediation_plan.actions)} approval-gated actions and master CCPA/GDPR legal notices.",
                tool_name="action_plan_engine",
                tool_input={"target_id": target_id, "exposures_count": len(extracted_profiles)},
                tool_output_summary=f"Compiled SuppressionActionPlan with {len(remediation_plan.actions)} actions.",
                duration_ms=dur,
            )
            for act in remediation_plan.actions:
                await emit_telemetry(
                    TelemetryEventType.ACTION_PLAN_GENERATED,
                    current_state,
                    f"Prepared {act.opt_out_type} action package for {act.broker_name}; no request dispatched",
                    {
                        "action": {
                            "remediation_id": act.remediation_id,
                            "broker_id": act.broker_id,
                            "broker_name": act.broker_name,
                            "opt_out_type": act.opt_out_type,
                            "submission_url": act.submission_url,
                            "status": act.status.value,
                        },
                        "provenance": ExecutionProvenance.LIVE.value,
                        "external_action_dispatched": False,
                    },
                )

            # =========================================================
            # Phase 7: Completion
            # =========================================================
            current_state = AgentLifecycleState.COMPLETED
            await emit_telemetry(
                TelemetryEventType.SCAN_COMPLETED,
                current_state,
                f"Mission completed successfully for authorized target reference: {target_id}.",
                {
                    "total_steps": self._step_count,
                    "exposures_found": len(extracted_profiles),
                    "tool_provenance": {k: v.value for k, v in self._tool_provenance.items()},
                    "models_used": sorted(self._models_used),
                    "model_invocations": self._model_invocations,
                    "external_actions_dispatched": 0,
                },
            )

        except BudgetExhaustedException:
            current_state = AgentLifecycleState.BUDGET_EXHAUSTED
            await emit_telemetry(
                TelemetryEventType.BUDGET_EXHAUSTED,
                current_state,
                f"Step budget limit ({self.max_budget}) reached. Performing emergency consolidation.",
                {"steps_executed": self._step_count},
            )
            # Emergency synthesis if sanitization or suppression missing
            if not sanitization_res and extracted_profiles:
                combined_text = "\n".join([str(p.model_dump()) for p in extracted_profiles])
                from project_umbra.classifiers.heuristics import FastPIISanitizer
                sanitization_res = FastPIISanitizer().sanitize(combined_text)

            if not remediation_plan:
                from project_umbra.tools.suppression_engine import SuppressionEngine
                remediation_plan = SuppressionEngine().compile_plan(target_input, extracted_profiles, target_id=target_id)

        except Exception as err:
            current_state = AgentLifecycleState.FAILED
            await emit_telemetry(
                TelemetryEventType.SCAN_FAILED,
                current_state,
                "Agent execution encountered an unexpected runtime failure.",
                {"error": "RUNTIME_FAILURE", "error_type": type(err).__name__},
            )

        # Final Summary Assembly
        completed_at = datetime.now(timezone.utc)
        summary_sanitization = sanitization_res.model_copy(deep=True) if sanitization_res else None
        if summary_sanitization is not None:
            summary_sanitization.redaction_map = {}
            for entity in summary_sanitization.detected_entities:
                entity.original_value = "[REDACTED]"

        summary = AgentRunSummary(
            run_id=run_id,
            target_id=target_id,
            target_name=target_input.full_name,
            started_at=started_at,
            completed_at=completed_at,
            final_state=current_state,
            total_steps_executed=self._step_count,
            budget_allocated=self.max_budget,
            budget_remaining=max(0, self.max_budget - self._step_count),
            vectors_analyzed=len(decomposition_res.vectors) if decomposition_res else 0,
            dorks_executed=len(dork_res.dorks) if dork_res else 0,
            brokers_scanned=len(broker_findings),
            exposures_found=len(extracted_profiles),
            pii_entities_sanitized=sanitization_res.total_pii_count if sanitization_res else 0,
            remediations_generated=len(remediation_plan.actions) if remediation_plan else 0,
            findings=extracted_profiles,
            sanitization_result=summary_sanitization,
            remediation_plan=remediation_plan,
            execution_state_log=self._execution_log,
            tool_provenance=self._tool_provenance,
            models_used=sorted(self._models_used),
            model_invocations=self._model_invocations,
            external_actions_dispatched=0,
        )
        return summary
