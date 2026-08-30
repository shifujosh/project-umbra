"""
Project Umbra State & Domain Data Models (Pydantic v2).
Strictly adheres to Python 3.12 PEP 604 type unions and Pydantic v2 validation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


# ==========================================
# 1. Enums
# ==========================================

class VectorCategory(str, Enum):
    DIRECT_IDENTIFIER = "direct_identifier"
    DIGITAL_FOOTPRINT = "digital_footprint"
    RELATIONAL_AFFILIATION = "relational_affiliation"
    GEOGRAPHIC_PHYSICAL = "geographic_physical"
    BREACH_CREDENTIAL = "breach_credential"


class PriorityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DorkCategory(str, Enum):
    DOCUMENTS_SPREADSHEETS = "documents_spreadsheets"
    PASTEBINS_DUMPS = "pastebins_dumps"
    CODE_REPOS_CONFIGS = "code_repos_configs"
    CREDENTIAL_LEAKS = "credential_leaks"
    GOV_PUBLIC_DIRECTORIES = "gov_public_directories"
    DATA_BROKER_PROFILES = "data_broker_profiles"
    SOCIAL_EXPOSURE = "social_exposure"


class PIITokenType(str, Enum):
    FULL_NAME = "FULL_NAME"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    PHYSICAL_ADDRESS = "PHYSICAL_ADDRESS"
    SSN = "SSN"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    CREDIT_CARD = "CREDIT_CARD"
    PASSWORD_HASH = "PASSWORD_HASH"
    RELATIVE_NAME = "RELATIVE_NAME"
    IP_ADDRESS = "IP_ADDRESS"


class PIISeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SuppressionStatus(str, Enum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    MANUAL_ACTION_REQUIRED = "manual_action_required"


class ExecutionProvenance(str, Enum):
    """Truthful origin of a tool result or mission artifact."""

    LIVE = "live"
    CONTROLLED_FIXTURE = "controlled_fixture"
    FALLBACK = "fallback"


class AgentLifecycleState(str, Enum):
    INITIALIZED = "initialized"
    DECOMPOSING_IDENTITY = "decomposing_identity"
    SYNTHESIZING_DORKS = "synthesizing_dorks"
    SCANNING_SERP = "scanning_serp"
    SCANNING_BROKERS = "scanning_brokers"
    EXTRACTING_EXPOSURES = "extracting_exposures"
    SANITIZING_PII = "sanitizing_pii"
    GENERATING_REMEDIATIONS = "generating_remediations"
    COMPLETED = "completed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


class TelemetryEventType(str, Enum):
    SCAN_INITIATED = "SCAN_INITIATED"
    STATE_TRANSITION = "STATE_TRANSITION"
    AGENT_THOUGHT = "AGENT_THOUGHT"
    TOOL_START = "TOOL_START"
    TOOL_COMPLETE = "TOOL_COMPLETE"
    TOOL_ERROR = "TOOL_ERROR"
    DORK_DISCOVERED = "DORK_DISCOVERED"
    BROKER_EXPOSURE_DETECTED = "BROKER_EXPOSURE_DETECTED"
    PII_SANITIZED = "PII_SANITIZED"
    GEMMA_PII_SANITIZED = "GEMMA_PII_SANITIZED"
    ACTION_PLAN_GENERATED = "ACTION_PLAN_GENERATED"
    SUPPRESSION_GENERATED = "SUPPRESSION_GENERATED"
    STEP_BUDGET_UPDATED = "STEP_BUDGET_UPDATED"
    LOOP_DETECTED = "LOOP_DETECTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"


# ==========================================
# 2. Target Identity & Decomposition Models
# ==========================================

class TargetIdentityInput(BaseModel):
    """Raw input parameters for target identity investigation."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    full_name: str = Field(..., description="Target's full legal name or primary name", min_length=2)
    aliases: list[str] = Field(default_factory=list, description="Known aliases or nicknames")
    primary_email: str | None = Field(default=None, description="Primary email address")
    secondary_emails: list[str] = Field(default_factory=list, description="Secondary or historical email addresses")
    phone_numbers: list[str] = Field(default_factory=list, description="Known phone numbers in any format")
    current_city: str | None = Field(default=None, description="Current city of residence")
    current_state: str | None = Field(default=None, description="Current state or province")
    known_addresses: list[str] = Field(default_factory=list, description="Known current or past street addresses")
    relatives: list[str] = Field(default_factory=list, description="Known relatives, spouses, or associates")
    employers: list[str] = Field(default_factory=list, description="Known current or past employers")
    usernames: list[str] = Field(default_factory=list, description="Known online usernames or social handles")


class InvestigativeVector(BaseModel):
    """Structured decomposed vector for targeted reconnaissance."""

    model_config = ConfigDict(extra="ignore")

    vector_id: str = Field(..., description="Unique deterministic vector identifier")
    category: VectorCategory = Field(..., description="Taxonomy category of the vector")
    query_term: str = Field(..., description="Normalized search term or coordinate")
    weight: float = Field(default=1.0, ge=0.0, le=1.0, description="Signal-to-noise priority weight")
    priority: PriorityLevel = Field(default=PriorityLevel.MEDIUM, description="Investigation priority")
    rationale: str = Field(..., description="Explanation of why this vector was synthesized")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional context or attributes")


class IdentityDecompositionResult(BaseModel):
    """Complete output of the Identity Decomposition Engine."""

    model_config = ConfigDict(extra="ignore")

    target_id: str = Field(..., description="Hash or UUID of target identity")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_input: TargetIdentityInput
    vectors: list[InvestigativeVector] = Field(default_factory=list)
    total_vectors: int = Field(default=0)


# ==========================================
# 3. Precision Dork Synthesizer Models
# ==========================================

class DorkQuery(BaseModel):
    """Synthesized precision Google search dork."""

    model_config = ConfigDict(extra="ignore")

    dork_id: str = Field(..., description="Unique dork identifier")
    category: DorkCategory = Field(..., description="Category of target vulnerability / exposure")
    raw_query: str = Field(..., description="Unencoded Google search query with operators")
    encoded_url: str = Field(..., description="URL-encoded Google search URL")
    target_vector_id: str = Field(..., description="Vector ID that prompted this dork")
    expected_signal: str = Field(..., description="What sensitive data this dork aims to uncover")
    risk_level: PriorityLevel = Field(default=PriorityLevel.MEDIUM)


class DorkSynthesisResult(BaseModel):
    """Collection of synthesized precision dorks for an identity."""

    model_config = ConfigDict(extra="ignore")

    target_id: str
    dorks: list[DorkQuery] = Field(default_factory=list)
    total_dorks: int = Field(default=0)


# ==========================================
# 4. Reconnaissance & Extraction Models
# ==========================================

class SERPFinding(BaseModel):
    """Individual result item from a search dork scan."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    dork_id: str
    title: str
    url: str
    snippet: str
    domain: str
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_page_text: str | None = None
    risk_level: PriorityLevel = Field(default=PriorityLevel.MEDIUM, description="Calculated finding risk level")
    matched_pii_tokens: list[str] = Field(default_factory=list, description="Target PII tokens detected in title/snippet")
    dork_category: DorkCategory | None = Field(default=None, description="Taxonomy category of the originating dork")
    provenance: ExecutionProvenance = Field(
        default=ExecutionProvenance.LIVE,
        description="Whether the finding came from a live provider, controlled fixture, or fallback",
    )


class BrokerScanTarget(BaseModel):
    """Target broker definition for browser scanning."""

    model_config = ConfigDict(extra="ignore")

    broker_id: str = Field(..., description="Broker key, e.g., 'truepeoplesearch', 'fastpeoplesearch'")
    broker_name: str
    base_url: str
    opt_out_url: str
    search_url_template: str


class BrokerScanResult(BaseModel):
    """Result of Playwright browser scrape against a data broker."""

    model_config = ConfigDict(extra="ignore")

    broker_id: str
    target_name: str
    target_location: str | None = None
    profile_url: str | None = None
    is_exposed: bool = False
    raw_html: str | None = None
    extracted_text: str | None = None
    status_code: int = 200
    execution_time_ms: float = 0.0
    is_simulated: bool = False
    provenance: ExecutionProvenance = ExecutionProvenance.LIVE


class ExtractedEntityProfile(BaseModel):
    """LLM-extracted structured profile from scraped OSINT text."""

    model_config = ConfigDict(extra="ignore")

    target_id: str
    source_url: str
    source_broker: str | None = None
    matched_names: list[str] = Field(default_factory=list)
    age: str | None = None
    phone_numbers: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    current_address: str | None = None
    past_addresses: list[str] = Field(default_factory=list)
    relatives: list[str] = Field(default_factory=list)
    associates: list[str] = Field(default_factory=list)
    removal_url: str | None = None
    confidence_score: float = Field(default=0.9, ge=0.0, le=1.0)
    provenance: ExecutionProvenance = ExecutionProvenance.LIVE
    extraction_provider: str = "unknown"
    extraction_model: str | None = None
    model_response_id: str | None = None
    model_version: str | None = None
    model_usage: dict[str, Any] = Field(default_factory=dict)


# ==========================================
# 5. Gemma 2 PII Sanitization Models
# ==========================================

class PIITokenEntity(BaseModel):
    """Detected sensitive entity identified by Gemma 2."""

    model_config = ConfigDict(extra="ignore")

    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    token_type: PIITokenType
    original_value: str
    surrogate_token: str  # e.g., '[PII_EMAIL_01]'
    severity: PIISeverity
    confidence: float = Field(default=0.95, ge=0.0, le=1.0)
    start_char: int | None = None
    end_char: int | None = None


class PIISanitizationResult(BaseModel):
    """Sanitized payload output by Gemma 2 with cryptographic token map."""

    model_config = ConfigDict(extra="ignore")

    sanitized_text: str
    detected_entities: list[PIITokenEntity] = Field(default_factory=list)
    redaction_map: dict[str, str] = Field(default_factory=dict, description="Surrogate token -> Original value")
    critical_pii_count: int = 0
    total_pii_count: int = 0
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    provenance: ExecutionProvenance = ExecutionProvenance.LIVE
    classifier_provider: str = "deterministic_heuristic"
    classifier_model: str | None = None


# ==========================================
# 6. Suppression & Remediation Models
# ==========================================

class SuppressionPayload(BaseModel):
    """Generated opt-out action payload for a specific broker or breach."""

    model_config = ConfigDict(extra="ignore")

    remediation_id: str = Field(default_factory=lambda: f"rem_{uuid.uuid4().hex[:8]}")
    broker_id: str
    broker_name: str
    opt_out_type: Literal["automated_form", "ccpa_email", "gdpr_email", "master_opt_out"]
    target_profile_url: str | None = None
    form_payload: dict[str, Any] = Field(default_factory=dict)
    legal_request_letter: str | None = None
    submission_url: str | None = None
    status: SuppressionStatus = SuppressionStatus.PENDING
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SuppressionReceipt(BaseModel):
    """Verifiable receipt for a dispatched opt-out or legal notice."""

    model_config = ConfigDict(extra="ignore")

    receipt_id: str = Field(default_factory=lambda: f"rcpt_{uuid.uuid4().hex[:8]}")
    remediation_id: str
    broker_name: str
    notice_type: str
    status: Literal["SUBMITTED", "CONFIRMED", "PENDING_VERIFICATION", "FAILED"]
    submission_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    compliance_deadline: datetime
    tracking_reference: str
    response_code: int = 200
    confirmation_message: str
    downloadable_notice_url: str | None = None


class SuppressionActionPlan(BaseModel):
    """Master remediation action plan generated for the user."""

    model_config = ConfigDict(extra="ignore")

    target_id: str
    actions: list[SuppressionPayload] = Field(default_factory=list)
    total_actions: int = 0
    master_ccpa_letter: str | None = None
    master_gdpr_letter: str | None = None


# ==========================================
# 7. Agent Execution & Telemetry Models
# ==========================================

class AgentStepRecord(BaseModel):
    """Record of a single reasoning or tool invocation step."""

    model_config = ConfigDict(extra="ignore")

    step_number: int
    state: AgentLifecycleState
    thought: str | None = None
    tool_name: str | None = None
    tool_input: dict[str, Any] | None = None
    tool_output_summary: str | None = None
    step_duration_ms: float = 0.0
    budget_remaining: int = 0
    provenance: ExecutionProvenance = ExecutionProvenance.LIVE


class AgentTelemetryEvent(BaseModel):
    """SSE event payload emitted during agent execution."""

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:8]}")
    scan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: TelemetryEventType
    state: AgentLifecycleState
    message: str
    step_number: int
    budget_remaining: int
    payload: dict[str, Any] = Field(default_factory=dict)


class AgentRunSummary(BaseModel):
    """Final comprehensive run report produced by Project Umbra."""

    model_config = ConfigDict(extra="ignore")

    run_id: str
    target_id: str
    target_name: str
    started_at: datetime
    completed_at: datetime
    final_state: AgentLifecycleState
    total_steps_executed: int
    budget_allocated: int
    budget_remaining: int
    vectors_analyzed: int
    dorks_executed: int
    brokers_scanned: int
    exposures_found: int
    pii_entities_sanitized: int
    remediations_generated: int
    findings: list[ExtractedEntityProfile] = Field(default_factory=list)
    sanitization_result: PIISanitizationResult | None = None
    remediation_plan: SuppressionActionPlan | None = None
    execution_state_log: list[AgentStepRecord] = Field(default_factory=list)
    tool_provenance: dict[str, ExecutionProvenance] = Field(default_factory=dict)
    models_used: list[str] = Field(default_factory=list)
    model_invocations: list[dict[str, Any]] = Field(default_factory=list)
    external_actions_dispatched: int = Field(
        default=0,
        description="External deletion or opt-out requests actually sent during this mission",
    )
