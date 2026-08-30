"""
Project Umbra Automated Suppression & Statutory Legal Notice Engine.
Compiles master remediation action plans, generates legally binding CCPA/CPRA
and GDPR Art. 17/21 notices, formats PeopleConnect master opt-out payloads,
dispatches multi-broker automated submissions, and issues SHA-256 cryptographic receipts.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import logging
import re
from typing import Any, Literal
import uuid
import httpx

from project_umbra.config import settings
from project_umbra.core.state import (
    ExtractedEntityProfile,
    SuppressionActionPlan,
    SuppressionPayload,
    SuppressionReceipt,
    SuppressionStatus,
    TargetIdentityInput,
)

logger = logging.getLogger(__name__)

# Statutory compliance deadline constant (in calendar days)
STATUTORY_COMPLIANCE_DAYS: int = 30


# ==============================================================================
# 1. Enums and Metadata Catalogs
# ==============================================================================

class LegalNoticeType(str, Enum):
    CCPA_DELETION = "ccpa_deletion"
    CCPA_OPT_OUT = "ccpa_opt_out"
    GDPR_ERASURE = "gdpr_erasure"
    GDPR_OBJECTION = "gdpr_objection"
    PEOPLECONNECT_MASTER = "peopleconnect_master"
    BROKER_TAKEDOWN = "broker_takedown"


class PeopleConnectBrand(str, Enum):
    TRUTHFINDER = "truthfinder"
    INSTANTCHECKMATE = "instantcheckmate"
    INTELIUS = "intelius"
    USSEARCH = "ussearch"


PEOPLECONNECT_BRAND_METADATA: dict[str, dict[str, str]] = {
    "truthfinder": {
        "name": "TruthFinder",
        "domain": "truthfinder.com",
        "opt_out_url": "https://www.truthfinder.com/opt-out/",
    },
    "instantcheckmate": {
        "name": "Instant Checkmate",
        "domain": "instantcheckmate.com",
        "opt_out_url": "https://www.instantcheckmate.com/opt-out/",
    },
    "intelius": {
        "name": "Intelius",
        "domain": "intelius.com",
        "opt_out_url": "https://www.intelius.com/opt-out/",
    },
    "ussearch": {
        "name": "US Search",
        "domain": "ussearch.com",
        "opt_out_url": "https://www.ussearch.com/opt-out/",
    },
}

BROKER_REMOVAL_ENDPOINTS: dict[str, str] = {
    "truepeoplesearch": "https://www.truepeoplesearch.com/removal",
    "fastpeoplesearch": "https://www.fastpeoplesearch.com/removal",
    "radaris": "https://radaris.com/control/privacy",
    "nuwber": "https://nuwber.com/removal/link",
    "whitepages": "https://www.whitepages.com/suppression-requests",
    "peopleconnect": "https://suppression.peopleconnect.us/privacy-center",
}

KNOWN_BROKER_REGISTRY: dict[str, dict[str, Any]] = {
    "truepeoplesearch": {
        "broker_name": "TruePeopleSearch",
        "opt_out_type": "automated_form",
        "opt_out_url": "https://www.truepeoplesearch.com/removal",
        "privacy_email": "support@truepeoplesearch.com",
        "field_mapping": {
            "record_url_field": "RecordUrl",
            "email_field": "Email",
            "reason_field": "Reason",
        },
    },
    "fastpeoplesearch": {
        "broker_name": "FastPeopleSearch",
        "opt_out_type": "automated_form",
        "opt_out_url": "https://www.fastpeoplesearch.com/removal",
        "privacy_email": "privacy@fastpeoplesearch.com",
        "field_mapping": {
            "record_url_field": "record_url",
            "email_field": "email",
            "agree_field": "agree",
        },
    },
    "radaris": {
        "broker_name": "Radaris",
        "opt_out_type": "automated_form",
        "opt_out_url": "https://radaris.com/control/privacy",
        "privacy_email": "privacy@radaris.com",
        "field_mapping": {
            "profile_url_field": "profile_url",
            "email_field": "email",
            "name_field": "full_name",
        },
    },
    "nuwber": {
        "broker_name": "Nuwber",
        "opt_out_type": "automated_form",
        "opt_out_url": "https://nuwber.com/removal/link",
        "privacy_email": "support@nuwber.com",
        "field_mapping": {
            "url_field": "url",
            "email_field": "email",
        },
    },
    "whitepages": {
        "broker_name": "Whitepages",
        "opt_out_type": "automated_form",
        "opt_out_url": "https://www.whitepages.com/suppression-requests",
        "privacy_email": "privacy@whitepages.com",
        "field_mapping": {
            "url_field": "url",
            "email_field": "email",
            "phone_field": "phone",
        },
    },
    "peopleconnect": {
        "broker_name": "PeopleConnect Suppression Hub (TruthFinder, Intelius, InstantCheckmate, USSearch)",
        "opt_out_type": "master_opt_out",
        "opt_out_url": "https://suppression.peopleconnect.us/login",
        "privacy_email": "privacy@peopleconnect.us",
        "field_mapping": {
            "first_name_field": "firstName",
            "last_name_field": "lastName",
            "email_field": "email",
            "birth_year_field": "birthYear",
            "phone_field": "phone",
            "addresses_field": "addresses",
        },
    },
    "spokeo": {
        "broker_name": "Spokeo",
        "opt_out_type": "automated_form",
        "opt_out_url": "https://www.spokeo.com/optout",
        "privacy_email": "privacy@spokeo.com",
        "field_mapping": {
            "url_field": "url",
            "email_field": "email",
        },
    },
    "beenverified": {
        "broker_name": "BeenVerified",
        "opt_out_type": "automated_form",
        "opt_out_url": "https://www.beenverified.com/app/optout/search",
        "privacy_email": "privacy@beenverified.com",
        "field_mapping": {
            "optout_field": "optout_url",
            "email_field": "email",
        },
    },
}

DEFAULT_PROACTIVE_BROKERS: list[str] = [
    "truepeoplesearch",
    "fastpeoplesearch",
    "radaris",
    "nuwber",
    "whitepages",
    "peopleconnect",
]

SIMULATED_BROKER_RESPONSES: dict[str, dict[str, Any]] = {
    "truepeoplesearch": {
        "status_code": 200,
        "message": "TruePeopleSearch Removal: Confirmation email dispatched to {email}. Record queued for de-listing.",
        "notice_type": "Automated Web Form Submission (TruePeopleSearch)",
    },
    "fastpeoplesearch": {
        "status_code": 200,
        "message": "FastPeopleSearch Removal: Opt-out request registered. Record suppressed pending 24h propagation.",
        "notice_type": "Automated Web Form Submission (FastPeopleSearch)",
    },
    "radaris": {
        "status_code": 202,
        "message": "Radaris Privacy Control: Verification code generated and sent to {email}. Ticket ref #{tracking_ref}.",
        "notice_type": "Privacy Control Ticket (Radaris)",
    },
    "nuwber": {
        "status_code": 200,
        "message": "Nuwber Privacy Portal: URL removal link generated. De-indexing scheduled.",
        "notice_type": "URL Removal Request (Nuwber)",
    },
    "whitepages": {
        "status_code": 200,
        "message": "Whitepages Suppression: Listing suppression confirmed. Statutory 30-day monitoring active.",
        "notice_type": "Listing Suppression (Whitepages)",
    },
    "peopleconnect": {
        "status_code": 200,
        "message": "PeopleConnect Master Opt-Out: Identity suppression broadcast to syndicated broker network.",
        "notice_type": "Master Syndicated Suppression (PeopleConnect)",
    },
    "default": {
        "status_code": 200,
        "message": "Broker Opt-Out: Privacy deletion notice submitted successfully for {email}.",
        "notice_type": "Automated Broker Opt-Out",
    },
}


# ==============================================================================
# 2. Cryptographic Reference & Identity Schedule Helpers
# ==============================================================================

def generate_tracking_reference(prefix: str, target_name: str, entity_id: str) -> str:
    """Generates a deterministic cryptographic tracking reference ID."""
    token = f"{target_name}:{entity_id}:{datetime.now(timezone.utc).strftime('%Y%m%d')}"
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:10].upper()
    return f"GP-{prefix.upper()}-{digest}"


def generate_cryptographic_tracking_hash(
    remediation_id: str,
    broker_id: str,
    timestamp: datetime,
    email: str | None = None,
    profile_url: str | None = None,
) -> str:
    """
    Computes a deterministic SHA-256 cryptographic tracking reference hash.
    Format: GP-SHA256-<HEX_DIGEST_UPPER[:16]>
    """
    seed = f"{remediation_id}:{broker_id}:{timestamp.isoformat()}:{email or 'none'}:{profile_url or 'none'}"
    raw_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"GP-SHA256-{raw_hash[:16].upper()}"


def calculate_compliance_deadline(
    submission_timestamp: datetime,
    days: int = STATUTORY_COMPLIANCE_DAYS,
) -> datetime:
    """Computes statutory compliance deadline in UTC."""
    return submission_timestamp + timedelta(days=days)


def map_response_to_status(
    status_code: int,
) -> Literal["SUBMITTED", "CONFIRMED", "PENDING_VERIFICATION", "FAILED"]:
    """Maps HTTP response status code to SuppressionReceipt status."""
    if status_code == 200:
        return "CONFIRMED"
    elif status_code == 202:
        return "PENDING_VERIFICATION"
    elif 200 <= status_code < 300:
        return "SUBMITTED"
    else:
        return "FAILED"


def format_identity_schedule(
    target: TargetIdentityInput,
    profile_url: str | None = None,
    extracted_profile: ExtractedEntityProfile | None = None,
) -> str:
    """Formats a structured consumer identity verification schedule for legal notices."""
    lines = [
        "================================================================================",
        "                       CONSUMER IDENTIFYING INFORMATION                         ",
        "================================================================================",
        f"  Full Legal Name:       {target.full_name}",
    ]
    if target.aliases:
        lines.append(f"  Known Aliases:         {', '.join(target.aliases)}")
    if target.primary_email:
        lines.append(f"  Primary Email:         {target.primary_email}")
    if target.secondary_emails:
        lines.append(f"  Secondary Emails:      {', '.join(target.secondary_emails)}")
    if target.phone_numbers:
        lines.append(f"  Phone Numbers:         {', '.join(target.phone_numbers)}")
    if target.known_addresses:
        lines.append(f"  Known Addresses:       {'; '.join(target.known_addresses)}")
    elif target.current_city or target.current_state:
        loc = f"{target.current_city or ''}, {target.current_state or ''}".strip(", ")
        lines.append(f"  Location:              {loc}")
    if target.relatives:
        lines.append(f"  Associated Relatives:  {', '.join(target.relatives)}")
    if profile_url:
        lines.append(f"  Target Record URL:     {profile_url}")
    elif extracted_profile and (extracted_profile.source_url or extracted_profile.removal_url):
        lines.append(f"  Target Record URL:     {extracted_profile.removal_url or extracted_profile.source_url}")
    lines.append("================================================================================")
    return "\n".join(lines)


def create_suppression_receipt(
    remediation_id: str,
    broker_name: str,
    broker_id: str,
    notice_type: str,
    status_code: int,
    confirmation_message: str,
    email: str | None = None,
    profile_url: str | None = None,
    submission_timestamp: datetime | None = None,
) -> SuppressionReceipt:
    """
    Constructs a complete SuppressionReceipt with cryptographic hash and statutory compliance deadline.
    """
    ts = submission_timestamp or datetime.now(timezone.utc)
    deadline = calculate_compliance_deadline(ts)
    tracking_ref = generate_cryptographic_tracking_hash(
        remediation_id=remediation_id,
        broker_id=broker_id,
        timestamp=ts,
        email=email,
        profile_url=profile_url,
    )
    status = map_response_to_status(status_code)
    receipt_id = f"rcpt_{uuid.uuid4().hex[:12]}"
    downloadable_url = f"https://receipts.project-umbra.internal/v1/notices/{receipt_id}.pdf"

    email_val = email or "user@example.com"
    formatted_msg = confirmation_message
    if "{" in confirmation_message:
        try:
            formatted_msg = confirmation_message.format(
                email=email_val,
                tracking_ref=tracking_ref,
            )
        except (KeyError, ValueError, IndexError):
            formatted_msg = confirmation_message.replace("{email}", email_val).replace("{tracking_ref}", tracking_ref)

    return SuppressionReceipt(
        receipt_id=receipt_id,
        remediation_id=remediation_id,
        broker_name=broker_name,
        notice_type=notice_type,
        status=status,
        submission_timestamp=ts,
        compliance_deadline=deadline,
        tracking_reference=tracking_ref,
        response_code=status_code,
        confirmation_message=formatted_msg,
        downloadable_notice_url=downloadable_url,
    )


# ==============================================================================
# 3. Statutory Legal Notice Generators (CCPA, GDPR, PeopleConnect)
# ==============================================================================

def generate_ccpa_notice(
    target: TargetIdentityInput,
    broker_name: str = "Data Broker / Data Controller",
    profile_url: str | None = None,
    reference_id: str | None = None,
    date_str: str | None = None,
) -> str:
    """
    Generates a formal, legally binding CCPA/CPRA Deletion Demand and Opt-Out Notice
    pursuant to California Civil Code §§ 1798.100 et seq., 1798.105, 1798.120, and 1798.125.
    """
    ref_id = reference_id or generate_tracking_reference("CCPA", target.full_name, broker_name)
    current_date = date_str or datetime.now(timezone.utc).strftime("%B %d, %Y")
    schedule = format_identity_schedule(target, profile_url=profile_url)

    notice_text = f"""DEMAND FOR PERMANENT DELETION AND OPT-OUT OF SALE/SHARING OF PERSONAL INFORMATION
PURSUANT TO THE CALIFORNIA CONSUMER PRIVACY ACT (CCPA / CPRA)
CALIFORNIA CIVIL CODE § 1798.100 ET SEQ.

DATE: {current_date}
REFERENCE ID: {ref_id}

TO:
  Data Protection Officer / Privacy Compliance Department
  {broker_name}
  Notice of Statutory Legal Demand

FROM:
  {target.full_name}
  (Authorized California Consumer / Verified Data Subject)

--------------------------------------------------------------------------------
1. STATUTORY NOTICE & DEMAND
--------------------------------------------------------------------------------
Please be advised that this document serves as a formal statutory demand pursuant to the California Consumer Privacy Act of 2018, as amended by the California Privacy Rights Act of 2020 (collectively, "CCPA/CPRA"), codified at California Civil Code § 1798.100 et seq., and Title 11, Division 6 of the California Code of Regulations.

I hereby exercise the following statutory rights regarding all personal information, sensitive personal information, search indices, aggregated dossiers, and derived metadata maintained or controlled by {broker_name}, its parent corporations, affiliates, and subsidiaries:

  A. RIGHT TO DELETION (Cal. Civ. Code § 1798.105):
     I formally demand the permanent, irrevocable deletion of all personal information and sensitive personal information pertaining to me from all active databases, search indexes, archive servers, caching tiers, and backup storage systems maintained by {broker_name}.

  B. RIGHT TO OPT-OUT OF SALE AND SHARING (Cal. Civ. Code § 1798.120 & 11 CCR § 7027):
     I formally direct {broker_name} to immediately cease selling, sharing, renting, releasing, disclosing, disseminating, making available, transferring, or otherwise communicating my personal information to any third party for monetary or other valuable consideration, or for cross-context behavioral advertising.

  C. DOWNSTREAM CASCADE NOTIFICATION MANDATE (Cal. Civ. Code § 1798.105(c)(1)):
     Pursuant to Cal. Civ. Code § 1798.105(c)(1), {broker_name} is legally required to notify all service providers, contractors, data brokers, and downstream third parties to whom you have disclosed, sold, or shared my personal information, directing them to delete my personal information from all of their respective systems and archives.

{schedule}

--------------------------------------------------------------------------------
2. STATUTORY DEADLINES & ENFORCEMENT CITATIONS
--------------------------------------------------------------------------------
1. STATUTORY COMPLIANCE TIMELINE:
   - Pursuant to Cal. Civ. Code § 1798.130(a)(2) (California Civil Code § 1798.130), you are required to confirm receipt of this deletion request within 10 business days and fully execute the deletion within forty-five (45) calendar days from receipt.
   - Pursuant to 11 CCR § 7027(f), you are required to comply with this opt-out of sale/sharing demand within fifteen (15) business days.

2. NON-DISCRIMINATION DECLARATION (Cal. Civ. Code § 1798.125):
   As guaranteed by Cal. Civ. Code § 1798.125, you shall not discriminate against me, deny me goods or services, charge different prices or rates, or provide a different level or quality of services as a result of my exercise of rights under the CCPA.

3. STATUTORY ENFORCEMENT & PENALTIES:
   Failure to comply with this statutory demand within the mandated timeline will be reported directly to the California Privacy Protection Agency (CPPA) and the Office of the California Attorney General for formal enforcement action under Cal. Civ. Code § 1798.199.90, which provides for statutory civil penalties up to $7,500 for each intentional violation.

--------------------------------------------------------------------------------
3. CONSUMER IDENTITY VERIFICATION DECLARATION
--------------------------------------------------------------------------------
I declare under penalty of perjury under the laws of the State of California that I am the consumer whose personal information is identified in this demand, that I am authorized to submit this request, and that all identifying details provided in the Schedule above are true, correct, and complete.

Please transmit formal written confirmation of completion, including the tracking reference number and verification of downstream notifications, to the primary email address specified in the Consumer Identifying Information Schedule.

Sincerely,

{target.full_name}
Verified Consumer / Data Subject
Tracking Reference: {ref_id}
"""
    return notice_text.strip()


def generate_gdpr_notice(
    target: TargetIdentityInput,
    controller_name: str = "Data Controller / Privacy Department",
    profile_url: str | None = None,
    reference_id: str | None = None,
    date_str: str | None = None,
) -> str:
    """
    Generates a formal, legally binding GDPR Article 17 Erasure Request and Article 21 Objection Notice
    pursuant to Regulation (EU) 2016/679.
    """
    ref_id = reference_id or generate_tracking_reference("GDPR", target.full_name, controller_name)
    current_date = date_str or datetime.now(timezone.utc).strftime("%B %d, %Y")
    schedule = format_identity_schedule(target, profile_url=profile_url)

    notice_text = f"""FORMAL REQUEST FOR ERASURE OF PERSONAL DATA (ARTICLE 17 GDPR)
AND NOTICE OF OBJECTION TO DATA PROCESSING (ARTICLE 21 GDPR)
REGULATION (EU) 2016/679 (GENERAL DATA PROTECTION REGULATION)

DATE: {current_date}
REFERENCE ID: {ref_id}

TO:
  Data Protection Officer (DPO) / Legal & Compliance Department
  {controller_name}
  Formal GDPR Data Subject Request

FROM:
  {target.full_name}
  (Data Subject / European Union & Global Privacy Claimant)

--------------------------------------------------------------------------------
1. STATUTORY GROUNDS & FORMAL DEMANDS
--------------------------------------------------------------------------------
Pursuant to Regulation (EU) 2016/679 of the European Parliament and of the Council of 27 April 2016 (GDPR), I hereby submit this formal request for the immediate erasure of all personal data concerning me and notice of absolute objection to further data processing.

I formally invoke the following provisions of the GDPR:

  A. RIGHT TO ERASURE ("RIGHT TO BE FORGOTTEN") — ARTICLE 17(1):
     You are hereby requested to erase without undue delay all personal data relating to me held by {controller_name}, on the following statutory grounds:
     - Article 17(1)(a): The personal data are no longer necessary in relation to the purposes for which they were originally collected or otherwise processed.
     - Article 17(1)(c): I formally object to the processing pursuant to Article 21, and there are no overriding legitimate grounds for the processing.
     - Article 17(1)(d): The personal data have been unlawfully collected, aggregated, or published without an applicable legal basis under Article 6(1).

  B. RIGHT TO OBJECT TO PROCESSING — ARTICLE 21(1) & ARTICLE 21(2):
     - Pursuant to Article 21(1), I formally object to any processing of my personal data based on Article 6(1)(e) (public task) or Article 6(1)(f) (legitimate interests).
     - Pursuant to Article 21(2) and 21(3), I exercise my unconditional and absolute right to object to the processing of my personal data for direct marketing purposes, consumer profiling, background scoring, or commercial intelligence dissemination. Article 21(3) requires that where the data subject objects to processing for direct marketing, the personal data shall no longer be processed for such purposes with zero exception.

  C. NOTIFICATION OF DOWNSTREAM RECIPIENTS — ARTICLE 19 & ARTICLE 17(2):
     Pursuant to Article 19, {controller_name} shall communicate any erasure of personal data to each recipient to whom the personal data have been disclosed. Furthermore, pursuant to Article 17(2), you must take reasonable steps, including technical measures, to inform controllers processing the personal data that the data subject has requested the erasure of any links to, or copies or replications of, those personal data.

{schedule}

--------------------------------------------------------------------------------
2. STATUTORY DEADLINE & ADMINISTRATIVE PENALTIES WARNING
--------------------------------------------------------------------------------
1. STATUTORY TIMELINE (Article 12(3) GDPR):
   Under Article 12(3) of the GDPR, you are legally obligated to provide information on action taken on this request without undue delay and in any event within ONE MONTH (30 calendar days) of receipt of this notice.

2. REGULATORY ESCALATION & ADMINISTRATIVE FINES:
   Failure to comply with this statutory request within the prescribed one-month period will result in an immediate formal complaint lodged with the competent Supervisory Authority pursuant to Article 77 GDPR.

   Please be reminded that infringements of data subjects' rights under Articles 12 to 22 are subject to administrative fines of up to €20,000,000, or in the case of an undertaking, up to 4% of the total worldwide annual turnover of the preceding financial year, whichever is higher, pursuant to Article 83(5)(b) GDPR.

--------------------------------------------------------------------------------
3. IDENTITY VERIFICATION & ATTESTATION
--------------------------------------------------------------------------------
I confirm that I am the individual whose personal data is referenced in this demand and that the details supplied in the Consumer Identifying Information Schedule are accurate and sufficient to identify my records across your platforms and databases.

Please transmit written confirmation of compliance, detailing the completion of data erasure and downstream notifications, to the primary email address provided.

Respectfully submitted,

{target.full_name}
Data Subject
Reference ID: {ref_id}
"""
    return notice_text.strip()


def generate_peopleconnect_payload(
    target: TargetIdentityInput,
    reference_id: str | None = None,
    target_brands: list[str | PeopleConnectBrand] | None = None,
) -> SuppressionPayload:
    """
    Generates a consolidated Master Suppression Payload targeting PeopleConnect, Inc.
    and its managed child brands (TruthFinder, InstantCheckmate, Intelius, USSearch).
    """
    ref_id = reference_id or generate_tracking_reference("PC", target.full_name, "peopleconnect_master")
    brands = target_brands or [b.value for b in PeopleConnectBrand]
    brand_names = [b.value if isinstance(b, PeopleConnectBrand) else str(b) for b in brands]

    name_parts = target.full_name.strip().split()
    first_name = name_parts[0] if name_parts else ""
    last_name = name_parts[-1] if len(name_parts) > 1 else ""
    middle_name = " ".join(name_parts[1:-1]) if len(name_parts) > 2 else ""

    addr_line = target.known_addresses[0] if target.known_addresses else ""
    city = target.current_city or ""
    state = target.current_state or ""
    zip_code = ""
    if addr_line and not (city and state):
        parts = addr_line.split(",")
        if len(parts) >= 2:
            city = parts[-2].strip()
            state_zip = parts[-1].strip().split()
            if state_zip:
                state = state_zip[0]
                if len(state_zip) > 1:
                    zip_code = state_zip[1]

    form_payload: dict[str, Any] = {
        "first_name": first_name,
        "last_name": last_name,
        "middle_name": middle_name,
        "aliases": target.aliases,
        "email": target.primary_email or (target.secondary_emails[0] if target.secondary_emails else ""),
        "secondary_emails": target.secondary_emails,
        "phone": target.phone_numbers[0] if target.phone_numbers else "",
        "phone_numbers": target.phone_numbers,
        "city": city,
        "state": state,
        "zip_code": zip_code,
        "known_addresses": target.known_addresses,
        "opt_out_all_brands": True,
        "target_brands": brand_names,
        "brand_endpoints": {b: PEOPLECONNECT_BRAND_METADATA.get(b, {}).get("opt_out_url", "") for b in brand_names},
        "verification_method": "email",
        "suppression_scope": "COMPLETE_REMOVAL",
        "tracking_reference": ref_id,
    }

    legal_letter = f"""PEOPLECONNECT MASTER SUPPRESSION & DATA REMOVAL DEMAND
TARGET BRANDS: TruthFinder, InstantCheckmate, Intelius, USSearch
PARENT ENTITY: PeopleConnect, Inc. Privacy Compliance Operations
REFERENCE ID: {ref_id}
DATE: {datetime.now(timezone.utc).strftime('%B %d, %Y')}

TO:
  PeopleConnect, Inc. Privacy Compliance & Legal Department
  Centralized Opt-Out Administration (suppression.peopleconnect.us)

FROM:
  {target.full_name}
  (Authorized Data Subject / Consumer)

RE: Master Suppression and Irrevocable Record Suppression Across All PeopleConnect Platforms

1. MASTER OPT-OUT DIRECTIVE:
   Pursuant to applicable statutory privacy laws (including CCPA/CPRA Cal. Civ. Code § 1798.100 et seq., GDPR Regulation (EU) 2016/679, and state privacy enactments), this demand serves as a unified Master Opt-Out and Deletion request directed to PeopleConnect, Inc. across all owned, operated, or affiliated people-search platforms, including but not limited to:
   - TruthFinder (truthfinder.com)
   - Instant Checkmate (instantcheckmate.com)
   - Intelius (intelius.com)
   - US Search (ussearch.com)

2. IDENTIFYING PARTICULARS:
   - Legal Name: {target.full_name}
   - Aliases: {', '.join(target.aliases) if target.aliases else 'None reported'}
   - Primary Contact Email: {target.primary_email or 'N/A'}
   - Primary Phone: {target.phone_numbers[0] if target.phone_numbers else 'N/A'}
   - Registered Addresses: {'; '.join(target.known_addresses) if target.known_addresses else f'{city}, {state}'}

3. REQUIRED REMEDIATION ACTIONS:
   A. Permanently flag and suppress all records matching the above identifiers across all PeopleConnect centralized master databases.
   B. Expunge public directory listings, search caches, report generator engines, and historical lookup archives across TruthFinder, Instant Checkmate, Intelius, and US Search.
   C. Suppress future ingestion, re-indexing, or re-population of records pertaining to this identity.

4. CERTIFICATION:
   I hereby certify under penalty of perjury that I am the person named above, or authorized to act on their behalf, and demand confirmation of suppression within statutory deadlines.

Tracking Reference: {ref_id}
"""

    return SuppressionPayload(
        remediation_id=f"rem_{uuid.uuid4().hex[:8]}",
        broker_id="peopleconnect_master",
        broker_name="PeopleConnect Master Suppression (TruthFinder, InstantCheckmate, Intelius, USSearch)",
        opt_out_type="master_opt_out",
        target_profile_url="https://suppression.peopleconnect.us/",
        form_payload=form_payload,
        legal_request_letter=legal_letter.strip(),
        submission_url="https://suppression.peopleconnect.us/api/suppression/request",
        status=SuppressionStatus.PENDING,
        generated_at=datetime.now(timezone.utc),
    )


def generate_master_ccpa_letter(
    target: TargetIdentityInput,
    profiles: list[ExtractedEntityProfile] | None = None,
    effective_date: str | None = None,
) -> str:
    """
    Generates an omnibus CCPA/CPRA master statutory demand letter
    incorporating § 1798.105, § 1798.120, § 1798.125 with all discovered broker profiles.
    """
    date_str = effective_date or datetime.now(timezone.utc).strftime("%B %d, %Y")
    aliases_str = ", ".join(target.aliases) if target.aliases else "None specified"
    emails = [target.primary_email] if target.primary_email else []
    emails.extend([e for e in target.secondary_emails if e not in emails])
    emails_str = ", ".join(emails) if emails else "None specified"
    phones_str = ", ".join(target.phone_numbers) if target.phone_numbers else "None specified"

    addresses: list[str] = []
    if target.known_addresses:
        addresses.extend(target.known_addresses)
    elif target.current_city and target.current_state:
        addresses.append(f"{target.current_city}, {target.current_state}")
    addresses_str = "; ".join(addresses) if addresses else "None specified"

    exposures_section = ""
    if profiles:
        exposures_section = "\nIDENTIFIED EXPOSURE RECORDS & BROKER PROFILES:\n"
        for idx, p in enumerate(profiles, start=1):
            broker_label = (p.source_broker or "Data Broker").title()
            url_val = p.removal_url or p.source_url or "URL not recorded"
            matched = ", ".join(p.matched_names) if p.matched_names else target.full_name
            exposures_section += f"{idx}. {broker_label}: {url_val} (Matched Identity: {matched})\n"
    else:
        exposures_section = "\nIDENTIFIED EXPOSURE RECORDS: Global defensive suppression request across all data aggregator databases.\n"

    letter = f"""CALIFORNIA CONSUMER PRIVACY ACT (CCPA) & CALIFORNIA PRIVACY RIGHTS ACT (CPRA)
OMNIBUS NOTICE OF FORMAL CONSUMER RIGHTS INVOCATION
Cal. Civ. Code §§ 1798.100 - 1798.199.100

DATE: {date_str}
TO: Privacy Officer / Designated Agent for CCPA Compliance

FROM (CONSUMER IDENTITY):
Legal Full Name: {target.full_name}
Known Aliases: {aliases_str}
Verified Email Address(es): {emails_str}
Verified Phone Number(s): {phones_str}
Current / Historical Physical Addresses: {addresses_str}
{exposures_section}
DEMAND AND NOTICE OF CONSUMER RIGHTS:

Pursuant to the California Consumer Privacy Act of 2018 (CCPA) as amended by the California Privacy Rights Act of 2020 (CPRA), California Civil Code §§ 1798.100 et seq., I hereby formally submit the following binding legal directives regarding all personal information, sensitive personal information, digital identifiers, and consumer profiles relating to me:

1. RIGHT TO OPT-OUT OF SALE AND SHARING (Cal. Civ. Code § 1798.120):
I hereby explicitly direct you and all affiliated entities, subsidiaries, downstream data brokers, and corporate partners to cease selling, sharing, licensing, transferring, renting, or disclosing my personal information to any third party for valuable consideration, cross-context behavioral advertising, or data brokerage monetization.

2. RIGHT TO DELETION OF PERSONAL INFORMATION (Cal. Civ. Code § 1798.105):
I formally demand the immediate, permanent deletion, expungement, and erasure of all personal information and records collected, scraped, indexed, aggregated, or derived concerning me across all production databases, search indexes, archival storage, caches, and backup repositories under your custody or control.

3. RIGHT TO LIMIT USE OF SENSITIVE PERSONAL INFORMATION (Cal. Civ. Code § 1798.121):
To the extent any sensitive personal information (including precise geolocation, government identifiers, financial records, biometric data, or communications) is maintained, I direct you to limit its use strictly to what is strictly necessary to perform authorized consumer transactions.

4. DOWNSTREAM NOTIFICATION OBLIGATION (Cal. Civ. Code § 1798.105(c)):
You are legally required to notify all third parties, downstream data purchasers, affiliates, and service providers to whom you sold, shared, or transferred my personal information to delete my personal information from their respective records.

5. NON-DISCRIMINATION (Cal. Civ. Code § 1798.125):
In accordance with § 1798.125, you may not discriminate against me, deny goods or services, charge different rates, or provide an altered level of quality due to the exercise of these statutory privacy rights.

6. STATUTORY COMPLIANCE TIMEFRAME:
In accordance with Cal. Civ. Code § 1798.130 and 11 CCR § 7002, you must confirm receipt of this request within ten (10) business days and complete substantive compliance within forty-five (45) calendar days.

DECLARATION UNDER PENALTY OF PERJURY:
I declare under penalty of perjury under the laws of the State of California and the United States of America that I am the individual named above, or the legally authorized representative of the individual, and that the information provided is true and accurate.

Sincerely,
{target.full_name}
Digital Signature Ref: GHOST-CCPA-{uuid.uuid4().hex[:12].upper()}
""".strip()
    return letter


def generate_master_gdpr_letter(
    target: TargetIdentityInput,
    profiles: list[ExtractedEntityProfile] | None = None,
    effective_date: str | None = None,
) -> str:
    """
    Generates a comprehensive omnibus GDPR Article 17 Erasure and Article 21 Objection demand notice.
    """
    date_str = effective_date or datetime.now(timezone.utc).strftime("%B %d, %Y")
    aliases_str = ", ".join(target.aliases) if target.aliases else "None specified"
    emails = [target.primary_email] if target.primary_email else []
    emails.extend([e for e in target.secondary_emails if e not in emails])
    emails_str = ", ".join(emails) if emails else "None specified"
    phones_str = ", ".join(target.phone_numbers) if target.phone_numbers else "None specified"

    addresses: list[str] = []
    if target.known_addresses:
        addresses.extend(target.known_addresses)
    elif target.current_city and target.current_state:
        addresses.append(f"{target.current_city}, {target.current_state}")
    addresses_str = "; ".join(addresses) if addresses else "None specified"

    exposures_section = ""
    if profiles:
        exposures_section = "\nIDENTIFIED DATA CONTROLLER ENDPOINTS & PROFILES:\n"
        for idx, p in enumerate(profiles, start=1):
            broker_label = (p.source_broker or "Data Broker").title()
            url_val = p.removal_url or p.source_url or "URL not recorded"
            exposures_section += f"{idx}. {broker_label}: {url_val}\n"
    else:
        exposures_section = "\nIDENTIFIED DATA PROCESSING: Comprehensive erasure demand covering all consumer database records.\n"

    letter = f"""REGULATION (EU) 2016/679 OF THE EUROPEAN PARLIAMENT AND OF THE COUNCIL (GDPR)
FORMAL EXERCISE OF DATA SUBJECT RIGHTS: ARTICLE 17 ERASURE & ARTICLE 21 OBJECTION

DATE: {date_str}
TO: Data Protection Officer (DPO) / Data Controller Legal Representative

DATA SUBJECT IDENTIFICATION:
Full Legal Name: {target.full_name}
Aliases / Previous Names: {aliases_str}
Associated Email Address(es): {emails_str}
Associated Telephone Number(s): {phones_str}
Address / Geographic Residence: {addresses_str}
{exposures_section}
LEGAL DEMANDS PURSUANT TO REGULATION (EU) 2016/679:

As a Data Subject, I hereby formally invoke my statutory rights under the General Data Protection Regulation (GDPR) and instruct you to execute the following mandatory obligations:

1. RIGHT TO ERASURE / "RIGHT TO BE FORGOTTEN" (ARTICLE 17 GDPR):
I demand the immediate and unconditional erasure of all personal data relating to me without undue delay pursuant to Article 17(1) GDPR, on the grounds that:
  a) The personal data are no longer necessary in relation to the purposes for which they were collected or otherwise processed (Art. 17(1)(a));
  b) I hereby withdraw any and all consent on which the processing may be based (Art. 17(1)(b));
  c) I object to the processing pursuant to Article 21(1) and there are no overriding legitimate grounds for the processing (Art. 17(1)(c));
  d) The personal data have been unlawfully scraped, processed, or indexed without a valid lawful basis under Article 6 (Art. 17(1)(d)).

2. RIGHT TO OBJECT TO PROCESSING (ARTICLE 21 GDPR):
Pursuant to Article 21(1) GDPR, I object on grounds relating to my particular situation to the processing of personal data concerning me. Furthermore, pursuant to Article 21(2) & 21(3) GDPR, I unconditionally object to the processing of my personal data for direct marketing, profiling, and background search monetization purposes.

3. NOTIFICATION OF THIRD-PARTY RECIPIENTS (ARTICLE 19 GDPR):
In accordance with Article 19 GDPR, you are legally required to communicate this erasure to each recipient to whom the personal data have been disclosed, unless this proves impossible or involves disproportionate effort.

4. STATUTORY RESPONSE TIMEFRAME (ARTICLE 12(3) GDPR):
Pursuant to Article 12(3) GDPR, you must provide information on action taken on this request without undue delay and in any event within one (1) month of receipt of the request.

5. SUPERVISORY AUTHORITY NOTIFICATION (ARTICLE 77 GDPR):
Please be advised that failure to comply with this statutory request within the prescribed timeframe may result in formal complaint lodgment with the competent Data Protection Supervisory Authority pursuant to Article 77 GDPR and civil action under Article 79 GDPR.

Respectfully submitted,
{target.full_name}
Digital Identifier: GHOST-GDPR-{uuid.uuid4().hex[:12].upper()}
""".strip()
    return letter


def generate_broker_legal_letter(
    broker_name: str,
    target: TargetIdentityInput,
    profile_url: str | None = None,
) -> str:
    """
    Generates a concise, broker-specific CCPA/GDPR demand notice for individual payload records.
    """
    email = target.primary_email or "(verified contact on file)"
    phone = target.phone_numbers[0] if target.phone_numbers else "(verified phone on file)"
    url_clause = f"\nTarget Profile URL: {profile_url}" if profile_url else ""

    return f"""FORMAL PRIVACY REMOVAL & OPT-OUT NOTICE
TO: {broker_name} Privacy Compliance Department
RE: Immediate Opt-Out & Record Suppression for {target.full_name}

Consumer: {target.full_name}
Contact Email: {email}
Contact Phone: {phone}{url_clause}

Pursuant to the California Consumer Privacy Act (Cal. Civ. Code § 1798.105/120) and GDPR Article 17, I hereby request the immediate opt-out from sale/sharing and complete removal of all listings, records, and background profiles associated with my identity from your database and search directory.

Please process this suppression request immediately and confirm completion.

Authorized Signature: {target.full_name}
Ref: GHOST-BROKER-{uuid.uuid4().hex[:8].upper()}
""".strip()


class LegalNoticeGenerator:
    """
    Statutory Legal Notice Generator for Project Umbra.
    Provides standardized rendering of CCPA, GDPR, and PeopleConnect remediation notices.
    """

    def __init__(self, default_jurisdiction: Literal["CCPA", "GDPR", "AUTO"] = "AUTO") -> None:
        self.default_jurisdiction = default_jurisdiction

    def generate_ccpa(
        self,
        target: TargetIdentityInput,
        broker_name: str = "Data Broker",
        profile_url: str | None = None,
        reference_id: str | None = None,
    ) -> str:
        return generate_ccpa_notice(
            target=target,
            broker_name=broker_name,
            profile_url=profile_url,
            reference_id=reference_id,
        )

    def generate_gdpr(
        self,
        target: TargetIdentityInput,
        controller_name: str = "Data Controller",
        profile_url: str | None = None,
        reference_id: str | None = None,
    ) -> str:
        return generate_gdpr_notice(
            target=target,
            controller_name=controller_name,
            profile_url=profile_url,
            reference_id=reference_id,
        )

    def generate_peopleconnect(
        self,
        target: TargetIdentityInput,
        reference_id: str | None = None,
        target_brands: list[str | PeopleConnectBrand] | None = None,
    ) -> SuppressionPayload:
        return generate_peopleconnect_payload(
            target=target,
            reference_id=reference_id,
            target_brands=target_brands,
        )

    def generate_notice_for_exposure(
        self,
        target: TargetIdentityInput,
        profile: ExtractedEntityProfile,
        jurisdiction: Literal["CCPA", "GDPR"] = "CCPA",
    ) -> str:
        """Generates a customized legal notice for a detected exposure profile."""
        broker_name = (profile.source_broker or "Data Broker").replace("_", " ").title()
        if jurisdiction == "GDPR":
            return self.generate_gdpr(
                target=target,
                controller_name=broker_name,
                profile_url=profile.source_url or profile.removal_url,
            )
        return self.generate_ccpa(
            target=target,
            broker_name=broker_name,
            profile_url=profile.source_url or profile.removal_url,
        )


# ==============================================================================
# 4. Profile Normalization & Aggregation
# ==============================================================================

def normalize_broker_id(raw_broker: str | None, url: str | None = None) -> str:
    """
    Normalizes arbitrary broker names or URLs into canonical broker keys.
    """
    if raw_broker:
        clean = re.sub(r"[^a-zA-Z0-9]", "", raw_broker).lower()
        for known_key in KNOWN_BROKER_REGISTRY:
            if known_key in clean or clean in known_key:
                return known_key
        return raw_broker.strip().lower().replace(" ", "_")

    if url:
        url_lower = url.lower()
        for known_key in KNOWN_BROKER_REGISTRY:
            if known_key in url_lower:
                return known_key
        match = re.search(r"https?://(?:www\.)?([^/]+)", url_lower)
        if match:
            return match.group(1).replace(".", "_")

    return "data_broker"


def aggregate_and_deduplicate_profiles(
    profiles: list[ExtractedEntityProfile],
) -> list[ExtractedEntityProfile]:
    """
    Groups and merges multiple ExtractedEntityProfile records belonging to the same broker.
    Combines matched names, phone numbers, emails, and addresses while preserving
    the best removal URL and highest confidence score.
    """
    if not profiles:
        return []

    grouped: dict[str, ExtractedEntityProfile] = {}

    for prof in profiles:
        broker_key = normalize_broker_id(prof.source_broker, prof.source_url)

        if broker_key not in grouped:
            grouped[broker_key] = ExtractedEntityProfile(
                target_id=prof.target_id,
                source_url=prof.source_url,
                source_broker=prof.source_broker or broker_key,
                matched_names=list(dict.fromkeys(prof.matched_names)),
                age=prof.age,
                phone_numbers=list(dict.fromkeys(prof.phone_numbers)),
                email_addresses=list(dict.fromkeys(prof.email_addresses)),
                current_address=prof.current_address,
                past_addresses=list(dict.fromkeys(prof.past_addresses)),
                relatives=list(dict.fromkeys(prof.relatives)),
                associates=list(dict.fromkeys(prof.associates)),
                removal_url=prof.removal_url or prof.source_url,
                confidence_score=prof.confidence_score,
            )
        else:
            existing = grouped[broker_key]
            existing.matched_names = list(dict.fromkeys(existing.matched_names + prof.matched_names))
            existing.phone_numbers = list(dict.fromkeys(existing.phone_numbers + prof.phone_numbers))
            existing.email_addresses = list(dict.fromkeys(existing.email_addresses + prof.email_addresses))
            existing.past_addresses = list(dict.fromkeys(existing.past_addresses + prof.past_addresses))
            existing.relatives = list(dict.fromkeys(existing.relatives + prof.relatives))
            existing.associates = list(dict.fromkeys(existing.associates + prof.associates))

            if not existing.current_address and prof.current_address:
                existing.current_address = prof.current_address
            if not existing.age and prof.age:
                existing.age = prof.age
            if prof.removal_url and (not existing.removal_url or "removal" in prof.removal_url or "opt-out" in prof.removal_url):
                existing.removal_url = prof.removal_url
            if prof.confidence_score > existing.confidence_score:
                existing.confidence_score = prof.confidence_score

    return list(grouped.values())


def build_broker_payload(
    target: TargetIdentityInput,
    profile: ExtractedEntityProfile | None,
    broker_id: str,
    broker_meta: dict[str, Any] | None = None,
    profile_url: str | None = None,
) -> SuppressionPayload:
    """
    Builds a single customized SuppressionPayload for a broker with structured form data.
    """
    meta = broker_meta or KNOWN_BROKER_REGISTRY.get(broker_id, {})
    broker_name = meta.get("broker_name", broker_id.replace("_", " ").title())
    opt_out_type: Literal["automated_form", "ccpa_email", "gdpr_email", "master_opt_out"] = meta.get(
        "opt_out_type", "automated_form"
    )
    submission_url = meta.get("opt_out_url") or (profile.removal_url if profile else None)

    target_profile_url = profile_url or ((profile.removal_url or profile.source_url) if profile else None)
    primary_email = target.primary_email or (target.secondary_emails[0] if target.secondary_emails else f"{target.full_name.lower().replace(' ', '.')}@example.com")
    primary_phone = target.phone_numbers[0] if target.phone_numbers else "(555) 010-0000"

    form_payload: dict[str, Any] = {}

    if broker_id == "truepeoplesearch":
        name_slug = re.sub(r"[^a-z0-9]+", "-", target.full_name.lower()).strip("-")
        form_payload = {
            "RecordUrl": target_profile_url or f"https://www.truepeoplesearch.com/find/person/{name_slug}",
            "Email": primary_email,
            "TermsAccepted": "true",
            "Reason": "CCPA / CPRA Personal Data Deletion Request",
            "FullName": target.full_name,
        }
    elif broker_id == "fastpeoplesearch":
        name_slug = re.sub(r"[^a-z0-9]+", "-", target.full_name.lower()).strip("-")
        form_payload = {
            "target_record_url": target_profile_url or f"https://www.fastpeoplesearch.com/name/{name_slug}",
            "contact_email": primary_email,
            "agree_to_terms": "1",
            "opt_out_reason": "Statutory privacy opt-out request",
            "subject_name": target.full_name,
        }
    elif broker_id == "radaris":
        name_slug = re.sub(r"[^a-z0-9]+", "-", target.full_name.lower()).strip("-")
        form_payload = {
            "name": target.full_name,
            "profile_url": target_profile_url or f"https://radaris.com/p/{name_slug}",
            "email": primary_email,
            "reason": "Consumer privacy data removal (CCPA/GDPR)",
            "action": "suppress_record",
        }
    elif broker_id == "nuwber":
        name_slug = re.sub(r"[^a-z0-9]+", "-", target.full_name.lower()).strip("-")
        form_payload = {
            "url": target_profile_url or f"https://nuwber.com/person/{name_slug}",
            "email": primary_email,
            "jurisdiction": "California / CCPA",
            "removal_reason": "Right to be forgotten request",
        }
    elif broker_id == "whitepages":
        name_slug = re.sub(r"[^a-z0-9]+", "-", target.full_name.lower()).strip("-")
        form_payload = {
            "listing_url": target_profile_url or f"https://www.whitepages.com/name/{name_slug}",
            "requester_email": primary_email,
            "requester_phone": primary_phone,
            "request_type": "full_suppression",
            "subject_name": target.full_name,
        }
    elif broker_id == "peopleconnect":
        name_parts = target.full_name.split()
        first_name = name_parts[0] if name_parts else "John"
        last_name = name_parts[-1] if len(name_parts) > 1 else "Doe"
        form_payload = {
            "first_name": first_name,
            "last_name": last_name,
            "email": primary_email,
            "phone_number": primary_phone if target.phone_numbers else None,
            "city": target.current_city,
            "state": target.current_state,
            "request_type": "master_suppression",
        }
    else:
        form_payload = {
            "full_name": target.full_name,
            "email": primary_email,
            "phone": primary_phone,
            "profile_url": target_profile_url,
            "request_type": "ccpa_gdpr_opt_out",
        }

    legal_letter = generate_broker_legal_letter(broker_name, target, profile_url=target_profile_url)

    return SuppressionPayload(
        remediation_id=f"rem_{uuid.uuid4().hex[:8]}",
        broker_id=broker_id,
        broker_name=broker_name,
        opt_out_type=opt_out_type,
        target_profile_url=target_profile_url,
        form_payload=form_payload,
        legal_request_letter=legal_letter,
        submission_url=submission_url,
        status=SuppressionStatus.PENDING,
        generated_at=datetime.now(timezone.utc),
    )


# ==============================================================================
# 5. Broker Form Dispatchers
# ==============================================================================

class BaseBrokerDispatcher:
    """Abstract base dispatcher for data broker removal submissions."""

    broker_id: str = "generic"
    broker_name: str = "Generic Broker"
    default_endpoint: str = "https://example.com/optout"

    def build_form_payload(
        self,
        identity: TargetIdentityInput,
        profile_url: str | None = None,
    ) -> dict[str, Any]:
        """Constructs broker-specific form fields dictionary."""
        email = identity.primary_email or f"{identity.full_name.lower().replace(' ', '.')}@example.com"
        return {
            "full_name": identity.full_name,
            "email": email,
            "profile_url": profile_url or f"https://{self.broker_id}.com/p/{identity.full_name.lower().replace(' ', '-')}",
            "reason": "Personal data suppression under applicable privacy statutes (CCPA/GDPR)",
            "accepted_terms": True,
        }

    async def submit(
        self,
        payload: SuppressionPayload,
        client: httpx.AsyncClient | None = None,
        simulation_mode: bool = False,
    ) -> SuppressionReceipt:
        """Dispatches form submission either live or via simulation fixture."""
        email_val = (
            payload.form_payload.get("email")
            or payload.form_payload.get("Email")
            or payload.form_payload.get("contact_email")
            or payload.form_payload.get("requester_email")
        )

        if simulation_mode or client is None:
            fixture = SIMULATED_BROKER_RESPONSES.get(self.broker_id, SIMULATED_BROKER_RESPONSES["default"])
            return create_suppression_receipt(
                remediation_id=payload.remediation_id,
                broker_name=payload.broker_name,
                broker_id=self.broker_id,
                notice_type=fixture["notice_type"],
                status_code=fixture["status_code"],
                confirmation_message=fixture["message"],
                email=email_val,
                profile_url=payload.target_profile_url,
            )

        url = payload.submission_url or self.default_endpoint
        origin_match = re.match(r"https?://[^/]+", url)
        origin = origin_match.group(0) if origin_match else url
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Referer": url,
            "Origin": origin,
        }

        try:
            resp = await client.post(url, data=payload.form_payload, headers=headers, timeout=10.0)
            status_code = resp.status_code
            msg = f"{self.broker_name} opt-out request acknowledged with HTTP {status_code}."
            if status_code == 200:
                payload.status = SuppressionStatus.CONFIRMED
            elif 200 <= status_code < 300:
                payload.status = SuppressionStatus.SUBMITTED
            else:
                payload.status = SuppressionStatus.FAILED

            return create_suppression_receipt(
                remediation_id=payload.remediation_id,
                broker_name=payload.broker_name,
                broker_id=self.broker_id,
                notice_type=f"Automated Web Form ({self.broker_name})",
                status_code=status_code,
                confirmation_message=msg,
                email=email_val,
                profile_url=payload.target_profile_url,
            )
        except Exception as e:
            logger.warning(
                "Live submission failed for %s (%s)",
                self.broker_name,
                type(e).__name__,
            )
            payload.status = SuppressionStatus.FAILED
            return create_suppression_receipt(
                remediation_id=payload.remediation_id,
                broker_name=payload.broker_name,
                broker_id=self.broker_id,
                notice_type=f"Automated Web Form ({self.broker_name})",
                status_code=500,
                confirmation_message=f"Submission failed: {str(e)}",
                email=email_val,
                profile_url=payload.target_profile_url,
            )


class TruePeopleSearchDispatcher(BaseBrokerDispatcher):
    broker_id = "truepeoplesearch"
    broker_name = "TruePeopleSearch"
    default_endpoint = BROKER_REMOVAL_ENDPOINTS["truepeoplesearch"]

    def build_form_payload(self, identity: TargetIdentityInput, profile_url: str | None = None) -> dict[str, Any]:
        email = identity.primary_email or f"{identity.full_name.lower().replace(' ', '.')}@example.com"
        name_slug = re.sub(r"[^a-z0-9]+", "-", identity.full_name.lower()).strip("-")
        return {
            "RecordUrl": profile_url or f"https://www.truepeoplesearch.com/find/person/{name_slug}",
            "Email": email,
            "TermsAccepted": "true",
            "Reason": "CCPA / CPRA Personal Data Deletion Request",
            "FullName": identity.full_name,
        }


class FastPeopleSearchDispatcher(BaseBrokerDispatcher):
    broker_id = "fastpeoplesearch"
    broker_name = "FastPeopleSearch"
    default_endpoint = BROKER_REMOVAL_ENDPOINTS["fastpeoplesearch"]

    def build_form_payload(self, identity: TargetIdentityInput, profile_url: str | None = None) -> dict[str, Any]:
        email = identity.primary_email or f"{identity.full_name.lower().replace(' ', '.')}@example.com"
        name_slug = re.sub(r"[^a-z0-9]+", "-", identity.full_name.lower()).strip("-")
        return {
            "target_record_url": profile_url or f"https://www.fastpeoplesearch.com/name/{name_slug}",
            "contact_email": email,
            "agree_to_terms": "1",
            "opt_out_reason": "Statutory privacy opt-out request",
            "subject_name": identity.full_name,
        }


class RadarisDispatcher(BaseBrokerDispatcher):
    broker_id = "radaris"
    broker_name = "Radaris"
    default_endpoint = BROKER_REMOVAL_ENDPOINTS["radaris"]

    def build_form_payload(self, identity: TargetIdentityInput, profile_url: str | None = None) -> dict[str, Any]:
        email = identity.primary_email or f"{identity.full_name.lower().replace(' ', '.')}@example.com"
        name_slug = re.sub(r"[^a-z0-9]+", "-", identity.full_name.lower()).strip("-")
        return {
            "name": identity.full_name,
            "profile_url": profile_url or f"https://radaris.com/p/{name_slug}",
            "email": email,
            "reason": "Consumer privacy data removal (CCPA/GDPR)",
            "action": "suppress_record",
        }


class NuwberDispatcher(BaseBrokerDispatcher):
    broker_id = "nuwber"
    broker_name = "Nuwber"
    default_endpoint = BROKER_REMOVAL_ENDPOINTS["nuwber"]

    def build_form_payload(self, identity: TargetIdentityInput, profile_url: str | None = None) -> dict[str, Any]:
        email = identity.primary_email or f"{identity.full_name.lower().replace(' ', '.')}@example.com"
        name_slug = re.sub(r"[^a-z0-9]+", "-", identity.full_name.lower()).strip("-")
        return {
            "url": profile_url or f"https://nuwber.com/person/{name_slug}",
            "email": email,
            "jurisdiction": "California / CCPA",
            "removal_reason": "Right to be forgotten request",
        }


class WhitepagesDispatcher(BaseBrokerDispatcher):
    broker_id = "whitepages"
    broker_name = "Whitepages"
    default_endpoint = BROKER_REMOVAL_ENDPOINTS["whitepages"]

    def build_form_payload(self, identity: TargetIdentityInput, profile_url: str | None = None) -> dict[str, Any]:
        email = identity.primary_email or f"{identity.full_name.lower().replace(' ', '.')}@example.com"
        phone = identity.phone_numbers[0] if identity.phone_numbers else "(555) 019-2834"
        name_slug = re.sub(r"[^a-z0-9]+", "-", identity.full_name.lower()).strip("-")
        return {
            "listing_url": profile_url or f"https://www.whitepages.com/name/{name_slug}",
            "requester_email": email,
            "requester_phone": phone,
            "request_type": "full_suppression",
            "subject_name": identity.full_name,
        }


class PeopleConnectDispatcher(BaseBrokerDispatcher):
    broker_id = "peopleconnect"
    broker_name = "PeopleConnect"
    default_endpoint = BROKER_REMOVAL_ENDPOINTS["peopleconnect"]

    def build_form_payload(self, identity: TargetIdentityInput, profile_url: str | None = None) -> dict[str, Any]:
        email = identity.primary_email or f"{identity.full_name.lower().replace(' ', '.')}@example.com"
        name_parts = identity.full_name.split()
        first_name = name_parts[0] if name_parts else "John"
        last_name = name_parts[-1] if len(name_parts) > 1 else "Doe"
        return {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone_number": identity.phone_numbers[0] if identity.phone_numbers else None,
            "city": identity.current_city,
            "state": identity.current_state,
            "request_type": "master_suppression",
        }


DISPATCHER_REGISTRY: dict[str, BaseBrokerDispatcher] = {
    "truepeoplesearch": TruePeopleSearchDispatcher(),
    "fastpeoplesearch": FastPeopleSearchDispatcher(),
    "radaris": RadarisDispatcher(),
    "nuwber": NuwberDispatcher(),
    "whitepages": WhitepagesDispatcher(),
    "peopleconnect": PeopleConnectDispatcher(),
}


# ==============================================================================
# 6. Master Suppression Engine Service
# ==============================================================================

class SuppressionEngine:
    """
    Comprehensive suppression payload generator, automated submission bot,
    statutory CCPA/GDPR demand synthesizer, and cryptographic receipt issuer.
    """

    def __init__(
        self,
        simulation_mode: bool | None = None,
        timeout_seconds: float = 10.0,
        broker_registry: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.simulation_mode = (
            settings.PLAYWRIGHT_SIMULATION_MODE if simulation_mode is None else simulation_mode
        )
        self.timeout_seconds = timeout_seconds
        self.broker_registry = broker_registry or KNOWN_BROKER_REGISTRY
        self._client: httpx.AsyncClient | None = None
        self._dispatchers = DISPATCHER_REGISTRY

    async def initialize(self) -> None:
        """Initializes internal HTTP client for live dispatches."""
        if not self.simulation_mode and self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True)

    async def close(self) -> None:
        """Closes internal HTTP client cleanly."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> SuppressionEngine:
        await self.initialize()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def get_dispatcher(self, broker_id: str) -> BaseBrokerDispatcher:
        """Retrieves matching dispatcher or returns generic fallback."""
        norm = broker_id.lower().replace("-", "").replace("_", "")
        for k, v in self._dispatchers.items():
            if k in norm:
                return v
        return BaseBrokerDispatcher()

    def build_payload(
        self,
        broker_id: str,
        identity: TargetIdentityInput,
        profile_url: str | None = None,
        opt_out_type: Literal["automated_form", "ccpa_email", "gdpr_email", "master_opt_out"] = "automated_form",
    ) -> SuppressionPayload:
        """Constructs a typed SuppressionPayload for a single broker."""
        meta = self.broker_registry.get(broker_id, {})
        return build_broker_payload(identity, None, broker_id, meta, profile_url=profile_url)

    def compile_plan(
        self,
        target_input: TargetIdentityInput | None = None,
        profiles: list[ExtractedEntityProfile] | None = None,
        target_id: str | None = None,
        identity: TargetIdentityInput | None = None,
        findings: list[ExtractedEntityProfile] | None = None,
    ) -> SuppressionActionPlan:
        """
        Compiles a comprehensive SuppressionActionPlan from target input and extracted profiles.
        """
        tgt = target_input or identity
        if tgt is None:
            raise ValueError("Target identity input is required to compile suppression plan.")

        effective_target_id = target_id or f"tgt_{uuid.uuid4().hex[:8]}"
        raw_profiles = profiles if profiles is not None else (findings or [])
        deduped_profiles = aggregate_and_deduplicate_profiles(raw_profiles)

        actions: list[SuppressionPayload] = []

        if deduped_profiles:
            seen_brokers: set[str] = set()
            for prof in deduped_profiles:
                broker_key = normalize_broker_id(prof.source_broker, prof.source_url)
                if broker_key in seen_brokers:
                    continue
                seen_brokers.add(broker_key)
                meta = self.broker_registry.get(broker_key)
                payload = build_broker_payload(tgt, prof, broker_key, meta)
                actions.append(payload)
        else:
            for broker_key in DEFAULT_PROACTIVE_BROKERS:
                meta = self.broker_registry.get(broker_key)
                payload = build_broker_payload(tgt, None, broker_key, meta)
                actions.append(payload)

        master_ccpa = generate_master_ccpa_letter(tgt, deduped_profiles)
        master_gdpr = generate_master_gdpr_letter(tgt, deduped_profiles)

        return SuppressionActionPlan(
            target_id=effective_target_id,
            actions=actions,
            total_actions=len(actions),
            master_ccpa_letter=master_ccpa,
            master_gdpr_letter=master_gdpr,
        )

    def generate_remediation_plan(
        self,
        identity: TargetIdentityInput | None = None,
        findings: list[ExtractedEntityProfile] | None = None,
        target_id: str | None = None,
        target_input: TargetIdentityInput | None = None,
        profiles: list[ExtractedEntityProfile] | None = None,
    ) -> SuppressionActionPlan:
        """
        Unified method to generate remediation action plan.
        Accepts any combination of identity/target_input and findings/profiles.
        """
        tgt = identity or target_input
        if tgt is None:
            raise ValueError("Target identity input is required.")
        profs = findings if findings is not None else (profiles or [])
        return self.compile_plan(target_input=tgt, profiles=profs, target_id=target_id)

    async def submit_suppression(
        self,
        payload: SuppressionPayload,
    ) -> SuppressionReceipt:
        """Submits an individual SuppressionPayload and generates a cryptographic receipt."""
        dispatcher = self.get_dispatcher(payload.broker_id)
        receipt = await dispatcher.submit(
            payload=payload,
            client=self._client,
            simulation_mode=self.simulation_mode,
        )
        return receipt

    async def submit_all(
        self,
        payloads: list[SuppressionPayload],
    ) -> list[SuppressionReceipt]:
        """Concurrently submits multiple suppression payloads."""
        tasks = [self.submit_suppression(p) for p in payloads]
        return await asyncio.gather(*tasks)

    async def execute_plan(
        self,
        plan: SuppressionActionPlan,
    ) -> list[SuppressionReceipt]:
        """Executes all actions within a SuppressionActionPlan."""
        return await self.submit_all(plan.actions)
