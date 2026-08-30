"""
Project Umbra Fixtures Module.
Loads and formats deterministic mock SERP responses and broker HTML pages.
"""

from __future__ import annotations

import functools
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from project_umbra.core.state import (
    DorkCategory,
    DorkQuery,
    ExecutionProvenance,
    PriorityLevel,
    SERPFinding,
    TargetIdentityInput,
)

FIXTURES_DIR = Path(__file__).parent


@functools.lru_cache(maxsize=1)
def load_serp_fixtures() -> dict[str, Any]:
    """Loads the mock_serp.json fixture with caching."""
    json_path = FIXTURES_DIR / "mock_serp.json"
    if not json_path.exists():
        return {"by_category": {}}
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_mock_serp_findings(
    dork: DorkQuery,
    target_name: str | None = None,
    target_input: TargetIdentityInput | None = None,
) -> list[SERPFinding]:
    """
    Generates deterministic mock findings for a given DorkQuery,
    interpolating target identity fields.
    """
    fixtures = load_serp_fixtures()
    by_category = fixtures.get("by_category", {})
    cat_key = dork.category.value if hasattr(dork.category, "value") else str(dork.category)
    templates = by_category.get(cat_key, [])

    # Target identity parameters for template interpolation
    name = target_name or (target_input.full_name if target_input else "Target Subject")
    name_slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    email = (
        target_input.primary_email
        if target_input and target_input.primary_email
        else f"{name_slug}@example.com"
    )
    phone = (
        target_input.phone_numbers[0]
        if target_input and target_input.phone_numbers
        else "(555) 019-2834"
    )
    username = (
        target_input.usernames[0]
        if target_input and target_input.usernames
        else f"{name_slug}_sec"
    )
    location = (
        f"{target_input.current_city}, {target_input.current_state}"
        if target_input and target_input.current_city
        else "Dallas, TX"
    )

    findings: list[SERPFinding] = []

    if templates:
        for idx, tpl in enumerate(templates):
            try:
                title = tpl["title"].format(
                    name=name,
                    name_slug=name_slug,
                    email=email,
                    phone=phone,
                    username=username,
                    location=location,
                )
            except Exception:
                title = tpl["title"]

            try:
                url = tpl["url"].format(
                    name=name,
                    name_slug=name_slug,
                    email=email,
                    phone=phone,
                    username=username,
                    location=location,
                )
            except Exception:
                url = tpl["url"]

            try:
                snippet = tpl["snippet"].format(
                    name=name,
                    name_slug=name_slug,
                    email=email,
                    phone=phone,
                    username=username,
                    location=location,
                )
            except Exception:
                snippet = tpl["snippet"]

            domain = tpl.get("domain", "example.com")
            risk_str = tpl.get("risk_level", "medium")
            risk = (
                PriorityLevel(risk_str)
                if risk_str in PriorityLevel._value2member_map_
                else PriorityLevel.MEDIUM
            )

            # Identify matched tokens
            matched = [
                t
                for t in [name, email, phone, location]
                if t and t.lower() in f"{title} {snippet}".lower()
            ]

            fid = f"fnd_{hashlib.sha256(f'{dork.dork_id}:{idx}:{url}'.encode()).hexdigest()[:8]}"

            findings.append(
                SERPFinding(
                    finding_id=fid,
                    dork_id=dork.dork_id,
                    title=title,
                    url=url,
                    snippet=snippet,
                    domain=domain,
                    risk_level=risk,
                    matched_pii_tokens=matched,
                    dork_category=dork.category,
                    provenance=ExecutionProvenance.CONTROLLED_FIXTURE,
                )
            )
    else:
        # Generic fallback finding if category has no pre-baked templates
        url = f"https://archive.org/details/{name_slug}_{cat_key}"
        title = f"Public Intelligence Record for {name} ({cat_key})"
        snippet = f"OSINT record referencing {name} in connection with query: {dork.raw_query}"
        findings.append(
            SERPFinding(
                finding_id=f"fnd_{hashlib.sha256(f'{dork.dork_id}:{url}'.encode()).hexdigest()[:8]}",
                dork_id=dork.dork_id,
                title=title,
                url=url,
                snippet=snippet,
                domain="archive.org",
                risk_level=PriorityLevel.MEDIUM,
                matched_pii_tokens=[name],
                dork_category=dork.category,
                provenance=ExecutionProvenance.CONTROLLED_FIXTURE,
            )
        )

    return findings


def load_broker_fixture(broker_id: str) -> str:
    """Loads raw HTML fixture for a broker ID."""
    norm = broker_id.lower().replace("-", "").replace("_", "")
    fpath = FIXTURES_DIR / f"{norm}.html"
    if fpath.exists():
        return fpath.read_text(encoding="utf-8")
    return (
        f"<!DOCTYPE html><html><body><h1>{{FULL_NAME}}</h1><p>{{KNOWN_ADDRESS}}</p>"
        f"<p>{{PHONE}}</p><p>{{PRIMARY_EMAIL}}</p><p>{{RELATIVE_1}}</p></body></html>"
    )


def render_broker_fixture(broker_id: str, identity: TargetIdentityInput) -> tuple[str, str]:
    """
    Renders the HTML fixture with interpolated identity fields.
    Returns (rendered_html, profile_url).
    """
    raw_html = load_broker_fixture(broker_id)

    name_parts = identity.full_name.split()
    first_name = name_parts[0] if name_parts else "John"
    last_name = name_parts[-1] if len(name_parts) > 1 else "Doe"
    city = identity.current_city or "Dallas"
    state = identity.current_state or "TX"
    phone = identity.phone_numbers[0] if identity.phone_numbers else "(214) 555-0192"
    email = identity.primary_email or f"{first_name.lower()}.{last_name.lower()}@example.com"
    address = (
        identity.known_addresses[0]
        if identity.known_addresses
        else f"1428 Elm Street, {city}, {state} 75201"
    )
    rel_1 = identity.relatives[0] if len(identity.relatives) > 0 else "Eleanor Brody"
    rel_2 = identity.relatives[1] if len(identity.relatives) > 1 else "Arthur Brody"

    rendered_html = (
        raw_html.replace("{{FULL_NAME}}", identity.full_name)
        .replace("{{FIRST_NAME}}", first_name)
        .replace("{{LAST_NAME}}", last_name)
        .replace("{{CURRENT_CITY}}", city)
        .replace("{{CURRENT_STATE}}", state)
        .replace("{{PHONE}}", phone)
        .replace("{{PRIMARY_EMAIL}}", email)
        .replace("{{KNOWN_ADDRESS}}", address)
        .replace("{{RELATIVE_1}}", rel_1)
        .replace("{{RELATIVE_2}}", rel_2)
    )

    name_slug = re.sub(r"[^a-z0-9]+", "-", identity.full_name.lower()).strip("-")
    profile_url = f"https://www.{broker_id}.com/find/person/{name_slug}"
    return rendered_html, profile_url
