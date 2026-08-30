"""Product-scope contracts for Project Umbra's scripted demonstration and copy."""

from pathlib import Path

from project_umbra.api.demo import AVERY_ACTION_PACKAGES, AVERY_CASE_LOCATIONS, DEMO_SCRIPT


def test_demo_stops_at_prepared_remediation_plan() -> None:
    narrative = " ".join(message for _, _, message, _ in DEMO_SCRIPT).lower()

    assert "remediation plan" in narrative
    assert "ready for approval" in narrative
    assert "request dispatched" not in narrative.replace("no request dispatched", "")
    assert "request submitted" not in narrative
    assert "eradicated" not in narrative
    assert "neutralized" not in narrative


def test_demo_records_are_prepared_not_sent() -> None:
    assert AVERY_ACTION_PACKAGES
    assert {record["status"] for record in AVERY_ACTION_PACKAGES} == {"PREPARED"}
    assert all(record["external_action_dispatched"] is False for record in AVERY_ACTION_PACKAGES)
    assert {record["provenance"] for record in AVERY_ACTION_PACKAGES} == {"controlled_fixture"}


def test_demo_ui_keeps_only_user_facing_status() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert "PROVENANCE TRACE" not in html
    assert "GRAPH LATENCY" not in html
    assert "EVENT TELEMETRY" not in html
    assert '<aside class="report-index"' not in html
    assert html.count('class="mission-stage"') == 4
    assert all(label in html for label in ("DISCOVER", "CONNECT", "ASSESS", "PLAN"))


def test_component_titles_share_the_window_header_system() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert '<span class="window-title">TARGET DOSSIER</span>' in html
    assert '<span class="window-title">GLOBAL SWEEP</span>' in html
    assert '<span class="window-title">EVIDENCE SUMMARY</span>' in html
    assert '<div class="window-header telemetry-stream-header">' in html
    assert '<span class="window-title">UMBRA ACTIVITY</span>' in html
    assert 'style="color:var(--cyan)">GLOBAL SWEEP' not in html


def test_desktop_activity_boundary_tracks_global_sweep_split() -> None:
    html = Path("project_umbra/static/index.html").read_text()
    compact_css = " ".join(html.split())

    assert "@media (min-width:1121px)" in compact_css
    assert "grid-template-rows:48px calc(62% - 46px) 48px minmax(0,1fr);" in compact_css


def test_graph_cards_fit_visible_copy_without_losing_full_labels() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert "function fitSvgText" in html
    assert 'clipPath.setAttribute("clipPathUnits", "userSpaceOnUse")' in html
    assert 'node.setAttribute("aria-label", `Inspect ${accessibleName}`)' in html
    assert "avery@helio.example" in html
    assert "avery.mercer@relay.example" in html


def test_header_uses_compact_navigation_and_quiet_report_ready_state() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert "Application header: quiet brand frame with a compact view switcher" in html
    assert '.report-tab.ready:not(.active)::before' in html
    assert 'reportTab?.classList.add("ready")' in html
    assert '.style.boxShadow = "0 0 12px var(--green)"' not in html


def test_risk_report_separates_current_risk_from_action_coverage() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert "CURRENT EXPOSURE &amp; ACTION COVERAGE" in html
    assert "Exposure index · higher means more public identity exposure" in html
    assert "Current exposure" in html
    assert "Five mapped brokers" in html
    assert "5 / 5" in html
    assert "does not claim removal or risk reduction" in html
    assert "No external requests have been submitted." in html
    assert "95%" not in html
    assert '<strong class="exposure-value">0.05</strong>' not in html
    assert "Sparkline Curve" not in html
    assert "Histogram bars" not in html


def test_root_node_uses_wrapped_copy_without_duplicate_metrics() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert "function renderGraphRootTitle" in html
    assert 'fitSvgText(tspan, line, 104)' in html
    assert '#g-root-node .card-meta-text { display:none; }' in html
    assert 'setGraphRootCopy(document.getElementById("f-name").value || "Target", "PLAN READY", "");' in html
    assert 'd="M 480 362 L 480 435"' in html


def test_demo_launches_through_a_three_step_deployment_wizard() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert 'id="deployment-wizard"' in html
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    assert 'class="deployment-wizard open"' in html
    assert 'aria-hidden="false"' in html
    assert html.count('<section class="wizard-panel') == 3
    assert 'onclick="openDeploymentWizard()"' in html
    assert "function simulateWizardIntake" in html
    assert "function advanceDeploymentWizard" in html
    assert "function deployUmbraAgent" in html
    assert 'document.documentElement.classList.add("wizard-open")' in html
    assert 'document.documentElement.classList.remove("wizard-open")' in html


def test_default_view_is_blank_onboarding_until_configuration_begins() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert '<html lang="en" data-theme="dark" class="wizard-open">' in html
    assert '<body class="wizard-open">' in html
    assert 'id="wizard-configure-agent" type="button" onclick="beginWizardIntake()"' in html
    assert '<span id="wizard-configure-label">CONFIGURE UMBRA AGENT</span>' in html
    assert "No synthetic target profile loaded." in html
    assert 'id="f-name" type="hidden" value=""' in html
    assert 'id="f-email" type="hidden" value=""' in html
    assert 'id="dossier-target-name">NO TARGET LOADED' in html
    assert 'id="globe-sweep-prefix">Awaiting configured target' in html


def test_wizard_stages_and_hands_off_the_full_identity_profile() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    for field_id in ("wizard-phone", "wizard-aliases", "wizard-socials"):
        assert f'id="{field_id}"' in html
        assert f'await typeWizardField("{field_id}"' in html

    intake_order = ("wizard-phone", "wizard-city", "wizard-jurisdiction", "wizard-aliases", "wizard-socials")
    call_positions = [html.index(f'await typeWizardField("{field_id}"') for field_id in intake_order]
    assert call_positions == sorted(call_positions)

    assert 'id="f-phone" type="hidden"' in html
    assert 'id="f-socials" type="hidden"' in html
    assert 'document.getElementById("f-phone").value = document.getElementById("wizard-phone").value;' in html
    assert 'document.getElementById("f-aliases").value = document.getElementById("wizard-aliases").value;' in html
    assert 'document.getElementById("f-socials").value = document.getElementById("wizard-socials").value;' in html
    assert "phone_numbers: phoneNumbers" in html
    assert "usernames," in html


def test_wizard_keeps_deployment_scope_explicit_and_hands_off_to_demo() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert "DEPLOY UMBRA INVESTIGATION AGENT" in html
    assert "Prepare remediation plan" in html
    assert "No external requests are submitted" in html
    assert "controlled synthetic replay" in html.lower()
    assert "Authorized live missions use <code>/api/v1/scan</code>" in html
    assert "mission data remains capability-scoped" in html
    assert "runDemo();" in html
    assert 'document.addEventListener("keydown", handleDeploymentWizardKeydown)' in html
    assert 'on ? label : "CONFIGURE UMBRA AGENT"' in html


def test_evidence_summary_starts_empty_until_the_agent_runs() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert '<span id="insp-title">No evidence yet</span>' in html
    assert "Deploy Umbra to begin collecting and correlating public evidence." in html
    assert "function renderInspectorIdleState" in html
    assert "function renderInspectorRunState" in html
    assert "Evidence will appear as Umbra connects it to the subject." in html
    assert "if (!isRunning && stepCount === 0 && !findings.length && !receipts.length)" in html


def test_demo_automatically_inspects_representative_revealed_nodes() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert "function automateNodeInspection(key)" in html
    assert 'selected.dispatchEvent(new MouseEvent("click", { bubbles:true, detail:1 }));' in html
    assert "Click any revealed node to inspect its evidence." in html
    assert "automatedInspectionKeys.clear();" in html
    assert ".node-item-g.auto-inspecting rect" in html
    assert ".signal-inspector-body.auto-updated" in html

    handler = html[html.index("function handleEvent"):]
    phase_keys = ("dork-0", "broker-tps", "pii-0", "rem-0")
    positions = [handler.index(f'automateNodeInspection("{key}")') for key in phase_keys]
    assert positions == sorted(positions)


def test_target_dossier_shows_profile_inputs_without_a_case_number() -> None:
    html = Path("project_umbra/static/index.html").read_text()

    assert all(label in html for label in ("ALIASES", "EMAILS", "PHONE", "SOCIAL HANDLES", "LOCATION"))
    assert "Avery J. Mercer" in html
    assert "avery.mercer@relay.example" in html
    assert "+1 (202) 555-0142" in html
    assert "@averymercer" in html
    assert "UM-0040" not in html
    assert "<span>CASE</span>" not in html


def test_demo_uses_a_consistent_rights_cleared_synthetic_identity_profile() -> None:
    html = Path("project_umbra/static/index.html").read_text()
    demo = Path("project_umbra/api/demo.py").read_text()
    rendered_demo = f"{html}\n{demo}"

    assert "Avery Mercer" in html
    assert "Avery J. Mercer" in html
    assert "Helio Civic Lab" in html
    assert "avery@helio.example" in rendered_demo
    assert "avery.mercer@relay.example" in rendered_demo
    assert "+1 (202) 555-0142" in rendered_demo
    assert "Oakland" in rendered_demo
    assert "California" in rendered_demo
    assert "@averymercer" in html
    assert "controlled synthetic" in rendered_demo.lower()
    for protected_character in ("Scoobert", "Scooby", "Shaggy Rogers", "Mystery Incorporated", "Moriarty"):
        assert protected_character.lower() not in rendered_demo.lower()


def test_avery_profile_uses_the_six_synthetic_case_locations() -> None:
    html = Path("project_umbra/static/index.html").read_text()
    demo = Path("project_umbra/api/demo.py").read_text()
    rendered_demo = f"{html}\n{demo}"
    locations = tuple(AVERY_CASE_LOCATIONS)

    assert all(location in rendered_demo for location in locations)
    assert html.count("case_location:") == len(locations)


def test_generated_umbra_mark_is_used_by_the_header_and_favicon() -> None:
    html = Path("project_umbra/static/index.html").read_text()
    header_mark = Path("project_umbra/static/assets/umbra-mark.png")
    favicon = Path("project_umbra/static/assets/favicon-32.png")

    assert 'src="/static/assets/umbra-mark.png?v=umbra-950d2ef2"' in html
    assert 'href="/static/assets/favicon-32.png?v=umbra-acd060a3"' in html
    assert 'rel="shortcut icon"' in html
    assert "phantom-2" not in html
    assert header_mark.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert favicon.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
