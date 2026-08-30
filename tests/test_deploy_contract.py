"""Static safety contract for the product-facing Cloud Run deploy script."""

from pathlib import Path
import re


SCRIPT = Path(__file__).resolve().parents[1] / "deploy_cloud_run.sh"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_deploy_refuses_dirty_tree_before_cloud_mutation() -> None:
    script = _script()
    dirty_check = script.index("git status --porcelain")
    first_cloud_mutation = script.index("gcloud services enable")

    assert dirty_check < first_cloud_mutation
    assert "working tree is dirty" in script


def test_deploy_commit_identity_is_head_not_override() -> None:
    script = _script()

    assert 'COMMIT_SHA="$(git rev-parse HEAD)"' in script
    assert 'COMMIT_SHA="${APP_COMMIT_SHA:-' not in script


def test_deploy_does_not_mutate_global_gcloud_project() -> None:
    assert "gcloud config set project" not in _script()


def test_deploy_requires_an_explicit_google_cloud_project() -> None:
    script = _script()

    assert 'PROJECT_ID="${1:-${GCP_PROJECT_ID:-}}"' in script
    assert 'if [[ -z "${PROJECT_ID}" ]]' in script
    assert 'GCP_PROJECT_ID:-project-' not in script


def test_deploy_verifies_correlated_runtime_evidence() -> None:
    script = _script()

    for required in (
        'payload["status"] == "ok"',
        'payload["storage_ready"] is True',
        'payload["persistence_backend"] == "firestore"',
        'payload["deployed_commit_sha"] == expected_commit',
        'payload["gemini_model"] == "gemini-3.7-flash"',
        'payload["cloud_run_revision"] == expected_revision',
        'payload["external_action_policy"] == "plan_only_no_dispatch"',
    ):
        assert required in script


def test_public_deploy_is_explicitly_controlled_demo_mode() -> None:
    script = _script()

    assert "PUBLIC_DEMO_MODE=true" in script
    assert "PLAYWRIGHT_SIMULATION_MODE=true" in script
    assert "SERP_MODE=mock" in script
    assert "PII_CLASSIFIER_MODE=heuristic" in script


def test_deploy_provisions_stable_access_secrets_without_printing_values() -> None:
    script = _script()

    assert "UMBRA_ACCESS_SECRET=" in script
    assert "UMBRA_OPERATOR_TOKEN=" in script
    assert "project-umbra-access-secret" in script
    assert "project-umbra-operator-token" in script
    assert "gcloud secrets versions access" not in script


def test_generated_access_secrets_are_written_without_trailing_newlines() -> None:
    script = _script()

    assert 'GENERATED_SECRET_VALUE="$(openssl rand -hex 48)"' in script
    assert "openssl rand -base64 48 | gcloud secrets create" not in script
    assert re.search(
        r"printf '%s' \"\$\{GENERATED_SECRET_VALUE\}\" \| gcloud secrets create \"\$\{generated_secret\}\"[\s\S]+?--quiet >/dev/null 2>&1",
        script,
    )
    assert "unset GENERATED_SECRET_VALUE" in script


def test_gemini_key_is_service_account_bound_and_api_restricted() -> None:
    script = _script()

    assert "apikeys.googleapis.com" in script
    assert "generativelanguage.googleapis.com" in script
    assert '--service-account="${RUNTIME_SERVICE_ACCOUNT}"' in script
    assert '--api-target=service=generativelanguage.googleapis.com' in script
    assert "gcloud services api-keys get-key-string" in script
    assert 'unset GEMINI_KEY_STRING' in script


def test_gemini_key_material_is_never_emitted_by_provisioning_commands() -> None:
    script = _script()
    create_block = script[
        script.index("gcloud services api-keys create") : script.index("GEMINI_KEY_STRING=")
    ]
    get_and_store_block = script[
        script.index("GEMINI_KEY_STRING=") : script.index("unset GEMINI_KEY_STRING")
    ]

    assert "--quiet >/dev/null 2>&1" in create_block
    assert "--format='value(keyString)' 2>/dev/null" in get_and_store_block
    assert "--quiet >/dev/null 2>&1" in get_and_store_block
    assert 'echo "${GEMINI_KEY_STRING}"' not in script
    assert "set -x" not in script


def test_required_firestore_indexes_are_deployed() -> None:
    script = _script()

    assert 'firestore.indexes.json' in script
    assert 'create_firestore_index "receipts" "mission_id" "ascending" "submission_timestamp" "descending"' in script
    assert 'create_firestore_index "telemetry" "scan_id" "ascending" "timestamp" "ascending"' in script
