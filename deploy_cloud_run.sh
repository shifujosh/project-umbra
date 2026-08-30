#!/usr/bin/env bash
# ==============================================================================
# Project Umbra — Google Cloud Run deployment with verifiable runtime provenance
# Usage: bash deploy_cloud_run.sh [PROJECT_ID] [REGION]
#
# Required before first deploy:
#   1. Authenticate gcloud (`gcloud auth login`).
#   2. If Firestore's default database does not exist, set FIRESTORE_LOCATION.
#
# The script provisions a service-account-bound, API-restricted Gemini key when
# needed and never prints it or places it in Cloud Run plaintext env flags.
# ==============================================================================
set -euo pipefail

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "ERROR: working tree is dirty. Commit every source change before deploying." >&2
  git status --short >&2
  exit 1
fi

PROJECT_ID="${1:-${GCP_PROJECT_ID:-}}"
REGION="${2:-${DEPLOY_REGION:-us-central1}}"
SERVICE_NAME="${SERVICE_NAME:-project-umbra}"
ARTIFACT_REPOSITORY="${ARTIFACT_REPOSITORY:-project-umbra}"
GEMINI_SECRET_NAME="${GEMINI_SECRET_NAME:-project-umbra-gemini-key}"
GEMINI_API_KEY_ID="${GEMINI_API_KEY_ID:-project-umbra-gemini-auth}"
ACCESS_SECRET_NAME="${ACCESS_SECRET_NAME:-project-umbra-access-secret}"
OPERATOR_TOKEN_SECRET_NAME="${OPERATOR_TOKEN_SECRET_NAME:-project-umbra-operator-token}"
RUNTIME_SERVICE_ACCOUNT_NAME="${RUNTIME_SERVICE_ACCOUNT_NAME:-project-umbra-runtime}"
RUNTIME_SERVICE_ACCOUNT="${RUNTIME_SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
FIRESTORE_DATABASE="${FIRESTORE_DATABASE:-(default)}"
COMMIT_SHA="$(git rev-parse HEAD)"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REPOSITORY}/${SERVICE_NAME}:${COMMIT_SHA}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "ERROR: pass a Google Cloud project ID or set GCP_PROJECT_ID." >&2
  exit 1
fi

if ! command -v gcloud >/dev/null 2>&1; then
  echo "ERROR: gcloud is not installed. Install the Google Cloud CLI, then retry." >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required to create access secrets safely." >&2
  exit 1
fi

ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n 1)"
if [[ -z "${ACTIVE_ACCOUNT}" ]]; then
  echo "ERROR: no active gcloud account. Run: gcloud auth login" >&2
  exit 1
fi

echo "Project Umbra Cloud Run deployment"
echo "  account: ${ACTIVE_ACCOUNT}"
echo "  project: ${PROJECT_ID}"
echo "  region:  ${REGION}"
echo "  commit:  ${COMMIT_SHA}"
echo "  image:   ${IMAGE}"

echo "Enabling required Google Cloud APIs..."
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  firestore.googleapis.com \
  secretmanager.googleapis.com \
  logging.googleapis.com \
  apikeys.googleapis.com \
  generativelanguage.googleapis.com \
  iam.googleapis.com \
  --project="${PROJECT_ID}" \
  --quiet

if ! gcloud artifacts repositories describe "${ARTIFACT_REPOSITORY}" \
  --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Creating Artifact Registry repository ${ARTIFACT_REPOSITORY}..."
  gcloud artifacts repositories create "${ARTIFACT_REPOSITORY}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="Project Umbra Cloud Run images" \
    --project="${PROJECT_ID}" \
    --quiet
fi

if ! gcloud firestore databases describe \
  --database="${FIRESTORE_DATABASE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  if [[ -z "${FIRESTORE_LOCATION:-}" ]]; then
    echo "ERROR: Firestore database ${FIRESTORE_DATABASE} does not exist." >&2
    echo "Set FIRESTORE_LOCATION to the intended permanent data location, then retry." >&2
    exit 1
  fi
  echo "Creating Firestore database ${FIRESTORE_DATABASE} in ${FIRESTORE_LOCATION}..."
  gcloud firestore databases create \
    --database="${FIRESTORE_DATABASE}" \
    --location="${FIRESTORE_LOCATION}" \
    --type=firestore-native \
    --project="${PROJECT_ID}" \
    --quiet
fi

if [[ ! -f "firestore.indexes.json" ]]; then
  echo "ERROR: firestore.indexes.json is required for the persisted query contract." >&2
  exit 1
fi

create_firestore_index() {
  local collection_group="$1"
  local first_field="$2"
  local first_order="$3"
  local second_field="$4"
  local second_order="$5"
  local index_output
  if ! index_output="$(gcloud firestore indexes composite create \
    --database="${FIRESTORE_DATABASE}" \
    --collection-group="${collection_group}" \
    --query-scope=collection \
    --field-config="field-path=${first_field},order=${first_order}" \
    --field-config="field-path=${second_field},order=${second_order}" \
    --project="${PROJECT_ID}" \
    --quiet 2>&1)"; then
    case "${index_output}" in
      *"already exists"*|*"Already exists"*|*"ALREADY_EXISTS"*) ;;
      *)
        echo "ERROR: Firestore index creation failed for ${collection_group}: ${index_output}" >&2
        exit 1
        ;;
    esac
  fi
}

echo "Ensuring Firestore indexes from firestore.indexes.json..."
create_firestore_index "receipts" "mission_id" "ascending" "submission_timestamp" "descending"
create_firestore_index "telemetry" "scan_id" "ascending" "timestamp" "ascending"

if ! gcloud iam service-accounts describe "${RUNTIME_SERVICE_ACCOUNT}" \
  --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Creating dedicated Cloud Run service account..."
  gcloud iam service-accounts create "${RUNTIME_SERVICE_ACCOUNT_NAME}" \
    --display-name="Project Umbra runtime" \
    --project="${PROJECT_ID}" \
    --quiet
fi

for role in roles/datastore.user roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${RUNTIME_SERVICE_ACCOUNT}" \
    --role="${role}" \
    --condition=None \
    --quiet >/dev/null
done

if ! gcloud secrets describe "${GEMINI_SECRET_NAME}" \
  --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Provisioning service-account-bound Gemini authorization key..."
  if ! gcloud services api-keys describe "${GEMINI_API_KEY_ID}" \
    --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud services api-keys create \
      --key-id="${GEMINI_API_KEY_ID}" \
      --display-name="Project Umbra Gemini runtime" \
      --service-account="${RUNTIME_SERVICE_ACCOUNT}" \
      --api-target=service=generativelanguage.googleapis.com \
      --project="${PROJECT_ID}" \
      --quiet >/dev/null 2>&1
  fi
  GEMINI_KEY_STRING="$(gcloud services api-keys get-key-string "${GEMINI_API_KEY_ID}" \
    --project="${PROJECT_ID}" \
    --format='value(keyString)' 2>/dev/null)"
  if [[ -z "${GEMINI_KEY_STRING}" ]]; then
    echo "ERROR: Google Cloud returned an empty Gemini API key string." >&2
    exit 1
  fi
  printf '%s' "${GEMINI_KEY_STRING}" | gcloud secrets create "${GEMINI_SECRET_NAME}" \
    --data-file=- \
    --replication-policy=automatic \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null 2>&1
  unset GEMINI_KEY_STRING
fi

for generated_secret in "${ACCESS_SECRET_NAME}" "${OPERATOR_TOKEN_SECRET_NAME}"; do
  if ! gcloud secrets describe "${generated_secret}" \
    --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "Creating generated Secret Manager secret ${generated_secret}..."
    GENERATED_SECRET_VALUE="$(openssl rand -hex 48)"
    if [[ -z "${GENERATED_SECRET_VALUE}" ]]; then
      echo "ERROR: secure secret generation returned an empty value." >&2
      exit 1
    fi
    printf '%s' "${GENERATED_SECRET_VALUE}" | gcloud secrets create "${generated_secret}" \
      --data-file=- \
      --replication-policy=automatic \
      --project="${PROJECT_ID}" \
      --quiet >/dev/null 2>&1
    unset GENERATED_SECRET_VALUE
  fi
done

for runtime_secret in "${GEMINI_SECRET_NAME}" "${ACCESS_SECRET_NAME}" "${OPERATOR_TOKEN_SECRET_NAME}"; do
  gcloud secrets add-iam-policy-binding "${runtime_secret}" \
    --member="serviceAccount:${RUNTIME_SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
done

echo "Building immutable image with Cloud Build..."
gcloud builds submit \
  --tag="${IMAGE}" \
  --project="${PROJECT_ID}" \
  --timeout=900s \
  .

echo "Deploying ${SERVICE_NAME} to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --image="${IMAGE}" \
  --platform=managed \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --service-account="${RUNTIME_SERVICE_ACCOUNT}" \
  --allow-unauthenticated \
  --port=8080 \
  --cpu=2 \
  --memory=2Gi \
  --min-instances=0 \
  --max-instances=3 \
  --timeout=300 \
  --set-env-vars="ENVIRONMENT=production,PUBLIC_DEMO_MODE=true,APP_COMMIT_SHA=${COMMIT_SHA},GEMINI_MODEL=gemini-3.7-flash,PLAYWRIGHT_HEADLESS=true,PLAYWRIGHT_SIMULATION_MODE=true,SERP_MODE=mock,PII_CLASSIFIER_MODE=heuristic,PERSISTENCE_MODE=firestore,GCP_PROJECT_ID=${PROJECT_ID},FIRESTORE_DATABASE=${FIRESTORE_DATABASE},LOG_LEVEL=INFO" \
  --set-secrets="GEMINI_API_KEY=${GEMINI_SECRET_NAME}:latest,UMBRA_ACCESS_SECRET=${ACCESS_SECRET_NAME}:latest,UMBRA_OPERATOR_TOKEN=${OPERATOR_TOKEN_SECRET_NAME}:latest" \
  --quiet

SERVICE_URL="$(gcloud run services describe "${SERVICE_NAME}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --format='value(status.url)')"
EXPECTED_REVISION="$(gcloud run services describe "${SERVICE_NAME}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --format='value(status.latestReadyRevisionName)')"

echo "Verifying deployed health endpoint..."
HEALTH_JSON="$(curl --fail --show-error --silent "${SERVICE_URL}/api/v1/health")"
python3 - "${COMMIT_SHA}" "${EXPECTED_REVISION}" "${HEALTH_JSON}" <<'PY'
import json
import sys

expected_commit, expected_revision, raw_payload = sys.argv[1:]
payload = json.loads(raw_payload)
checks = {
    "status": payload["status"] == "ok",
    "storage_ready": payload["storage_ready"] is True,
    "persistence_backend": payload["persistence_backend"] == "firestore",
    "deployed_commit_sha": payload["deployed_commit_sha"] == expected_commit,
    "gemini_model": payload["gemini_model"] == "gemini-3.7-flash",
    "cloud_run_revision": payload["cloud_run_revision"] == expected_revision,
    "external_action_policy": payload["external_action_policy"] == "plan_only_no_dispatch",
}
failed = [name for name, passed in checks.items() if not passed]
if failed:
    raise SystemExit(f"Deployment evidence check failed: {', '.join(failed)}; payload={payload}")
print(json.dumps(payload, indent=2, sort_keys=True))
PY
echo
echo "Deployment complete"
echo "  service: ${SERVICE_URL}"
echo "  health:  ${SERVICE_URL}/api/v1/health"
echo "  docs:    ${SERVICE_URL}/docs"
echo "  commit:  ${COMMIT_SHA}"
