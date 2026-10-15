#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

image_name="${UMBRA_VERIFY_IMAGE:-project-umbra:verify}"
image_platform="${UMBRA_VERIFY_PLATFORM:-linux/amd64}"
docker build --platform "$image_platform" -t "$image_name" .
docker run --platform "$image_platform" --rm --init -i --network none \
  -e PERSISTENCE_MODE=sqlite \
  -e SERP_MODE=mock \
  -e UMBRA_ACCESS_SECRET=container-smoke-only \
  -e UMBRA_OPERATOR_TOKEN=container-smoke-only \
  --entrypoint python "$image_name" - <<'PY'
import os
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from project_umbra.api.app import app

assert os.geteuid() != 0
with TestClient(app) as client:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["environment"] == "production"
    assert response.json()["storage_ready"] is True
    assert client.get("/").status_code == 200

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.set_content("<title>Umbra smoke</title>")
    assert page.title() == "Umbra smoke"
    browser.close()
print("Container verification passed.")
PY
