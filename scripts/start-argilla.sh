#!/usr/bin/env bash
# Start local Argilla (Elasticsearch + quickstart) for feedback development.
#
# See docs/development.md and:
# https://github.com/RHEcosystemAppEng/morpheus-feedback-api#running-locally
#
# Usage:
#   ./scripts/start-argilla.sh
#   ./scripts/start-argilla.sh --logs

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly COMPOSE_FILE="${REPO_ROOT}/devservices/argilla/docker-compose.yaml"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required" >&2
  exit 1
fi

docker compose -f "${COMPOSE_FILE}" up -d

echo
echo "Argilla UI:  http://localhost:6900/sign-in"
echo "Login:       admin / 12345678"
echo "API key:     admin.apikey"
echo
echo "Next: start morpheus-feedback-api (see docs/development.md), then run quarkus:dev."

if [[ "${1:-}" == "--logs" ]]; then
  docker compose -f "${COMPOSE_FILE}" logs -f
fi
