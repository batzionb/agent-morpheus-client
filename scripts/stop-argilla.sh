#!/usr/bin/env bash
# Stop local Argilla containers (preserves data volumes).
#
# Usage: ./scripts/stop-argilla.sh

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly COMPOSE_FILE="${REPO_ROOT}/devservices/argilla/docker-compose.yaml"

docker compose -f "${COMPOSE_FILE}" stop

echo "Argilla stopped. Run ./scripts/start-argilla.sh to start again."
