#!/usr/bin/env bash
# Run morpheus-feedback-api locally against the Argilla instance from start-argilla.sh.
#
# Clones https://github.com/RHEcosystemAppEng/morpheus-feedback-api on first run.
# Defaults match app/config.py and this repo's dev profile.
#
# Usage:
#   ./scripts/start-feedback-api.sh
#
# Optional env:
#   FEEDBACK_API_DIR   checkout location (default: ../morpheus-feedback-api)
#   ARGILLA_API_URL    default http://localhost:6900
#   ARGILLA_API_KEY    default admin.apikey
#   ARGILLA_DATASET    default feedback-ai
#   ARGILLA_WORKSPACE  default admin

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly FEEDBACK_API_DIR="${FEEDBACK_API_DIR:-${REPO_ROOT}/../morpheus-feedback-api}"
readonly FEEDBACK_API_REPO="https://github.com/RHEcosystemAppEng/morpheus-feedback-api.git"

export ARGILLA_API_URL="${ARGILLA_API_URL:-http://localhost:6900}"
export ARGILLA_API_KEY="${ARGILLA_API_KEY:-admin.apikey}"
export ARGILLA_DATASET="${ARGILLA_DATASET:-feedback-ai}"
export ARGILLA_WORKSPACE="${ARGILLA_WORKSPACE:-admin}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 1
fi

if [[ ! -d "${FEEDBACK_API_DIR}/.git" ]]; then
  echo "Cloning morpheus-feedback-api into ${FEEDBACK_API_DIR}..."
  git clone "${FEEDBACK_API_REPO}" "${FEEDBACK_API_DIR}"
fi

cd "${FEEDBACK_API_DIR}"

if [[ ! -d venv ]]; then
  python3 -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate
pip install -q -r requirements.txt

echo
echo "Feedback API: http://localhost:5001"
echo "Argilla:      ${ARGILLA_API_URL} (workspace=${ARGILLA_WORKSPACE}, dataset=${ARGILLA_DATASET})"
echo "ExploitIQ:    quarkus.rest-client.feedback-api.url=http://localhost:5001 (%dev)"
echo

python run.py
