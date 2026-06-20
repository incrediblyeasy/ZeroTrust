#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

VENV="${REPO_ROOT}/.venv-test"
PY="${VENV}/bin/python"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 1; }

if [[ ! -x "${PY}" ]]; then
  echo "==> Creating test virtualenv at .venv-test"
  python3 -m venv "${VENV}"
  "${PY}" -m pip install --quiet --upgrade pip
  "${PY}" -m pip install --quiet -r tests/requirements.txt
fi

if [[ "${1:-}" == "--verify-logs-only" ]]; then
  exec "${PY}" scripts/verify_log_chain.py
fi

echo "==> Running adversarial pytest suite"
"${PY}" -m pytest tests/ -v -p no:cacheprovider "$@"

echo "==> Verifying audit log hash-chain integrity"
"${PY}" scripts/verify_log_chain.py
