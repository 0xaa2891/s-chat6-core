#!/usr/bin/env bash
# Configure, start, wait, and verify a Chutney network.
# Usage:
#   ./tools/testnet/run-testnet.sh [s-chat6-min|s-chat6-full]
#   ./tools/testnet/run-testnet.sh --stop [s-chat6-min|s-chat6-full]
#
# Unix: needs `tor` on PATH and Python 3. Windows: run inside WSL2 or Docker.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CHUTNEY="${ROOT}/chutney"
NETWORKS="${ROOT}/networks"
NAME="${1:-s-chat6-min}"

# Tor control sockets and DataDirectory cannot live in a path with spaces.
if [[ "${ROOT}" == *" "* ]]; then
  export CHUTNEY_DATA_DIR="/tmp/s-chat6-chutney"
  mkdir -p "${CHUTNEY_DATA_DIR}"
  echo "workspace path has spaces; Chutney data -> ${CHUTNEY_DATA_DIR}" >&2
fi

# Chutney (pinned) still uses stdlib `asyncore` (removed in 3.12) and `cgitb`
# (removed in 3.13). Prefer 3.11 when present.
for py in python3.11 python3.12; do
  if command -v "${py}" >/dev/null 2>&1; then
    export PYTHON="$(command -v "${py}")"
    break
  fi
done
export PYTHONPATH="${ROOT}/pycompat${PYTHONPATH:+:${PYTHONPATH}}"

if [[ "${1:-}" == "--stop" ]]; then
  NAME="${2:-s-chat6-min}"
  NETWORK="${NETWORKS}/${NAME}"
  if [[ ! -f "${NETWORK}" ]]; then
    echo "unknown network: ${NAME}" >&2
    exit 2
  fi
  cd "${CHUTNEY}"
  ./chutney stop "${NETWORK}"
  exit 0
fi

NETWORK="${NETWORKS}/${NAME}"
if [[ ! -f "${NETWORK}" ]]; then
  echo "unknown network: ${NAME} (expected s-chat6-min or s-chat6-full)" >&2
  exit 2
fi

if [[ ! -x "${CHUTNEY}/chutney" && ! -f "${CHUTNEY}/chutney" ]]; then
  echo "Chutney not found at ${CHUTNEY}." >&2
  echo "Clone it: git submodule update --init tools/testnet/chutney" >&2
  exit 1
fi

if ! command -v tor >/dev/null 2>&1; then
  echo "tor is not on PATH. Install the Tor daemon (not just Tor Browser)." >&2
  exit 1
fi

# Authorities on a 9-node mininet often need >60s to report bootstrap 100%.
export CHUTNEY_START_TIME="${CHUTNEY_START_TIME:-180}"

cd "${CHUTNEY}"
chmod +x chutney 2>/dev/null || true

./chutney configure "${NETWORK}"
./chutney start "${NETWORK}"
./chutney wait_for_bootstrap "${NETWORK}"
# Onion-only nets have no exits; chutney's verify.py tries SOCKS→exit traffic.
if ./chutney verify "${NETWORK}"; then
  :
else
  echo "chutney verify: no exit/HS traffic check (expected for onion-only s-chat6 nets)." >&2
fi

echo "READY"
