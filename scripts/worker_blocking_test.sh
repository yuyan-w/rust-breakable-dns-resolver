#!/usr/bin/env bash
set -euo pipefail

SERVER="${SERVER:-127.0.0.1}"
PORT="${PORT:-33053}"
TOTAL="${TOTAL:-12}"
PARALLEL="${PARALLEL:-12}"

echo "========================================"
echo "Worker blocking test"
echo "========================================"
echo "server:   ${SERVER}"
echo "port:     ${PORT}"
echo "total:    ${TOTAL}"
echo "parallel: ${PARALLEL}"
echo

start=$(date +%s)

seq 1 "${TOTAL}" | xargs -n1 -P"${PARALLEL}" -I{} sh -c '
  name="blocking-{}.internal.test"

  started_at=$(date +%s)

  dig @"$0" -p "$1" "$name" A +short >/dev/null

  finished_at=$(date +%s)
  elapsed=$((finished_at - started_at))

  echo "query {} finished in ${elapsed}s"
' "${SERVER}" "${PORT}"

end=$(date +%s)
elapsed=$((end - start))

echo
echo "========================================"
echo "Finished"
echo "========================================"
echo "total elapsed: ${elapsed}s"