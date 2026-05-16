#!/bin/bash

set -eu

RESOLVER="@127.0.0.1"
PORT="-p 33053"
TOTAL=12

echo "========================================"
echo "Thundering herd test"
echo "========================================"
echo "total: $TOTAL"
echo ""

for i in $(seq 1 $TOTAL); do
  (
    dig $RESOLVER $PORT herd.internal.test A +tries=1 +time=5 +short > /dev/null
    echo "query $i finished"
  ) &
done

wait

echo ""
echo "========================================"
echo "Finished"
echo "========================================"