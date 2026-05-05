#!/usr/bin/env bash

HOST=127.0.0.1
PORT=33053
DOMAIN=internal.test
TOTAL=100
PARALLEL=16

echo "Start test: TOTAL=$TOTAL, PARALLEL=$PARALLEL"

start_time=$(date +%s)

seq "$TOTAL" | xargs -n1 -P"$PARALLEL" -I{} \
  dig @"$HOST" -p "$PORT" "$DOMAIN" A +short +tries=1 +time=10 > /dev/null

end_time=$(date +%s)

echo "Finished"
echo "Total time: $((end_time - start_time)) sec"