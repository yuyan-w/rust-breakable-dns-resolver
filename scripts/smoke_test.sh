#!/bin/bash

set -eu

RESOLVER="@127.0.0.1"
PORT="-p 33053"

echo ""
echo "========================================"
echo "A record"
echo "========================================"

dig $RESOLVER $PORT internal.test A +short

echo ""
echo "========================================"
echo "AAAA (NODATA)"
echo "========================================"

dig $RESOLVER $PORT internal.test AAAA

echo ""
echo "========================================"
echo "NXDOMAIN"
echo "========================================"

dig $RESOLVER $PORT unknown.internal.test A

echo ""
echo "========================================"
echo "Delegation"
echo "========================================"

dig $RESOLVER $PORT api.dev.internal.test A +short

echo ""
echo "========================================"
echo "CNAME"
echo "========================================"

dig $RESOLVER $PORT www.internal.test A

echo ""
echo "========================================"
echo "CNAME LOOP"
echo "========================================"

dig $RESOLVER $PORT a.internal.test A

echo ""
echo "========================================"
echo "Cache Test"
echo "========================================"

time dig $RESOLVER $PORT internal.test A +short > /dev/null
time dig $RESOLVER $PORT internal.test A +short > /dev/null

echo ""
echo "========================================"
echo "Done"
echo "========================================"