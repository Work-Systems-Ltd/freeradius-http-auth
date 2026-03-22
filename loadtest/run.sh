#!/bin/bash
#
# High-throughput RADIUS load test using radclient -c -p
# Sends auth + acct traffic directly to FreeRADIUS instances
#
set -euo pipefail

# Config via environment
TARGETS="${RADIUS_TARGETS:-freeradius-1,freeradius-2,freeradius-3,freeradius-4}"
SECRET="${RADIUS_SECRET:-testing123}"
TARGET_RPS="${TARGET_RPS:-5000}"
DURATION="${DURATION:-30}"
AUTH_RATIO="${AUTH_RATIO:-70}"    # percent of traffic that is auth

PACKETS_DIR="/etc/radperf/packets"

IFS=',' read -ra HOSTS <<< "$TARGETS"
NUM_HOSTS=${#HOSTS[@]}

# Calculate per-host counts
AUTH_RPS=$(( TARGET_RPS * AUTH_RATIO / 100 ))
ACCT_RPS=$(( TARGET_RPS - AUTH_RPS ))

AUTH_RPS_PER_HOST=$(( AUTH_RPS / NUM_HOSTS ))
ACCT_RPS_PER_HOST=$(( ACCT_RPS / NUM_HOSTS ))

AUTH_COUNT=$(( AUTH_RPS_PER_HOST * DURATION ))
ACCT_COUNT=$(( ACCT_RPS_PER_HOST * DURATION ))

# Parallelism: target_rps * avg_latency. Assume ~2ms for bypass, ~20ms with REST.
# Use aggressive parallelism — radclient handles it well.
AUTH_PAR=$(( AUTH_RPS_PER_HOST / 5 ))
ACCT_PAR=$(( ACCT_RPS_PER_HOST / 5 ))
AUTH_PAR=$(( AUTH_PAR < 10 ? 10 : AUTH_PAR ))
ACCT_PAR=$(( ACCT_PAR < 5 ? 5 : ACCT_PAR ))
AUTH_PAR=$(( AUTH_PAR > 500 ? 500 : AUTH_PAR ))
ACCT_PAR=$(( ACCT_PAR > 500 ? 500 : ACCT_PAR ))

echo "=========================================="
echo " RADIUS Load Test"
echo "=========================================="
echo " Targets:    ${HOSTS[*]}"
echo " Target RPS: ${TARGET_RPS} (auth=${AUTH_RPS} acct=${ACCT_RPS})"
echo " Duration:   ${DURATION}s"
echo " Per host:   auth=${AUTH_RPS_PER_HOST}/s acct=${ACCT_RPS_PER_HOST}/s"
echo " Packets:    auth=${AUTH_COUNT} acct=${ACCT_COUNT} per host"
echo " Parallel:   auth=${AUTH_PAR} acct=${ACCT_PAR}"
echo "=========================================="

# Wait for targets to be resolvable
echo "Waiting for targets..."
for host in "${HOSTS[@]}"; do
    host=$(echo "$host" | tr -d ' ')
    for i in $(seq 1 30); do
        if getent hosts "$host" > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
done
echo "All targets resolved."

# Resolve hostnames to IPs once
declare -A HOST_IPS
for host in "${HOSTS[@]}"; do
    host=$(echo "$host" | tr -d ' ')
    HOST_IPS[$host]=$(getent hosts "$host" | awk '{print $1}')
done

PIDS=()
TMPDIR=$(mktemp -d)
T0=$(date +%s%N)

# Launch radclient processes — one auth + one acct per host
for host in "${HOSTS[@]}"; do
    host=$(echo "$host" | tr -d ' ')
    ip=${HOST_IPS[$host]}

    # Auth
    radclient -c "$AUTH_COUNT" -p "$AUTH_PAR" \
        -r 1 -t 2 \
        -f "$PACKETS_DIR/auth.txt" \
        "${ip}:1812" auth "$SECRET" \
        > "$TMPDIR/${host}_auth.out" 2>&1 &
    PIDS+=($!)

    # Acct (mix: 50% start, 33% interim, 17% stop — use start for simplicity at scale)
    radclient -c "$ACCT_COUNT" -p "$ACCT_PAR" \
        -r 1 -t 2 \
        -f "$PACKETS_DIR/acct_start.txt" \
        "${ip}:1813" acct "$SECRET" \
        > "$TMPDIR/${host}_acct.out" 2>&1 &
    PIDS+=($!)
done

echo "Launched ${#PIDS[@]} radclient processes. Waiting..."

# Wait for all to finish
FAILURES=0
for pid in "${PIDS[@]}"; do
    if ! wait "$pid"; then
        FAILURES=$((FAILURES + 1))
    fi
done

T1=$(date +%s%N)
ELAPSED_MS=$(( (T1 - T0) / 1000000 ))
ELAPSED_S=$(( ELAPSED_MS / 1000 ))
ELAPSED_S=${ELAPSED_S:-1}

echo ""
echo "=========================================="
echo " Results (${ELAPSED_MS}ms elapsed)"
echo "=========================================="

TOTAL_SENT=0
TOTAL_ACCEPT=0
TOTAL_REJECT=0
TOTAL_ACCT_RESP=0
TOTAL_LOST=0

for host in "${HOSTS[@]}"; do
    host=$(echo "$host" | tr -d ' ')
    for type in auth acct; do
        f="$TMPDIR/${host}_${type}.out"
        if [ -f "$f" ]; then
            sent=$(grep -c "^Sent " "$f" 2>/dev/null || echo 0)
            accept=$(grep -c "Received Access-Accept" "$f" 2>/dev/null || echo 0)
            reject=$(grep -c "Received Access-Reject" "$f" 2>/dev/null || echo 0)
            acct_resp=$(grep -c "Received Accounting-Response" "$f" 2>/dev/null || echo 0)
            recv=$((accept + reject + acct_resp))
            lost=$((sent - recv))
            lost=$((lost < 0 ? 0 : lost))

            TOTAL_SENT=$((TOTAL_SENT + sent))
            TOTAL_ACCEPT=$((TOTAL_ACCEPT + accept))
            TOTAL_REJECT=$((TOTAL_REJECT + reject))
            TOTAL_ACCT_RESP=$((TOTAL_ACCT_RESP + acct_resp))
            TOTAL_LOST=$((TOTAL_LOST + lost))

            printf "  %-15s %-5s  sent=%-8d recv=%-8d lost=%-5d\n" "$host" "$type" "$sent" "$recv" "$lost"
        fi
    done
done

TOTAL_RECV=$((TOTAL_ACCEPT + TOTAL_REJECT + TOTAL_ACCT_RESP))
RPS=$((TOTAL_RECV * 1000 / ELAPSED_MS))

echo "------------------------------------------"
printf "  TOTAL          sent=%-8d recv=%-8d lost=%-5d\n" "$TOTAL_SENT" "$TOTAL_RECV" "$TOTAL_LOST"
echo "  Accept=$TOTAL_ACCEPT  Reject=$TOTAL_REJECT  Acct-Response=$TOTAL_ACCT_RESP"
echo "  Effective RPS: ${RPS}"
echo "  Process failures: ${FAILURES}"
echo "=========================================="

rm -rf "$TMPDIR"
