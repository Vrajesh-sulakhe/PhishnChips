#!/usr/bin/env bash
# scripts/verify_containment.sh - Verifies network boundary & containment guarantees from inside the sandbox
set -euo pipefail

NET_NAME="phishnet"
TEST_IMG="curlimages/curl:latest"
FAILED_CHECKS=0

echo "=========================================================="
echo "    PHISH&CHIPS: CONTAINMENT PERIMETER VERIFICATION       "
echo "=========================================================="
echo "Starting ephemeral verification container in ${NET_NAME}..."

run_test() {
    local target_desc="$1"
    local test_url="$2"
    local expect_blocked="$3" # "yes" or "no"

    echo -n "  Testing ${target_desc} (${test_url}) ... "
    
    # Run curl inside ephemeral test container on phishnet
    local output=""
    local exit_code=0
    set +e
    output=$(docker run --rm --network "${NET_NAME}" "${TEST_IMG}" \
        -s -S -o /dev/null -w "%{http_code}" --connect-timeout 3 --max-time 5 "${test_url}" 2>&1)
    exit_code=$?
    set -e

    if [ "$expect_blocked" = "yes" ]; then
        if [ $exit_code -ne 0 ] || [ "$output" = "000" ]; then
            echo " [PASS] BLOCKED (Code: ${exit_code}, Output: ${output})"
        else
            echo " [FAIL] LEAK DETECTED! Expected blocked, but got HTTP ${output}"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    else
        if [ $exit_code -eq 0 ] && [ "$output" != "000" ]; then
            echo " [PASS] REACHABLE (HTTP ${output})"
        else
            echo " [FAIL] OUTBOUND FAILED! Expected reachable, but failed (Code: ${exit_code}, Output: ${output})"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    fi
}

# 1. Public Internet Connectivity Check
run_test "Public Internet (Cloudflare 1.1.1.1)" "https://1.1.1.1" "no"
run_test "Public Internet (Example.com)" "https://example.com" "no"

# 2. Host Isolation Checks
run_test "Host Bridge Gateway (172.30.0.1:8000)" "http://172.30.0.1:8000" "yes"
run_test "Host Public IP (139.84.159.12:8000)" "http://139.84.159.12:8000" "yes"

# 3. Cloud Metadata Isolation Check
run_test "Cloud Metadata Service (169.254.169.254)" "http://169.254.169.254" "yes"

# 4. RFC1918 Private Ranges
run_test "Private Subnet 10.0.0.1" "http://10.0.0.1" "yes"
run_test "Private Subnet 192.168.1.1" "http://192.168.1.1" "yes"

echo "----------------------------------------------------------"
if [ $FAILED_CHECKS -eq 0 ]; then
    echo "🎉 ALL CONTAINMENT CHECKS PASSED. Blast Radius Zero verified!"
    exit 0
else
    echo "❌ CONTAINMENT CHECKS FAILED: ${FAILED_CHECKS} check(s) violated isolation."
    exit 1
fi

