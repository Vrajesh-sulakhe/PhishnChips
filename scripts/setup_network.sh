#!/usr/bin/env bash
# scripts/setup_network.sh - Idempotently configure the isolated phishnet Docker network & iptables containment
set -euo pipefail

SUBNET="172.30.0.0/16"
NET_NAME="phishnet"

echo "==> [Network Setup] Checking Docker network: ${NET_NAME}..."
if docker network inspect "${NET_NAME}" >/dev/null 2>&1; then
    echo "    Network '${NET_NAME}' already exists."
else
    echo "    Creating Docker bridge network '${NET_NAME}' with subnet ${SUBNET}..."
    docker network create --subnet="${SUBNET}" "${NET_NAME}"
fi

echo "==> [Network Setup] Configuring iptables containment perimeter..."

# 1. Host Protection (INPUT Chain)
# Drop all inbound traffic from phishnet to the host system (gateway, host IP, loopback)
if iptables -C INPUT -s "${SUBNET}" -j DROP 2>/dev/null; then
    echo "    [INPUT] Drop rule from ${SUBNET} already present."
else
    echo "    [INPUT] Adding drop rule for ${SUBNET}..."
    iptables -I INPUT 1 -s "${SUBNET}" -j DROP
fi

# 2. Forwarded Traffic Isolation (DOCKER-USER Chain)
# Docker passes container forwarded traffic through DOCKER-USER first.

# Ensure connection tracking accepts established/related
if iptables -C DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    echo "    [DOCKER-USER] Established/Related rule already present."
else
    iptables -I DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi

# Block RFC1918 Private Subnets
for target_range in "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"; do
    if iptables -C DOCKER-USER -s "${SUBNET}" -d "${target_range}" -j DROP 2>/dev/null; then
        echo "    [DOCKER-USER] Drop rule to ${target_range} already present."
    else
        echo "    [DOCKER-USER] Adding drop rule from ${SUBNET} to ${target_range}..."
        iptables -I DOCKER-USER 2 -s "${SUBNET}" -d "${target_range}" -j DROP
    fi
done

# Block Cloud Metadata (169.254.0.0/16)
if iptables -C DOCKER-USER -s "${SUBNET}" -d 169.254.0.0/16 -j DROP 2>/dev/null; then
    echo "    [DOCKER-USER] Drop rule to 169.254.0.0/16 already present."
else
    echo "    [DOCKER-USER] Adding drop rule from ${SUBNET} to 169.254.0.0/16..."
    iptables -I DOCKER-USER 2 -s "${SUBNET}" -d 169.254.0.0/16 -j DROP
fi

echo "==> [Network Setup] phishnet isolation successfully verified and armed."

