#!/bin/sh
# Capture the transit segment while a tunnel is negotiated and used.
#   /capture.sh <profile> <seconds>
set -eu
PROFILE="${1:-weak}"
SECONDS_TO_RUN="${2:-60}"
OUT="/captures/${PROFILE}.pcap"

echo "Capturing IKE (UDP 500/4500) and ESP (proto 50) for ${SECONDS_TO_RUN}s"
timeout "${SECONDS_TO_RUN}" tcpdump -i any -s 0 -w "${OUT}" \
    'udp port 500 or udp port 4500 or proto 50' || true

echo "Wrote ${OUT}"
echo "Analyse with: cipherguard analyze docker/captures/${PROFILE}.pcap"
