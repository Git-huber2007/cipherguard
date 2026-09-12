#!/bin/sh
# Fetch real IPsec captures for external validation.
#
# These are not vendored into this repository. They belong to the Wireshark
# project and are covered by its licence, so they are downloaded on demand and
# attributed rather than redistributed here. The tests that use them skip
# cleanly when they are absent, so an offline checkout still passes.
#
#   ./scripts/fetch-real-captures.sh
#   python -m cipherguard.cli verify-real

set -eu
BASE="https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures"
DEST="${1:-samples/real}"

CAPTURES="ikev2-decrypt-aes256gcm16.pcap
ikev2-decrypt-aes256gcm8.pcap
ikev2-decrypt-aes128ccm12.pcap
ikev2-decrypt-aes192ctr.pcap
ikev1-certs.pcap"

mkdir -p "$DEST"
echo "Fetching real IPsec captures into $DEST/"
echo "Source: Wireshark project test suite"
echo

got=0
for name in $CAPTURES; do
    if [ -f "$DEST/$name" ]; then
        echo "  have $name"
        got=$((got + 1))
        continue
    fi
    if curl -fsSL -o "$DEST/$name" "$BASE/$name" 2>/dev/null; then
        echo "  got  $name ($(wc -c < "$DEST/$name") bytes)"
        got=$((got + 1))
    else
        rm -f "$DEST/$name"
        echo "  MISS $name (upstream path may have moved)"
    fi
done

echo
echo "$got capture(s) available. Validate with:"
echo "    python -m cipherguard.cli verify-real"
