#!/usr/bin/env bash
#
# Pulls the forest facts off the domain controller and writes them as JSON.
#
# Run Command caps its response at about 4 KB and truncates from the FRONT, so
# an oversized payload loses its opening brace and stops being parseable rather
# than arriving visibly short. The export on the machine therefore compresses
# and base64-encodes the facts and prints them between markers, and this pulls
# the encoded block out of the surrounding chatter and decodes it here.
#
# The markers matter. Run Command wraps the script output in its own status
# text, and grepping for something that looks like base64 would eventually
# match that instead.

set -euo pipefail

RESOURCE_GROUP="${1:?resource group required}"
VM_NAME="${2:?vm name required}"
OUTPUT="${3:?output path required}"

raw=$(az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --command-id RunPowerShellScript \
  --scripts @"$(dirname "$0")/vm/Export-ForestFacts.ps1" \
  --query "value[0].message" -o tsv)

# Report the counts the script printed before anything else, so a failure below
# is read against how much was actually exported.
echo "$raw" | grep -E '^users=' || true

encoded=$(echo "$raw" | sed -n '/FACTS_BEGIN/,/FACTS_END/p' | sed '1d;$d' | tr -d '\r\n ')

if [ -z "$encoded" ]; then
  echo "No facts block came back. Run Command returned:" >&2
  echo "$raw" | tail -20 >&2
  exit 1
fi

if ! echo "$encoded" | base64 -d 2>/dev/null | gzip -dc > "$OUTPUT" 2>/dev/null; then
  echo "The facts block did not decode. That is what front-truncation looks like:" >&2
  echo "  encoded length: ${#encoded}" >&2
  exit 1
fi

# An empty or malformed object here would otherwise surface much later as an
# assessment that found nothing and reported success.
count=$(jq -e '.users | length' "$OUTPUT")
echo "decoded $count user(s) into $OUTPUT"
if [ "$count" -eq 0 ]; then
  echo "The forest exported no users, so there is nothing to assess." >&2
  exit 1
fi
