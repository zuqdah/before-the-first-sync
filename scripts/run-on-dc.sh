#!/usr/bin/env bash
#
# Runs a script on the domain controller and fails if the script failed.
#
# `az vm run-command invoke` reports on the invocation, not on the script. An
# exception inside comes back as a successful call with the error buried in the
# response body, so a caller reading only the exit code sees success over a
# script that threw. That is how a half-built directory reached the assessment
# and looked like a broken check rather than a directory that was never built.
#
# Every script on the machine prints SCRIPT_OK as its last line. Its absence is
# the failure signal, whatever the CLI said.

set -euo pipefail

RESOURCE_GROUP="${1:?resource group required}"
VM_NAME="${2:?vm name required}"
SCRIPT="${3:?script path required}"
shift 3

args=(--resource-group "$RESOURCE_GROUP" --name "$VM_NAME"
      --command-id RunPowerShellScript --scripts @"$SCRIPT")
for p in "$@"; do args+=(--parameters "$p"); done

output=$(az vm run-command invoke "${args[@]}" --query "value[0].message" -o tsv)

echo "$output" | sed 's/^/  /' | tail -30

if ! grep -q 'SCRIPT_OK' <<<"$output"; then
  echo "" >&2
  echo "$(basename "$SCRIPT") did not reach its end. Run Command reported the call as successful, which it was -- the script inside it was not." >&2
  exit 1
fi
