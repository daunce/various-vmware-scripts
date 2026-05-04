#!/bin/bash

set -euo pipefail
IFS=$'\n\t'
shopt -s nullglob

# ===============================================================================
# This script imports, validates and replaces ESX host certificates. Tested on VCF 9.
# 
# Prerequisities:
# Certificates should be named <fqdn>.pem and be placed in a subfolder. 
# 
# ./import-replace-certs.sh <workload domain> <cert folder>
#
# It performs the following steps:
# 1. Validates input parameters and required commands.
# 2. Authenticates with the SDDC Manager API to obtain a bearer token.
# 3. Resolves the workload domain by name to get its ID.
# 4. Retrieves the current list of ESXi hosts in the domain.
# 5. Inspects the input certificate folder to match PEM files to hosts based on FQDN.
# 6. Builds a manifest of matched hosts and their corresponding PEM files.
# 7. Prompts the user to continue with validation.
# 8. Runs certificate validation for the matched hosts.
# 9. If validation succeeds, prompts the user to continue with replacement.
# 10. Performs certificate replacement for each matched host sequentially.
# 11. Saves before and after snapshots of the domain's resource certificates.


fail() {
  echo "ERROR: $1" >&2
  exit 1
}

require_commands() {
  local cmd
  for cmd in bash curl jq openssl tar grep sed awk find; do
    command -v "$cmd" >/dev/null 2>&1 || fail "Required command not found: $cmd"
  done
}

safe_name() {
  printf '%s' "$1" | tr ' /:' '___'
}

prompt_yes_no() {
  local prompt="$1"
  local answer
  read -r -p "$prompt" answer
  [ "$answer" = "yes" ] || [ "$answer" = "YES" ] || [ "$answer" = "y" ] || [ "$answer" = "Y" ]
}

if [ $# -ne 2 ]; then
  echo "Usage: $0 <workload-domain-name> <cert-folder>"
  exit 1
fi

DOMAIN_NAME_INPUT="$1"
CERT_DIR="$2"
# Autodetect SDDC hostname Or hard code it.
# SDDC="$(hostname -f)"

# ==========================================
# SDDC="sddc-site1"
SDDC="sddc-site2"
# ==========================================

[ -d "$CERT_DIR" ] || fail "Certificate folder not found: $CERT_DIR"

CHAIN_FILE="${CERT_DIR}/ca-chain.pem"
[ -f "$CHAIN_FILE" ] || fail "Common chain file not found: $CHAIN_FILE"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_ROOT="$(pwd)/runs"
mkdir -p "$RUN_ROOT"

RUN_DIR=""
SAFE_DOMAIN_NAME=""
DOMAIN_ID=""
DOMAIN_NAME=""
TOKEN=""

get_token() {
  local auth_file="$1"

  jq -n \
    --arg username "$USERNAME" \
    --arg password "$PASSWORD" \
    '{username:$username,password:$password}' > "$auth_file"

  curl -sk -X POST "https://${SDDC}/v1/tokens" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary @"$auth_file"
}

api_get() {
  local path="$1"
  curl -sk "https://${SDDC}${path}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Accept: application/json'
}

api_put_json_file() {
  local path="$1"
  local payload_file="$2"
  curl -sk -X PUT "https://${SDDC}${path}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary @"$payload_file"
}

resolve_domain() {
  DOMAINS_JSON="$(api_get "/v1/domains")"
  printf '%s\n' "$DOMAINS_JSON" > "${RUN_DIR}/domains.json"

  local match_count
  match_count="$(printf '%s\n' "$DOMAINS_JSON" | jq -r --arg name "$DOMAIN_NAME_INPUT" '
    [ .elements[] | select(.name == $name and .type == "VI") ] | length
  ')"

  [ "$match_count" = "1" ] || fail "Expected exactly 1 VI workload domain named '$DOMAIN_NAME_INPUT', found $match_count"

  DOMAIN_ID="$(printf '%s\n' "$DOMAINS_JSON" | jq -r --arg name "$DOMAIN_NAME_INPUT" '
    .elements[] | select(.name == $name and .type == "VI") | .id
  ')"

  DOMAIN_NAME="$(printf '%s\n' "$DOMAINS_JSON" | jq -r --arg name "$DOMAIN_NAME_INPUT" '
    .elements[] | select(.name == $name and .type == "VI") | .name
  ')"

  SAFE_DOMAIN_NAME="$(safe_name "$DOMAIN_NAME")"

  echo "Resolved workload domain: $DOMAIN_NAME"
  echo "Domain ID: $DOMAIN_ID"
}

declare -A HOST_ID_BY_FQDN
declare -A HOST_CLUSTER_BY_FQDN
HOST_ORDER=()

get_current_hosts() {
  local hosts_json
  hosts_json="$(api_get "/v1/hosts?domainId=${DOMAIN_ID}")"
  printf '%s\n' "$hosts_json" > "${RUN_DIR}/current-hosts.json"

  while IFS=$'\t' read -r fqdn host_id cluster_name; do
    [ -n "$fqdn" ] || continue
    HOST_ID_BY_FQDN["$fqdn"]="$host_id"
    HOST_CLUSTER_BY_FQDN["$fqdn"]="$cluster_name"
    HOST_ORDER+=("$fqdn")
  done < <(
    printf '%s\n' "$hosts_json" | jq -r '
      .elements[]? |
      [ .fqdn, .id, (.clusterName // "") ] | @tsv
    '
  )

  [ "${#HOST_ORDER[@]}" -gt 0 ] || fail "No hosts found for workload domain $DOMAIN_NAME"

  echo "Current ESXi hosts found: ${#HOST_ORDER[@]}"
}

declare -A PEM_BY_FQDN
MATCHED_HOSTS=()
SKIPPED_HOSTS=()
EXTRA_PEMS=()

pem_matches_host() {
  local pem_file="$1"
  local fqdn="$2"
  local san_text=""
  local subject_text=""
  local san_ok=1
  local cn_ok=1

  openssl x509 -in "$pem_file" -noout >/dev/null 2>&1 || return 1

  san_text="$(openssl x509 -in "$pem_file" -noout -ext subjectAltName 2>/dev/null || true)"
  subject_text="$(openssl x509 -in "$pem_file" -noout -subject -nameopt RFC2253 2>/dev/null || true)"

  printf '%s\n' "$san_text" | grep -Eq "DNS:${fqdn}([, ]|$)" && san_ok=0 || true
  printf '%s\n' "$subject_text" | grep -Eq "CN=${fqdn}([,]|$)" && cn_ok=0 || true

  if [ "$san_ok" -ne 0 ] && [ "$cn_ok" -ne 0 ]; then
    return 1
  fi

  return 0
}

inspect_input_folder() {
  local pem_file
  local base
  local fqdn

  for pem_file in "${CERT_DIR}"/*.pem; do
    base="$(basename "$pem_file")"

    if [ "$base" = "ca-chain.pem" ]; then
      continue
    fi

    fqdn="${base%.pem}"

    if [ -z "${HOST_ID_BY_FQDN[$fqdn]+x}" ]; then
      EXTRA_PEMS+=("$base")
      continue
    fi

    if [ -n "${PEM_BY_FQDN[$fqdn]+x}" ]; then
      fail "Duplicate PEM mapping for host: $fqdn"
    fi

    pem_matches_host "$pem_file" "$fqdn" || fail "PEM subject/SAN does not match host FQDN: $fqdn"

    PEM_BY_FQDN["$fqdn"]="$pem_file"
  done

  if [ "${#EXTRA_PEMS[@]}" -gt 0 ]; then
    {
      echo "Extra PEM files found that do not map to a current host in workload domain:"
      printf '  %s\n' "${EXTRA_PEMS[@]}"
    } | tee "${RUN_DIR}/extra-pems.txt"
    fail "Found PEM files with no matching current host"
  fi

  local fqdn
  for fqdn in "${HOST_ORDER[@]}"; do
    if [ -n "${PEM_BY_FQDN[$fqdn]+x}" ]; then
      MATCHED_HOSTS+=("$fqdn")
    else
      SKIPPED_HOSTS+=("$fqdn")
    fi
  done

  [ "${#MATCHED_HOSTS[@]}" -gt 0 ] || fail "No matching PEM files found for current hosts in $DOMAIN_NAME"

  echo "Matched hosts to replace: ${#MATCHED_HOSTS[@]}"
  echo "Current hosts with no returned cert: ${#SKIPPED_HOSTS[@]}"
}

write_manifest() {
  local tmp_file="${RUN_DIR}/manifest-items.jsonl"
  : > "$tmp_file"

  local fqdn
  for fqdn in "${HOST_ORDER[@]}"; do
    jq -n \
      --arg fqdn "$fqdn" \
      --arg resourceId "${HOST_ID_BY_FQDN[$fqdn]}" \
      --arg clusterName "${HOST_CLUSTER_BY_FQDN[$fqdn]}" \
      --arg certFile "${PEM_BY_FQDN[$fqdn]-}" \
      --arg status "$(
        if [ -n "${PEM_BY_FQDN[$fqdn]+x}" ]; then
          printf 'ready'
        else
          printf 'missing_cert'
        fi
      )" \
      '{
        fqdn:$fqdn,
        resourceId:$resourceId,
        clusterName:$clusterName,
        certFile:$certFile,
        status:$status
      }' >> "$tmp_file"
  done

  jq -s '.' "$tmp_file" > "${RUN_DIR}/manifest.json"
  rm -f "$tmp_file"

  {
    echo "Workload domain: $DOMAIN_NAME"
    echo "Domain ID: $DOMAIN_ID"
    echo "Certificate folder: $CERT_DIR"
    echo "Current ESXi hosts found: ${#HOST_ORDER[@]}"
    echo "Matched hosts to replace: ${#MATCHED_HOSTS[@]}"
    echo "Current hosts with no returned cert: ${#SKIPPED_HOSTS[@]}"
    echo "Extra PEM files with no matching current host: 0"
    echo
    echo "Replacement set:"
    printf '  %s\n' "${MATCHED_HOSTS[@]}"
    echo
    if [ "${#SKIPPED_HOSTS[@]}" -gt 0 ]; then
      echo "Skipped current hosts with no PEM:"
      printf '  %s\n' "${SKIPPED_HOSTS[@]}"
      echo
    fi
  } | tee "${RUN_DIR}/summary-precheck.txt"
}

build_payload_for_hosts() {
  local output_file="$1"
  shift

  local tmp_file="${RUN_DIR}/payload-items.jsonl"
  : > "$tmp_file"

  local fqdn
  local cert_chain
  for fqdn in "$@"; do
    cert_chain="$(cat "${PEM_BY_FQDN[$fqdn]}" "$CHAIN_FILE")"

    jq -n \
      --arg resourceId "${HOST_ID_BY_FQDN[$fqdn]}" \
      --arg certificateChain "$cert_chain" \
      '{
        resourceId:$resourceId,
        certificateChain:$certificateChain
      }' >> "$tmp_file"
  done

  jq -s '.' "$tmp_file" > "$output_file"
  rm -f "$tmp_file"
}

poll_validation() {
  local validation_id="$1"
  local output_file="$2"
  local result

  while true; do
    result="$(api_get "/v1/domains/${DOMAIN_ID}/resource-certificates/validations/${validation_id}")"
    printf '%s\n' "$result" > "$output_file"

    local completed
    completed="$(printf '%s\n' "$result" | jq -r '.completed')"

    echo "Validation completed: $completed"

    if [ "$completed" = "true" ]; then
      break
    fi

    sleep 5
  done
}

run_validation() {
  local payload_file="${RUN_DIR}/validation-payload.json"
  local start_file="${RUN_DIR}/validation-start.json"
  local result_file="${RUN_DIR}/validation-result.json"
  local validation_id

  build_payload_for_hosts "$payload_file" "${MATCHED_HOSTS[@]}"

  api_put_json_file "/v1/domains/${DOMAIN_ID}/resource-certificates/validations" "$payload_file" > "$start_file"

  validation_id="$(jq -r '.validationId // empty' "$start_file")"
  [ -n "$validation_id" ] || fail "Validation did not return validationId"

  echo "Validation ID: $validation_id"

  poll_validation "$validation_id" "$result_file"

  local failed_count
  failed_count="$(jq -r '
    [ .validations[]? | select(.validationStatus != "SUCCESSFUL") ] | length
  ' "$result_file")"

  if [ "$failed_count" != "0" ]; then
    jq -r '
      .validations[]? |
      select(.validationStatus != "SUCCESSFUL") |
      [
        (.resourceFqdn // .resourceId // "unknown"),
        .validationStatus,
        (.validationMessage // "")
      ] | @tsv
    ' "$result_file" > "${RUN_DIR}/validation-failures.tsv"

    echo "Validation failures:"
    cat "${RUN_DIR}/validation-failures.tsv"
    fail "Validation failed for one or more hosts"
  fi

  echo "All validations succeeded"
}

save_domain_cert_snapshot() {
  local output_file="$1"
  api_get "/v1/domains/${DOMAIN_ID}/resource-certificates" > "$output_file"
}

poll_task() {
  local task_id="$1"
  local output_file="$2"
  local task_json
  local task_status

  while true; do
    task_json="$(api_get "/v1/tasks/${task_id}")"
    printf '%s\n' "$task_json" > "$output_file"

    task_status="$(printf '%s\n' "$task_json" | jq -r '.status')"
    echo "Task status: $task_status"

    case "$task_status" in
      SUCCESSFUL|Successful)
        return 0
        ;;
      FAILED|Failed|CANCELLED|Cancelled)
        return 1
        ;;
      *)
        sleep 10
        ;;
    esac
  done
}

run_replacements() {
  local replace_dir="${RUN_DIR}/replace"
  mkdir -p "$replace_dir"

  local total="${#MATCHED_HOSTS[@]}"
  local index=0
  local fqdn
  local payload_file
  local start_file
  local task_file
  local task_id

  for fqdn in "${MATCHED_HOSTS[@]}"; do
    index=$((index + 1))
    echo
    echo "[$index/$total] Replacing certificate for $fqdn"

    payload_file="${replace_dir}/$(safe_name "$fqdn")-payload.json"
    start_file="${replace_dir}/$(safe_name "$fqdn")-start.json"
    task_file="${replace_dir}/$(safe_name "$fqdn")-task.json"

    build_payload_for_hosts "$payload_file" "$fqdn"
    api_put_json_file "/v1/domains/${DOMAIN_ID}/resource-certificates" "$payload_file" > "$start_file"

    task_id="$(jq -r '.id // empty' "$start_file")"
    [ -n "$task_id" ] || fail "Replacement did not return task id for $fqdn"

    echo "Task ID: $task_id"

    if ! poll_task "$task_id" "$task_file"; then
      fail "Replacement failed for $fqdn"
    fi
  done
}

require_commands

read -r -p "Username: " USERNAME
read -r -s -p "Password: " PASSWORD
echo

BOOTSTRAP_DIR="$(mktemp -d)"
trap 'rm -rf "$BOOTSTRAP_DIR"' EXIT

AUTH_FILE="${BOOTSTRAP_DIR}/auth.json"
TOKEN_RESPONSE="$(get_token "$AUTH_FILE")"
TOKEN="$(printf '%s\n' "$TOKEN_RESPONSE" | jq -r '.accessToken // empty')"
[ -n "$TOKEN" ] || fail "Failed to get bearer token"

RUN_DIR="${RUN_ROOT}/${TIMESTAMP}_bootstrap"
mkdir -p "$RUN_DIR"
printf '%s\n' "$TOKEN_RESPONSE" > "${RUN_DIR}/token-response.json"

resolve_domain

FINAL_RUN_DIR="${RUN_ROOT}/${TIMESTAMP}_${SAFE_DOMAIN_NAME}"
mkdir -p "$FINAL_RUN_DIR"

mv "${RUN_DIR}/token-response.json" "${FINAL_RUN_DIR}/token-response.json"
mv "${RUN_DIR}/domains.json" "${FINAL_RUN_DIR}/domains.json"
rmdir "$RUN_DIR" 2>/dev/null || true
RUN_DIR="$FINAL_RUN_DIR"

echo "Run artifacts: $RUN_DIR"
echo

get_current_hosts
printf 'DEBUG known host=%s\n' "${HOST_ORDER[@]}"
inspect_input_folder
write_manifest

echo
if ! prompt_yes_no "Continue with validation for ${#MATCHED_HOSTS[@]} matched hosts? (yes/no): "; then
  echo "Cancelled"
  exit 0
fi

echo
echo "Saving before snapshot"
save_domain_cert_snapshot "${RUN_DIR}/before.json"

echo
echo "Running validation"
run_validation

echo
if ! prompt_yes_no "Validation passed. Continue with replacement for ${#MATCHED_HOSTS[@]} hosts? (yes/no): "; then
  echo "Cancelled"
  exit 0
fi

echo
echo "Starting replacement"
run_replacements

echo
echo "Saving after snapshot"
save_domain_cert_snapshot "${RUN_DIR}/after.json"

{
  echo "Completed successfully"
  echo "Run folder: $RUN_DIR"
  echo "Before snapshot: ${RUN_DIR}/before.json"
  echo "Validation result: ${RUN_DIR}/validation-result.json"
  echo "After snapshot: ${RUN_DIR}/after.json"
  echo "Manifest: ${RUN_DIR}/manifest.json"
} | tee "${RUN_DIR}/summary-final.txt"
