#!/bin/bash

set -euo pipefail

# ==========================================
# Stored certificate defaults
# ==========================================
COUNTRY="AU"
# STATE="VIC"
STATE="NSW"
# LOCALITY="Melbourne"
LOCALITY="Sydney"
ORGANIZATION="My Org"
ORG_UNIT="Org Unit"
EMAIL=""
KEY_SIZE="2048"
KEY_ALGO="RSA"

# ==========================================
# Basic input
# ==========================================
if [ $# -ne 1 ]; then
  echo "Usage: $0 <workload-domain-name>"
  exit 1
fi

DOMAIN_NAME_INPUT="$1"
# Autodetect fqdn if running on SDDC Manager
# SDDC="$(hostname -f)"

# ==========================================
# Site 1
# SDDC="<sddc mgr 1>"

# Site 2
SDDC="<sddc mgr 2>"
# ==========================================

read -p "Username: " USERNAME
read -s -p "Password: " PASSWORD
echo

# ==========================================
# Get bearer token
# ==========================================
get_token() {
  AUTH_JSON=$(jq -n \
    --arg username "$USERNAME" \
    --arg password "$PASSWORD" \
    '{username:$username,password:$password}')

  curl -sk -X POST "https://${SDDC}/v1/tokens" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -d "$AUTH_JSON"
}

# ==========================================
# Get all domains
# ==========================================
get_domains() {
  curl -sk "https://${SDDC}/v1/domains" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Accept: application/json'
}

# ==========================================
# Get hosts for a domain
# ==========================================
get_hosts() {
  curl -sk "https://${SDDC}/v1/hosts?domainId=${DOMAIN_ID}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Accept: application/json'
}

# ==========================================
# Build ESXi resource list
# FQDN only, SAN = FQDN
# ==========================================
build_resources() {
  printf '%s\n' "$HOSTS_JSON" | jq '{
    resources: [
      .elements[] |
      {
        resourceId: .id,
        fqdn: .fqdn,
        type: "ESXI",
        name: .fqdn
      }
    ]
  }'
}

# ==========================================
# Build CSR payload
# ==========================================
build_payload() {
  jq -n \
    --arg country "$COUNTRY" \
    --arg state "$STATE" \
    --arg locality "$LOCALITY" \
    --arg organization "$ORGANIZATION" \
    --arg organizationUnit "$ORG_UNIT" \
    --arg email "$EMAIL" \
    --arg keySize "$KEY_SIZE" \
    --arg keyAlgorithm "$KEY_ALGO" \
    --argjson resources "$RESOURCES_JSON" \
    '{
      csrGenerationSpec: {
        country: $country,
        state: $state,
        locality: $locality,
        organization: $organization,
        organizationUnit: $organizationUnit,
        email: $email,
        keySize: $keySize,
        keyAlgorithm: $keyAlgorithm
      },
      resources: $resources.resources
    }'
}

# ==========================================
# Submit CSR generation
# ==========================================
generate_csrs() {
  curl -sk -X PUT "https://${SDDC}/v1/domains/${DOMAIN_ID}/csrs" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -d "$PAYLOAD_JSON"
}

# ==========================================
# Get task status
# ==========================================
get_task() {
  curl -sk "https://${SDDC}/v1/tasks/${TASK_ID}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Accept: application/json'
}

# ==========================================
# Get CSR JSON
# ==========================================
get_csrs() {
  curl -sk "https://${SDDC}/v1/domains/${DOMAIN_ID}/csrs" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Accept: application/json'
}

# ==========================================
# Save raw CSR JSON
# ==========================================
save_csrs_json() {
  printf '%s\n' "$CSRS_JSON" > "${SAFE_DOMAIN_NAME}-csrs.json"
}

# ==========================================
# Save decoded CSR text
# ==========================================
save_decoded_csrs() {
  printf '%s\n' "$CSRS_JSON" | jq -r '
    .elements[] |
    "Host: \(.resource.fqdn)\n" +
    "Type: \(.resource.type // "ESX")\n\n" +
    (.csrDecodedContent // "") +
    "\n--------------------------------------------------\n"
  ' > "${SAFE_DOMAIN_NAME}-csrs-decoded.txt"
}

# ==========================================
# Download CSR tarball
# ==========================================
download_csrs() {
  curl -sk "https://${SDDC}/v1/domains/${DOMAIN_ID}/csrs/downloads" \
    -H "Authorization: Bearer ${TOKEN}" \
    -o "${SAFE_DOMAIN_NAME}-csrs.tar.gz"
}


# ==========================================
# Extract CSR tarball
# ==========================================
extract_csrs_flat() {
  TMP_DIR="${SAFE_DOMAIN_NAME}-csrs-extract"
  FLAT_DIR="${SAFE_DOMAIN_NAME}-csrs-flat"

  rm -rf "$TMP_DIR"
  mkdir -p "$TMP_DIR"
  mkdir -p "$FLAT_DIR"
  tar -xzf "${SAFE_DOMAIN_NAME}-csrs.tar.gz" -C "$TMP_DIR"
  find "$TMP_DIR" -mindepth 2 -type f -name '*.csr' | while read -r FILE; do
    HOST_FQDN=$(basename "$(dirname "$FILE")")
    cp "$FILE" "${FLAT_DIR}/${HOST_FQDN}.csr"
  done

  echo "Saved flattened CSRs to ${FLAT_DIR}/"
}


# ==========================================
# Main
# ==========================================
TOKEN=$(get_token | jq -r '.accessToken')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to get token"
  exit 1
fi

DOMAINS_JSON=$(get_domains)

DOMAIN_ID=$(printf '%s\n' "$DOMAINS_JSON" | jq -r --arg name "$DOMAIN_NAME_INPUT" '
  .elements[]
  | select(.name == $name)
  | .id
' | head -n1)

DOMAIN_NAME=$(printf '%s\n' "$DOMAINS_JSON" | jq -r --arg name "$DOMAIN_NAME_INPUT" '
  .elements[]
  | select(.name == $name)
  | .name
' | head -n1)

DOMAIN_TYPE=$(printf '%s\n' "$DOMAINS_JSON" | jq -r --arg name "$DOMAIN_NAME_INPUT" '
  .elements[]
  | select(.name == $name)
  | .type
' | head -n1)

if [ -z "$DOMAIN_ID" ] || [ "$DOMAIN_ID" = "null" ]; then
  echo "Domain not found: $DOMAIN_NAME_INPUT"
  exit 1
fi

if [ "$DOMAIN_TYPE" != "VI" ]; then
  echo "Domain $DOMAIN_NAME is type $DOMAIN_TYPE, not VI"
  exit 1
fi

SAFE_DOMAIN_NAME=$(printf '%s' "$DOMAIN_NAME" | tr ' /:' '___')

HOSTS_JSON=$(get_hosts)
HOST_COUNT=$(printf '%s\n' "$HOSTS_JSON" | jq '.elements | length')

if [ "$HOST_COUNT" -eq 0 ]; then
  echo "No hosts found in domain $DOMAIN_NAME"
  exit 1
fi

RESOURCES_JSON=$(build_resources)
PAYLOAD_JSON=$(build_payload)

printf '%s\n' "$PAYLOAD_JSON" > "payload-${SAFE_DOMAIN_NAME}.json"
echo "Saved payload-${SAFE_DOMAIN_NAME}.json"

### DEBUG
# exit 0

RESPONSE_JSON=$(generate_csrs)
TASK_ID=$(printf '%s\n' "$RESPONSE_JSON" | jq -r '.id')

if [ -z "$TASK_ID" ] || [ "$TASK_ID" = "null" ]; then
  echo "CSR generation did not return a task id"
  printf '%s\n' "$RESPONSE_JSON"
  exit 1
fi

echo "Started task: $TASK_ID"

while true; do
  TASK_JSON=$(get_task)
  TASK_STATUS=$(printf '%s\n' "$TASK_JSON" | jq -r '.status')

  echo "Task status: $TASK_STATUS"

  case "$TASK_STATUS" in
    SUCCESSFUL|Successful)
      echo "CSR generation completed for $DOMAIN_NAME"
      break
      ;;
    FAILED|Failed|CANCELLED|Cancelled)
      printf '%s\n' "$TASK_JSON" > "task-failed-${SAFE_DOMAIN_NAME}.json"
      echo "CSR generation failed"
      echo "Saved task-failed-${SAFE_DOMAIN_NAME}.json"
      exit 1
      ;;
    *)
      sleep 10
      ;;
  esac
done

CSRS_JSON=$(get_csrs)

save_csrs_json
echo "Saved ${SAFE_DOMAIN_NAME}-csrs.json"

save_decoded_csrs
echo "Saved ${SAFE_DOMAIN_NAME}-csrs-decoded.txt"

read -p "Download CSR tarball now? (y/N): " DOWNLOAD_NOW

if [ "$DOWNLOAD_NOW" = "y" ] || [ "$DOWNLOAD_NOW" = "Y" ]; then
  download_csrs
  echo "Saved ${SAFE_DOMAIN_NAME}-csrs.tar.gz"

  read -p "Extract CSRs into one flat folder now? (y/N): " EXTRACT_NOW

  if [ "$EXTRACT_NOW" = "y" ] || [ "$EXTRACT_NOW" = "Y" ]; then
    extract_csrs_flat
  else
   echo "Skipped flat extraction"
  fi
else
  echo "Skipped CSR tarball download"
fi
