#!/bin/bash

# shellcheck disable=SC2181
# SC2181 = Check exit code directly with e.g. 'if mycmd;', not indirectly with $?.

# INSTALLATION:
#
# Copy this script to ~/pc_iac_scan.sh
# Edit [API, USERNAME, PASSWORD] below
# Make ~/pc_iac_scan.sh executable

# USAGE:
#
# ~/pc_iac_scan.sh <module> <template_type>

DEBUG=false

#### BEGIN USER CONFIGURATION

# Prisma Cloud › Access URL: Prisma Cloud API URL
API=https://api.prismacloud.io

# Prisma Cloud › Login Credentials: Access Key
USERNAME=abcdefghijklmnopqrstuvwxyz

# Prisma Cloud › Login Credentials: Secret Key
PASSWORD=1234567890=

#### END USER CONFIGURATION

MODULE=$1
TEMPLATETYPE=$2

#### Utility functions.

debug() {
  if $DEBUG; then
     echo
     echo "DEBUG: ${1}"
     echo
  fi
}

error_and_exit() {
  echo
  echo "ERROR: ${1}"
  echo
  exit 1
}

# TODO: Optionally accept and set TEMPLATEVERSION.
#
# TEMPLATEVERSION="0.12"
#
# 'templateVersion'': '${TEMPLATEVERSION}'

if [ -z "${MODULE}" ]; then
  error_and_exit "Please specify a module"
fi

if [ -z "${TEMPLATETYPE}" ]; then
  error_and_exit "Please specify a template type [cft, k8s, tf]"
fi

PC_API_LOGIN_FILE=/tmp/prisma-api-login.json
PC_IAC_CREATE_FILE=/tmp/prisma-scan-create.json
PC_IAC_HISTORY_FILE=/tmp/prisma-scan-history.json
PC_IAC_UPLOAD_FILE=/tmp/prisma-scan-upload.json
PC_IAC_START_FILE=/tmp/prisma-scan-start.json
PC_IAC_STATUS_FILE=/tmp/prisma-scan-status.json
PC_IAC_RESULTS=/tmp/prisma-scan-results.json

#### Use the active login, or login.
# https://api.docs.prismacloud.io/reference#login

# TODO:
#
# The login token is valid for 10 minutes.
# Refresh instead of replace, if it exists, as per:
# https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/get-started-with-prisma-cloud/access-the-prisma-cloud-api.html

ACTIVELOGIN=$(find "${PC_API_LOGIN_FILE}" -mmin -10 2>/dev/null)
if [ -z "${ACTIVELOGIN}" ]; then
  rm -f "${PC_API_LOGIN_FILE}"
  curl --fail --silent \
    --request POST "${API}/login" \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}" \
    --output "${PC_API_LOGIN_FILE}"
fi

if [ $? -ne 0 ]; then
  error_and_exit "API Login Failed"
fi

# Check the output instead of checking the response code.

if [ ! -s "${PC_API_LOGIN_FILE}" ]; then
  rm -f "${PC_API_LOGIN_FILE}"
  error_and_exit "API Login Returned No Response Data"
fi

TOKEN=$(jq -r '.token' < "${PC_API_LOGIN_FILE}")
if [ -z "${TOKEN}" ]; then
  rm -f "${PC_API_LOGIN_FILE}"
  error_and_exit "Token Missing From 'API Login' Response"
fi

debug "Token: ${TOKEN}"

#### Create an IaC scan asset in Prisma Cloud.
# https://api.docs.prismacloud.io/reference#startasyncscan

echo "Creating Scan"

rm -f "${PC_IAC_CREATE_FILE}"

JSON="
{
  'data': {
    'type': 'async-scan',
    'attributes': {
      'assetName': '${MODULE}',
      'assetType': 'IaC-API',
      'tags': {
        'env': 'dev'
      },
      'scanAttributes': {
        'projectName': 'pc_iac'
      },
      'failureCriteria': {
        'high':     8,
        'medium':   16,
        'low':      32,
        'operator': 'or'
      }
    }
  }
}
"
JSON=${JSON//\'/\"}

curl --silent --show-error \
  --request POST "${API}/iac/v2/scans" \
  --header "x-redlock-auth: ${TOKEN}" \
  --header "Accept: application/vnd.api+json" \
  --header "Content-Type: application/vnd.api+json" \
  --data-raw "${JSON}" \
  --output "${PC_IAC_CREATE_FILE}"

# TODO: Use --fail and/or --write-out '{http_code}' ?
if [ $? -ne 0 ]; then
  error_and_exit "Create Scan Asset Failed"
fi

# Check the output instead of checking the response code.

if [ ! -s "${PC_IAC_CREATE_FILE}" ]; then
  error_and_exit "Create Scan Returned No Response Data"
fi

PC_IAC_ID=$(jq -r '.data.id' < "${PC_IAC_CREATE_FILE}")

if [ -z "${PC_IAC_ID}" ]; then
  error_and_exit "Scan ID Missing From 'Create Scan' Response"
fi

PC_IAC_URL=$(jq -r '.data.links.url' < "${PC_IAC_CREATE_FILE}")

if [ -z "${PC_IAC_URL}" ]; then
  error_and_exit "Scan URL Missing From 'Create Scan' Response"
fi

echo "$(date '+%F %T') ${PC_IAC_ID}" >> "${PC_IAC_HISTORY_FILE}"

debug "Scan ID: ${PC_IAC_ID}"

#### Use the pre-signed URL from the scan asset creation to upload the files to be scanned.

echo "Uploading Files"

ARCHIVE="/tmp/${MODULE}.zip"

zip -r -q "${ARCHIVE}" "${MODULE}"

rm -f "${PC_IAC_UPLOAD_FILE}"

curl --silent --show-error \
  --request PUT "${PC_IAC_URL}" \
  --upload-file "${ARCHIVE}" \
  --output "${PC_IAC_UPLOAD_FILE}"

# TODO: Use --fail and/or --write-out '{http_code}' ?
if [ $? -ne 0 ]; then
  error_and_exit "Upload Scan Asset Failed"
fi

debug "Uploaded: ${ARCHIVE}"

#### Start a job to perform a scan of the uploaded files.
# https://api.docs.prismacloud.io/reference#triggerasyncscan-1

# TODO:
#
# This API detects Terraform module structures and variable files automatically, in most cases.
# Review the use of variables, variableFiles, files, and folders attributes.

echo "Starting Scan"

rm -f "${PC_IAC_START_FILE}"

JSON="
{
  'data': {
    'id': '${PC_IAC_ID}',
    'attributes': {
      'templateType': '${TEMPLATETYPE}'
    }
  }
}
"
JSON=${JSON//\'/\"}


curl --silent --show-error \
  --request POST "${API}/iac/v2/scans/${PC_IAC_ID}" \
  --header "x-redlock-auth: ${TOKEN}" \
  --header "Accept: application/vnd.api+json" \
  --header "Content-Type: application/vnd.api+json" \
  --data-raw "${JSON}" \
  --output "${PC_IAC_START_FILE}"

# TODO: Use --fail and/or --write-out '{http_code}' ?
if [ $? -ne 0 ]; then
  error_and_exit "Start Scan Failed"
fi

# Check the output instead of checking the response code.
# Note that there is no output upon success.

if [ -s "${PC_IAC_START_FILE}" ]; then
  START_STATUS=$(jq -r '.status' < "${PC_IAC_START_FILE}")

  if [ -z "${START_STATUS}" ]; then
    error_and_exit "Status Missing From 'Start Scan' Response"
  fi

  if [ "${START_STATUS}" -ne 200 ]; then
    error_and_exit "Start Scan Returned: ${START_STATUS}"
  fi

  START_STATUS="unknown"
else
  START_STATUS="success"
fi

debug "Start Scan Status: ${START_STATUS}"

#### Query scan status.

echo -n "Querying Scan Status "

SCAN_STATUS="processing"
while [ $SCAN_STATUS == "processing" ]
do
  sleep 4

  rm -f "${PC_IAC_STATUS_FILE}"

  HTTP_CODE=$(curl --silent --write-out '%{http_code}' \
    --request GET "${API}/iac/v2/scans/${PC_IAC_ID}/status" \
    --header "x-redlock-auth: ${TOKEN}" \
    --header "Accept: application/vnd.api+json" \
    --header "Content-Type: application/vnd.api+json" \
    --output "${PC_IAC_STATUS_FILE}")

  # TODO: Use --fail ?
  if [ $? -ne 0 ]; then
    error_and_exit "Query Scan Status Failed"
  fi

  if [[ $HTTP_CODE == 5?? ]]; then
    echo -n " ${HTTP_CODE} "
  else
    SCAN_STATUS=$(jq -r '.data.attributes.status' < "${PC_IAC_STATUS_FILE}")
    if [ -z "${SCAN_STATUS}" ]; then
      error_and_exit "Status Missing From 'Query Scan Status' Response"
    fi
    echo -n "."
  fi

  debug "Scan Status: ${SCAN_STATUS}"

done

echo

#### Query scan results.
# https://api.docs.prismacloud.io/reference#getscanresult

echo "Querying Scan Results"

curl --fail --silent --show-error \
  --request GET "${API}/iac/v2/scans/${PC_IAC_ID}/results" \
  --header "x-redlock-auth: ${TOKEN}" \
  --header 'Accept: application/vnd.api+json' \
  --header "Content-Type: application/vnd.api+json" \
  --output ${PC_IAC_RESULTS}

if [ $? -ne 0 ]; then
  error_and_exit "Query Scan Results Failed"
fi

HIGH=$(  jq '.meta.matchedPoliciesSummary.high'   < "${PC_IAC_RESULTS}")
MEDIUM=$(jq '.meta.matchedPoliciesSummary.medium' < "${PC_IAC_RESULTS}")
LOW=$(   jq '.meta.matchedPoliciesSummary.low'    < "${PC_IAC_RESULTS}")

# TODO: Deeply parse the results with jq, and display the parsed results.

echo "Results:"
echo
jq '.data' < "${PC_IAC_RESULTS}"
echo
echo "Summary:"
echo
echo "High Severity Issues: ${HIGH}"
echo "Medium Severity Issues: ${MEDIUM}"
echo "Low Severity Issues: ${LOW}"
echo
echo "Scan ${SCAN_STATUS}!"

echo