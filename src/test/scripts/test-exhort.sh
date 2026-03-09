#!/bin/bash
# ==============================================================================
# Exhort Testing Script
# ==============================================================================
# This script automates testing of Exhort API.
# It gets all vulnerabilities for a given SBOM file and prints the vulnerabilities.
# Used for dev purposes to check if the API is working.
# ==============================================================================

set -e

# ==============================================================================
# CONFIGURATION - Customize these variables as needed
# ==============================================================================
# Get all vulnerabilities
echo "Getting all vulnerabilities for nmstate-rhel8-operator"
curl -X POST "https://exhort.stage.devshift.net/api/v5/analysis" \
  -H "Content-Type: application/vnd.cyclonedx+json" \
  --data-binary @./src/test/resources/devservices/cyclonedx-sboms/nmstate-rhel8-operator.json | jq 