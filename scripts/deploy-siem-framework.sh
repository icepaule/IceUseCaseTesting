#!/usr/bin/env bash
# =============================================================================
# deploy-siem-framework.sh
# Master deployment script for the Bank SIEM Use Case & Adversary Framework
# Runs all generators and deploys to Caldera + Splunk
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/caldera-splunk"
LOG_FILE="${LOG_DIR}/deploy-$(date +%Y%m%d-%H%M%S).log"
REPO_DIR="/root/IceUseCaseTesting"

mkdir -p "$LOG_DIR"

# --- Logging ---
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2; }
log_section() {
    echo "" | tee -a "$LOG_FILE"
    echo "================================================================" | tee -a "$LOG_FILE"
    echo "  $*" | tee -a "$LOG_FILE"
    echo "================================================================" | tee -a "$LOG_FILE"
}

# --- Environment ---
export CALDERA_API="${CALDERA_API:-http://localhost:8888/api/v2}"
export CALDERA_API_KEY="${CALDERA_API_KEY:-<API_KEY>}"
export SPLUNK_HOST="${SPLUNK_HOST:-<SPLUNK_HOST>}"
export SPLUNK_USER="${SPLUNK_USER:-admin}"
export SPLUNK_PASS="${SPLUNK_PASS:-<PASSWORD>}"

# --- Pre-flight checks ---
preflight() {
    log_section "PRE-FLIGHT CHECKS"

    # Check Caldera API
    log "Checking Caldera API..."
    if curl -sk -H "KEY: ${CALDERA_API_KEY}" "${CALDERA_API}/abilities" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200"; then
        log "  Caldera API: OK"
    else
        log_error "  Caldera API: UNREACHABLE at ${CALDERA_API}"
        log "  Continuing anyway - YAML files will still be generated"
    fi

    # Check Python
    log "Checking Python3..."
    if command -v python3 &>/dev/null; then
        log "  Python3: $(python3 --version)"
    else
        log_error "  Python3 not found!"
        exit 1
    fi

    # Check required Python modules
    log "Checking Python modules..."
    python3 -c "import requests, yaml, csv, json" 2>/dev/null && log "  Python modules: OK" || {
        log "  Installing missing modules..."
        pip3 install requests pyyaml 2>/dev/null || true
    }

    # Check directories
    for dir in "/opt/caldera/data/adversaries" "/opt/caldera-splunk/lookups" "/opt/caldera-splunk/siem" "${REPO_DIR}/caldera/adversaries"; do
        mkdir -p "$dir"
        log "  Directory: $dir (exists)"
    done

    log "Pre-flight checks complete."
}

# --- Step 1: Generate Adversary Profiles ---
step1_adversary_profiles() {
    log_section "STEP 1: Generate Adversary Profiles"
    log "Running: generate-adversary-profiles.py"

    if python3 "${SCRIPT_DIR}/generate-adversary-profiles.py" 2>&1 | tee -a "$LOG_FILE"; then
        log "Step 1 COMPLETE: Adversary profiles generated and loaded"
        # Count profiles
        local count
        count=$(ls -1 /opt/caldera/data/adversaries/bank-*-advanced.yml /opt/caldera/data/adversaries/bank-credential-access.yml /opt/caldera/data/adversaries/bank-discovery-recon.yml /opt/caldera/data/adversaries/bank-command-control.yml 2>/dev/null | wc -l)
        log "  New profiles: $count"
    else
        log_error "Step 1 FAILED: Adversary profile generation had errors"
        log "  Continuing with remaining steps..."
    fi
}

# --- Step 2: Generate MITRE Lookup ---
step2_mitre_lookup() {
    log_section "STEP 2: Generate MITRE Lookup"
    log "Running: generate-mitre-lookup.py"

    if python3 "${SCRIPT_DIR}/generate-mitre-lookup.py" 2>&1 | tee -a "$LOG_FILE"; then
        log "Step 2 COMPLETE: MITRE lookup generated"
        local rows
        rows=$(wc -l < /opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv 2>/dev/null || echo "0")
        log "  Lookup rows: $((rows - 1)) (excluding header)"
    else
        log_error "Step 2 FAILED: MITRE lookup generation had errors"
    fi
}

# --- Step 3: Generate Saved Searches ---
step3_saved_searches() {
    log_section "STEP 3: Generate Saved Searches"
    log "Running: generate-savedsearches.py"

    if python3 "${SCRIPT_DIR}/generate-savedsearches.py" 2>&1 | tee -a "$LOG_FILE"; then
        log "Step 3 COMPLETE: Saved searches generated"
        local stanzas
        stanzas=$(grep -c '^\[' /opt/caldera-splunk/siem/siem_usecases_savedsearches.conf 2>/dev/null || echo "0")
        log "  Saved search stanzas: $stanzas"
    else
        log_error "Step 3 FAILED: Saved search generation had errors"
    fi
}

# --- Step 4: Publish to Splunk ---
step4_publish() {
    log_section "STEP 4: Publish to Splunk"

    if [[ -x "${SCRIPT_DIR}/publish-to-splunk.sh" ]]; then
        log "Running: publish-to-splunk.sh"
        if bash "${SCRIPT_DIR}/publish-to-splunk.sh" 2>&1 | tee -a "$LOG_FILE"; then
            log "Step 4 COMPLETE: Data published to Splunk"
        else
            log_error "Step 4 had issues but continued"
        fi
    else
        log "  publish-to-splunk.sh not found or not executable, skipping"
    fi
}

# --- Step 5: Copy to GitHub repo ---
step5_copy_repo() {
    log_section "STEP 5: Copy to GitHub Repository"

    # Copy scripts
    for script in generate-adversary-profiles.py generate-mitre-lookup.py generate-savedsearches.py deploy-siem-framework.sh; do
        if [[ -f "${SCRIPT_DIR}/${script}" ]]; then
            cp "${SCRIPT_DIR}/${script}" "${REPO_DIR}/scripts/${script}" 2>/dev/null || \
            cp "${SCRIPT_DIR}/${script}" "${REPO_DIR}/${script}" 2>/dev/null || true
            log "  Copied: ${script}"
        fi
    done

    # Copy lookup
    if [[ -f "/opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv" ]]; then
        mkdir -p "${REPO_DIR}/caldera"
        cp /opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv "${REPO_DIR}/caldera/" 2>/dev/null || true
        log "  Copied: mitre_attack_bank_mapping.csv"
    fi

    # Copy saved searches
    if [[ -f "/opt/caldera-splunk/siem/siem_usecases_savedsearches.conf" ]]; then
        cp /opt/caldera-splunk/siem/siem_usecases_savedsearches.conf "${REPO_DIR}/" 2>/dev/null || true
        log "  Copied: siem_usecases_savedsearches.conf"
    fi

    # Copy adversary profiles
    for profile in /opt/caldera/data/adversaries/bank-*.yml; do
        if [[ -f "$profile" ]]; then
            cp "$profile" "${REPO_DIR}/caldera/adversaries/" 2>/dev/null || true
        fi
    done
    log "  Copied adversary profiles"

    log "Step 5 COMPLETE: Files copied to ${REPO_DIR}"
}

# --- Final Summary ---
summary() {
    log_section "DEPLOYMENT SUMMARY"

    log "Adversary Profiles:"
    ls -1 /opt/caldera/data/adversaries/bank-*-advanced.yml /opt/caldera/data/adversaries/bank-credential-access.yml /opt/caldera/data/adversaries/bank-discovery-recon.yml /opt/caldera/data/adversaries/bank-command-control.yml 2>/dev/null | while read f; do
        log "  $(basename "$f")"
    done

    log ""
    log "MITRE Lookup:"
    local rows
    rows=$(wc -l < /opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv 2>/dev/null || echo "0")
    log "  Entries: $((rows - 1))"

    log ""
    log "Saved Searches:"
    local stanzas
    stanzas=$(grep -c '^\[' /opt/caldera-splunk/siem/siem_usecases_savedsearches.conf 2>/dev/null || echo "0")
    log "  Stanzas: $stanzas"

    log ""
    log "Log file: $LOG_FILE"
    log ""
    log "Framework deployment complete."
}

# --- Main ---
main() {
    log_section "BANK SIEM USE CASE & ADVERSARY FRAMEWORK DEPLOYMENT"
    log "Started at $(date)"
    log "Working directory: ${SCRIPT_DIR}"
    log ""

    preflight
    step1_adversary_profiles
    step2_mitre_lookup
    step3_saved_searches
    step4_publish
    step5_copy_repo
    summary

    log ""
    log "All steps completed at $(date)"
}

# Allow running individual steps
case "${1:-all}" in
    all)        main ;;
    preflight)  preflight ;;
    profiles)   step1_adversary_profiles ;;
    lookup)     step2_mitre_lookup ;;
    searches)   step3_saved_searches ;;
    publish)    step4_publish ;;
    repo)       step5_copy_repo ;;
    *)
        echo "Usage: $0 [all|preflight|profiles|lookup|searches|publish|repo]"
        exit 1
        ;;
esac
