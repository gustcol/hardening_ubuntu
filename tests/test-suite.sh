#!/bin/bash
# Ubuntu Hardening Suite - Comprehensive Test Suite
# Tests script syntax, structure, and configuration consistency
# Can be run locally without root or an Ubuntu target

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0
WARN=0

pass() {
    PASS=$((PASS + 1))
    echo -e "${GREEN}  PASS${NC} $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo -e "${RED}  FAIL${NC} $1"
}

warn() {
    WARN=$((WARN + 1))
    echo -e "${YELLOW}  WARN${NC} $1"
}

section() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# ──────────────────────────────────────────────
# 1. Bash Syntax Validation
# ──────────────────────────────────────────────

section "Bash Syntax Validation"

scripts=(
    "ubuntu-hardening-suite.sh"
    "modules/initial-setup.sh"
    "modules/security-hardening.sh"
    "modules/advanced-hardening.sh"
    "modules/cloud-security.sh"
    "modules/cloud-init/generate-image.sh"
    "modules/docker/build-image.sh"
    "test-pam-limits.sh"
)

for script in "${scripts[@]}"; do
    filepath="${SCRIPT_DIR}/${script}"
    if [[ -f "$filepath" ]]; then
        if bash -n "$filepath" 2>/dev/null; then
            pass "Syntax OK: $script"
        else
            fail "Syntax ERROR: $script"
        fi
    else
        fail "File missing: $script"
    fi
done

# ──────────────────────────────────────────────
# 2. File Structure and Permissions
# ──────────────────────────────────────────────

section "File Structure"

required_files=(
    "ubuntu-hardening-suite.sh"
    "modules/initial-setup.sh"
    "modules/security-hardening.sh"
    "modules/advanced-hardening.sh"
    "modules/cloud-security.sh"
    "modules/cloud-init/generate-image.sh"
    "modules/docker/build-image.sh"
    "configs/default.conf"
    "configs/ubuntu-18.04.conf"
    "configs/ubuntu-20.04.conf"
    "configs/ubuntu-22.04.conf"
    "configs/ubuntu-24.04.conf"
    "configs/ubuntu-25.04.conf"
    "configs/ubuntu-25.10.conf"
    "test-pam-limits.sh"
    "README.md"
    "LICENSE"
)

for file in "${required_files[@]}"; do
    if [[ -f "${SCRIPT_DIR}/${file}" ]]; then
        pass "Exists: $file"
    else
        fail "Missing: $file"
    fi
done

# ──────────────────────────────────────────────
# 3. Shebang and Safety Headers
# ──────────────────────────────────────────────

section "Shebang and Safety Headers"

for script in "${scripts[@]}"; do
    filepath="${SCRIPT_DIR}/${script}"
    [[ ! -f "$filepath" ]] && continue

    # Check shebang
    first_line=$(head -1 "$filepath")
    if [[ "$first_line" == "#!/bin/bash" ]] || [[ "$first_line" == "#!/usr/bin/env bash" ]]; then
        pass "Shebang OK: $script"
    else
        fail "Missing/wrong shebang: $script (got: $first_line)"
    fi
done

# Check main script has set -euo pipefail
if grep -q "set -euo pipefail" "${SCRIPT_DIR}/ubuntu-hardening-suite.sh"; then
    pass "Main script uses strict mode (set -euo pipefail)"
else
    fail "Main script missing strict mode"
fi

# ──────────────────────────────────────────────
# 4. Configuration Consistency
# ──────────────────────────────────────────────

section "Configuration Consistency"

# Check all supported versions have config files
supported_versions=("18.04" "20.04" "22.04" "24.04" "25.04" "25.10")

for ver in "${supported_versions[@]}"; do
    conf="${SCRIPT_DIR}/configs/ubuntu-${ver}.conf"
    if [[ -f "$conf" ]]; then
        pass "Config exists for Ubuntu ${ver}"

        # Check required variables
        for var in UBUNTU_VERSION UBUNTU_CODENAME TIME_SYNC_SERVICE KERNEL_VERSION; do
            if grep -q "^${var}=" "$conf"; then
                pass "  ${var} defined in ubuntu-${ver}.conf"
            else
                fail "  ${var} MISSING in ubuntu-${ver}.conf"
            fi
        done

        # Check no duplicate TIME_SYNC_SERVICE
        count=$(grep -c "^TIME_SYNC_SERVICE=" "$conf" 2>/dev/null || echo 0)
        if [[ "$count" -le 1 ]]; then
            pass "  No duplicate TIME_SYNC_SERVICE in ubuntu-${ver}.conf"
        else
            fail "  Duplicate TIME_SYNC_SERVICE in ubuntu-${ver}.conf (found ${count} occurrences)"
        fi
    else
        fail "Config missing for Ubuntu ${ver}"
    fi
done

# ──────────────────────────────────────────────
# 5. Version-Specific Kernel Validation
# ──────────────────────────────────────────────

section "Kernel Version Validation"

declare -A expected_kernels=(
    ["18.04"]="4.15"
    ["20.04"]="5.4"
    ["22.04"]="5.15"
    ["24.04"]="6.8"
    ["25.04"]="6.14"
    ["25.10"]="6.17"
)

for ver in "${!expected_kernels[@]}"; do
    conf="${SCRIPT_DIR}/configs/ubuntu-${ver}.conf"
    if [[ -f "$conf" ]]; then
        actual=$(grep "^KERNEL_VERSION=" "$conf" | cut -d'"' -f2)
        expected="${expected_kernels[$ver]}"
        if [[ "$actual" == "$expected" ]]; then
            pass "Kernel version correct for Ubuntu ${ver}: ${actual}"
        else
            fail "Kernel version wrong for Ubuntu ${ver}: got ${actual}, expected ${expected}"
        fi
    fi
done

# ──────────────────────────────────────────────
# 6. Function Definition Checks
# ──────────────────────────────────────────────

section "Function Definition Checks"

# Check that print_success is NOT used (was a known bug)
for script in "${scripts[@]}"; do
    filepath="${SCRIPT_DIR}/${script}"
    [[ ! -f "$filepath" ]] && continue

    if grep -q "print_success" "$filepath"; then
        fail "Undefined function 'print_success' found in $script"
    else
        pass "No undefined 'print_success' in $script"
    fi
done

# Check SSH service name (should be 'ssh' not 'sshd' on Ubuntu)
for script in "${scripts[@]}"; do
    filepath="${SCRIPT_DIR}/${script}"
    [[ ! -f "$filepath" ]] && continue

    if grep -q "systemctl restart sshd" "$filepath"; then
        fail "Wrong service name 'sshd' in $script (Ubuntu uses 'ssh')"
    fi
done
pass "SSH service name check passed (no 'systemctl restart sshd' found)"

# ──────────────────────────────────────────────
# 7. Security Checks
# ──────────────────────────────────────────────

section "Security Checks"

# Check that ecryptfs-utils is NOT in base packages (deprecated)
if grep -q "ecryptfs-utils" "${SCRIPT_DIR}/ubuntu-hardening-suite.sh"; then
    fail "Deprecated ecryptfs-utils found in base packages"
else
    pass "ecryptfs-utils not in base packages (correctly removed)"
fi

# Check that auditd.conf does NOT open TCP listener
sec_hardening="${SCRIPT_DIR}/modules/security-hardening.sh"
if [[ -f "$sec_hardening" ]]; then
    if grep -q "tcp_listen_port" "$sec_hardening"; then
        fail "auditd.conf opens TCP listener (security issue)"
    else
        pass "auditd.conf does not open TCP listener"
    fi

    # Check that deprecated stime syscall is removed
    if grep -q "\-S stime" "$sec_hardening"; then
        fail "Deprecated 'stime' syscall found in audit rules"
    else
        pass "No deprecated 'stime' syscall in audit rules"
    fi

    # Check Debian-only sysctl is removed
    if grep -q "unprivileged_userns_clone" "$sec_hardening"; then
        fail "Debian-only sysctl 'unprivileged_userns_clone' found"
    else
        pass "No Debian-only 'unprivileged_userns_clone' sysctl"
    fi
fi

# Check SSH hardening uses sshd_config.d (not append to sshd_config)
initial_setup="${SCRIPT_DIR}/modules/initial-setup.sh"
if [[ -f "$initial_setup" ]]; then
    if grep -q "sshd_config.d" "$initial_setup"; then
        pass "SSH hardening uses drop-in config (sshd_config.d)"
    else
        warn "SSH hardening may append to sshd_config directly"
    fi

    # Check ChallengeResponseAuthentication is replaced
    if grep -q "ChallengeResponseAuthentication" "$initial_setup"; then
        fail "Deprecated ChallengeResponseAuthentication found (use KbdInteractiveAuthentication)"
    else
        pass "No deprecated ChallengeResponseAuthentication"
    fi
fi

# Check Docker Compose version key
docker_build="${SCRIPT_DIR}/modules/docker/build-image.sh"
if [[ -f "$docker_build" ]]; then
    if grep -q "^version:" "$docker_build" || grep -q "version: '3" "$docker_build"; then
        fail "Docker Compose 'version' key is obsolete"
    else
        pass "No obsolete Docker Compose 'version' key"
    fi
fi

# ──────────────────────────────────────────────
# 8. Advanced Hardening Logic
# ──────────────────────────────────────────────

section "Advanced Hardening Logic"

main_script="${SCRIPT_DIR}/ubuntu-hardening-suite.sh"
if [[ -f "$main_script" ]]; then
    # Verify advanced hardening doesn't run with COMPONENTS=all alone
    advanced_func=$(sed -n '/^run_advanced_hardening()/,/^}/p' "$main_script")

    if echo "$advanced_func" | grep -q '"advanced-hardening"'; then
        pass "Advanced hardening requires explicit --advanced or component selection"
    else
        warn "Advanced hardening logic may need review"
    fi
fi

# Check ksmbd is NOT in filesystem list
adv_hardening="${SCRIPT_DIR}/modules/advanced-hardening.sh"
if [[ -f "$adv_hardening" ]]; then
    fs_line=$(grep 'local filesystems=' "$adv_hardening" 2>/dev/null || true)
    if echo "$fs_line" | grep -q "ksmbd"; then
        fail "ksmbd still in filesystem list (should be in hardware modules)"
    else
        pass "ksmbd correctly NOT in filesystem list"
    fi
fi

# ──────────────────────────────────────────────
# 9. Cloud Security Checks
# ──────────────────────────────────────────────

section "Cloud Security Checks"

cloud_sec="${SCRIPT_DIR}/modules/cloud-security.sh"
if [[ -f "$cloud_sec" ]]; then
    # Check CLOUD_PROVIDER default guard
    if grep -q 'CLOUD_PROVIDER=.*:-' "$cloud_sec"; then
        pass "CLOUD_PROVIDER has default guard against unset variable"
    else
        warn "CLOUD_PROVIDER may fail under set -u if unset"
    fi
fi

# ──────────────────────────────────────────────
# 10. Version Consistency
# ──────────────────────────────────────────────

section "Version Consistency"

if [[ -f "$main_script" ]]; then
    script_ver=$(grep 'SCRIPT_VERSION=' "$main_script" | head -1 | cut -d'"' -f2)
    header_ver=$(grep '# Version:' "$main_script" | head -1 | sed 's/.*Version: //')
    if [[ "$script_ver" == "$header_ver" ]]; then
        pass "Script version consistent (header=$header_ver, variable=$script_ver)"
    else
        fail "Version mismatch: header=$header_ver, variable=$script_ver"
    fi
fi

# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

echo ""
echo -e "${BLUE}══════════════════════════════════════════${NC}"
echo -e "${BLUE}  Test Suite Summary${NC}"
echo -e "${BLUE}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${RED}Failed:${NC}  $FAIL"
echo -e "  ${YELLOW}Warned:${NC}  $WARN"
echo -e "  Total:   $((PASS + FAIL + WARN))"
echo -e "${BLUE}══════════════════════════════════════════${NC}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n${RED}Some tests FAILED. Review the output above.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
fi
