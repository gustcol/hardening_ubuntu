#!/bin/bash
# Test script to verify PAM limits configuration
# This script checks if the PAM limits from lines 62-69 are properly applied

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if a line exists in a file
check_line_in_file() {
    local file=$1
    local pattern=$2
    local description=$3

    if grep -q "$pattern" "$file" 2>/dev/null; then
        print_message "$GREEN" "✓ $description"
        return 0
    else
        print_message "$RED" "✗ $description"
        return 1
    fi
}

# Function to test PAM limits configuration
test_pam_limits() {
    print_message "$BLUE" "Testing PAM limits configuration..."

    local errors=0

    # Test /etc/security/limits.conf
    print_message "$YELLOW" "Checking /etc/security/limits.conf..."

    # Check for soft nproc limits
    if ! check_line_in_file "/etc/security/limits.conf" "\* soft.*nproc.*65535" "Soft nproc limit for all users (65535)"; then
        ((errors++))
    fi

    if ! check_line_in_file "/etc/security/limits.conf" "\* hard.*nproc.*65535" "Hard nproc limit for all users (65535)"; then
        ((errors++))
    fi

    if ! check_line_in_file "/etc/security/limits.conf" "\* soft.*nofile.*65535" "Soft nofile limit for all users (65535)"; then
        ((errors++))
    fi

    if ! check_line_in_file "/etc/security/limits.conf" "\* hard.*nofile.*65535" "Hard nofile limit for all users (65535)"; then
        ((errors++))
    fi

    # Check for root user limits
    if ! check_line_in_file "/etc/security/limits.conf" "root soft.*nproc.*65535" "Soft nproc limit for root (65535)"; then
        ((errors++))
    fi

    if ! check_line_in_file "/etc/security/limits.conf" "root hard.*nproc.*65535" "Hard nproc limit for root (65535)"; then
        ((errors++))
    fi

    if ! check_line_in_file "/etc/security/limits.conf" "root soft.*nofile.*65535" "Soft nofile limit for root (65535)"; then
        ((errors++))
    fi

    if ! check_line_in_file "/etc/security/limits.conf" "root hard.*nofile.*65535" "Hard nofile limit for root (65535)"; then
        ((errors++))
    fi

    # Test PAM session configuration
    print_message "$YELLOW" "Checking PAM session configuration..."

    if ! check_line_in_file "/etc/pam.d/common-session" "session required pam_limits.so" "PAM session limits module"; then
        ((errors++))
    fi

    # Test current session limits
    print_message "$YELLOW" "Testing current session limits..."

    # Get current limits
    local current_nproc=$(ulimit -u 2>/dev/null || echo "unknown")
    local current_nofile=$(ulimit -n 2>/dev/null || echo "unknown")

    print_message "$BLUE" "Current session limits:"
    print_message "$BLUE" "  Max processes (nproc): $current_nproc"
    print_message "$BLUE" "  Max open files (nofile): $current_nofile"

    # Test if limits are applied correctly
    if [[ "$current_nproc" == "65535" ]]; then
        print_message "$GREEN" "✓ Current nproc limit is correctly set to 65535"
    else
        print_message "$YELLOW" "⚠ Current nproc limit is $current_nproc (expected 65535)"
        print_message "$YELLOW" "  This may require a new session or reboot to take effect"
    fi

    if [[ "$current_nofile" == "65535" ]]; then
        print_message "$GREEN" "✓ Current nofile limit is correctly set to 65535"
    else
        print_message "$YELLOW" "⚠ Current nofile limit is $current_nofile (expected 65535)"
        print_message "$YELLOW" "  This may require a new session or reboot to take effect"
    fi

    # Test system-wide limits
    print_message "$YELLOW" "Checking system-wide limits..."

    if [[ -f "/proc/sys/fs/file-max" ]]; then
        local file_max=$(cat /proc/sys/fs/file-max)
        print_message "$BLUE" "  System file-max: $file_max"
        if [[ $file_max -ge 65535 ]]; then
            print_message "$GREEN" "✓ System file-max is sufficient"
        else
            print_message "$YELLOW" "⚠ System file-max may be too low"
        fi
    fi

    # Test PAM configuration files
    print_message "$YELLOW" "Checking PAM configuration files..."

    local pam_files=(
        "/etc/pam.d/common-session"
        "/etc/pam.d/common-session-noninteractive"
        "/etc/pam.d/sshd"
        "/etc/pam.d/login"
    )

    for pam_file in "${pam_files[@]}"; do
        if [[ -f "$pam_file" ]]; then
            if grep -q "pam_limits" "$pam_file" 2>/dev/null; then
                print_message "$GREEN" "✓ PAM limits found in $pam_file"
            else
                print_message "$YELLOW" "⚠ No PAM limits found in $pam_file"
            fi
        else
            print_message "$YELLOW" "⚠ PAM file not found: $pam_file"
        fi
    done

    # Summary
    print_message "$BLUE" "\n=== Test Summary ==="
    if [[ $errors -eq 0 ]]; then
        print_message "$GREEN" "✓ All PAM limits tests passed!"
        print_message "$GREEN" "The limits configuration from lines 62-69 is properly applied."
        return 0
    else
        print_message "$RED" "✗ $errors test(s) failed."
        print_message "$YELLOW" "Some PAM limits may not be properly configured."
        print_message "$YELLOW" "Try running: sudo pam-auth-update --force"
        print_message "$YELLOW" "Or restart your session/system."
        return 1
    fi
}

# Function to test Docker limits (if running in container)
test_docker_limits() {
    if [[ -f "/.dockerenv" ]] || grep -q "docker" /proc/1/cgroup 2>/dev/null; then
        print_message "$BLUE" "Detected Docker environment - testing container limits..."

        # Check if limits are configured in container
        if [[ -f "/etc/security/limits.conf" ]]; then
            print_message "$YELLOW" "Container limits.conf:"
            grep -E "(nproc|nofile).*65535" /etc/security/limits.conf 2>/dev/null || print_message "$YELLOW" "No 65535 limits found"
        fi

        if [[ -f "/etc/pam.d/common-session" ]]; then
            if grep -q "pam_limits" /etc/pam.d/common-session; then
                print_message "$GREEN" "✓ PAM limits configured in container"
            else
                print_message "$YELLOW" "⚠ PAM limits not configured in container"
            fi
        fi
    fi
}

# Function to show remediation steps
show_remediation() {
    print_message "$BLUE" "\n=== Remediation Steps ==="
    print_message "$YELLOW" "If limits are not working, try:"
    print_message "$YELLOW" "1. Edit /etc/security/limits.conf and add:"
    print_message "$WHITE" "   * soft nproc 65535"
    print_message "$WHITE" "   * hard nproc 65535"
    print_message "$WHITE" "   * soft nofile 65535"
    print_message "$WHITE" "   * hard nofile 65535"
    print_message "$WHITE" "   root soft nproc 65535"
    print_message "$WHITE" "   root hard nproc 65535"
    print_message "$WHITE" "   root soft nofile 65535"
    print_message "$WHITE" "   root hard nofile 65535"
    print_message "$YELLOW" "2. Edit /etc/pam.d/common-session and add:"
    print_message "$WHITE" "   session required pam_limits.so"
    print_message "$YELLOW" "3. Restart your session or reboot the system"
    print_message "$YELLOW" "4. Verify with: ulimit -u && ulimit -n"
}

# Main function
main() {
    print_message "$BLUE" "=== PAM Limits Configuration Test ==="
    print_message "$BLUE" "Testing the limits configuration from lines 62-69..."
    print_message "$BLUE" ""

    # Check if running as root (needed for some tests)
    if [[ $EUID -ne 0 ]]; then
        print_message "$YELLOW" "Warning: Some tests may require root privileges"
        print_message "$YELLOW" "Consider running with sudo for complete testing"
        print_message "$YELLOW" ""
    fi

    # Run tests
    test_pam_limits
    local test_result=$?

    test_docker_limits

    # Show remediation if needed
    if [[ $test_result -ne 0 ]]; then
        show_remediation
    fi

    print_message "$BLUE" "\n=== Test Complete ==="

    return $test_result
}

# Run main function
main "$@"
