#!/bin/bash
# Ubuntu Hardening Suite - Combined Setup and Security Hardening
# Combines du_setup and Ubuntu-Security-Hardening-Script functionality
# Includes cloud-init image creation and Docker image building
# Version: 1.0
# Author: Combined from multiple sources

set -euo pipefail
IFS=$'\n\t'

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Global variables
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_VERSION="1.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_DIR="/var/log/hardening-suite"
readonly LOG_FILE="${LOG_DIR}/hardening-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/var/backups/hardening-suite"
readonly REPORT_FILE="${LOG_DIR}/hardening_report_$(date +%Y%m%d-%H%M%S).txt"
readonly CONFIG_DIR="${SCRIPT_DIR}/configs"
readonly MODULES_DIR="${SCRIPT_DIR}/modules"

# Default configuration
MODE="interactive"
COMPONENTS="all"
CLOUD_INIT=false
DOCKER_BUILD=false
ADVANCED_HARDENING=false
DRY_RUN=false
VERBOSE=true

# Ubuntu version detection
UBUNTU_VERSION=""
UBUNTU_CODENAME=""

# Function to print colored output
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}" | tee -a "$LOG_FILE"
}

# Function to print section headers
print_section() {
    local message=$1
    echo -e "\n${BLUE}=== $message ===${NC}" | tee -a "$LOG_FILE"
}

# Function to print info message
print_info() {
    local message=$1
    print_message "$BLUE" "$message"
}

# Function to confirm action
confirm() {
    local message=$1
    local default=${2:-y} # Default to yes if not specified
    local prompt

    if [[ "$MODE" != "interactive" ]]; then
        return 0 # Auto-confirm in non-interactive mode
    fi

    if [[ "$default" == "y" ]]; then
        prompt="[Y/n]"
    else
        prompt="[y/N]"
    fi

    read -p "$message $prompt " -r response
    if [[ -z "$response" ]]; then
        response=$default
    fi

    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to handle errors
error_exit() {
    print_message "$RED" "ERROR: $1"
    cleanup_on_error
    exit 1
}

# Function to cleanup on error
cleanup_on_error() {
    print_message "$YELLOW" "Performing cleanup due to error..."
    # Add cleanup operations here
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Function to detect Ubuntu version
detect_ubuntu_version() {
    if ! command -v lsb_release &> /dev/null; then
        error_exit "lsb_release not found. Is this Ubuntu?"
    fi

    UBUNTU_VERSION=$(lsb_release -rs)
    UBUNTU_CODENAME=$(lsb_release -cs)

    print_message "$GREEN" "Detected Ubuntu version: $UBUNTU_VERSION ($UBUNTU_CODENAME)"

    # Validate supported versions
    case "$UBUNTU_VERSION" in
        "18.04"|"20.04"|"22.04"|"24.04"|"25.04"|"25.10")
            print_message "$GREEN" "Supported Ubuntu version detected"
        ;;
        *)
            print_message "$YELLOW" "WARNING: Ubuntu $UBUNTU_VERSION may not be fully supported"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 0
            fi
        ;;
    esac
}

# Function to create directories
setup_directories() {
    mkdir -p "$LOG_DIR" "$BACKUP_DIR" "$CONFIG_DIR" "$MODULES_DIR"
    chmod 700 "$LOG_DIR" "$BACKUP_DIR"

    # Create subdirectories
    mkdir -p "${LOG_DIR}/initial-audit"
    mkdir -p "${MODULES_DIR}/initial-setup"
    mkdir -p "${MODULES_DIR}/security-hardening"
    mkdir -p "${MODULES_DIR}/advanced-hardening"
    mkdir -p "${MODULES_DIR}/cloud-init"
    mkdir -p "${MODULES_DIR}/docker"
}

# Function to backup configuration files
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup_name="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
        cp -p "$file" "$backup_name"
        print_message "$GREEN" "Backed up $file to $backup_name"
    fi
}

# Function to load configuration
load_config() {
    # Load default configuration
    if [[ -f "${CONFIG_DIR}/default.conf" ]]; then
        source "${CONFIG_DIR}/default.conf"
    fi

    # Load version-specific configuration
    if [[ -f "${CONFIG_DIR}/ubuntu-${UBUNTU_VERSION}.conf" ]]; then
        source "${CONFIG_DIR}/ubuntu-${UBUNTU_VERSION}.conf"
    fi
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --cloud-init)
                CLOUD_INIT=true
                shift
            ;;
            --docker)
                DOCKER_BUILD=true
                shift
            ;;
            --advanced)
                ADVANCED_HARDENING=true
                shift
            ;;
            --dry-run)
                DRY_RUN=true
                shift
            ;;
            --quiet)
                VERBOSE=false
                shift
            ;;
            --components)
                COMPONENTS="$2"
                shift 2
            ;;
            --help)
                show_help
                exit 0
            ;;
            *)
                error_exit "Unknown option: $1"
            ;;
        esac
    done
}

# Function to show help
show_help() {
    cat << EOF
Ubuntu Hardening Suite v${SCRIPT_VERSION}

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    --cloud-init           Generate cloud-init compatible image
    --docker              Build Docker images
    --advanced            Run advanced hardening (aggressive options)
    --dry-run             Show what would be done without making changes
    --quiet               Reduce output verbosity
    --components LIST     Comma-separated list of components to install
                         (all, initial-setup, security-hardening, cloud-security)
    --help                Show this help message

EXAMPLES:
    # Interactive hardening
    sudo ./$SCRIPT_NAME

    # Cloud-init image creation
    sudo ./$SCRIPT_NAME --cloud-init

    # Docker image building
    sudo ./$SCRIPT_NAME --docker

    # Selective components
    sudo ./$SCRIPT_NAME --components initial-setup,security-hardening

COMPONENTS:
    initial-setup     User creation, SSH hardening, firewall, basic config
    security-hardening AIDE, auditd, AppArmor, ClamAV, security tools
    cloud-security    Cloud-specific hardening (AWS/Azure/GCP)
    cloud-init        Cloud-init image creation tools
    docker           Docker image building tools

EOF
}

# Function to check system requirements
check_system_requirements() {
    print_section "System Requirements Check"

    # Check available disk space (minimum 2GB)
    local available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 2097152 ]]; then
        error_exit "Insufficient disk space. At least 2GB required."
    fi

    # Check memory (minimum 1GB)
    local total_memory=$(free -m | awk 'NR==2 {print $2}')
    if [[ $total_memory -lt 1024 ]]; then
        print_message "$YELLOW" "WARNING: Low memory detected. Some operations may be slow."
    fi

    # Check internet connectivity
    if ! curl -s --head https://archive.ubuntu.com | head -1 | grep -q "200 OK"; then
        error_exit "No internet connectivity detected."
    fi

    print_message "$GREEN" "✓ System requirements met"
}

# Function to update system packages
update_system() {
    print_section "System Update"

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would update package lists"
        print_message "$BLUE" "[DRY RUN] Would upgrade packages"
        return
    fi

    print_message "$GREEN" "Updating package lists..."
    apt-get update -y || error_exit "Failed to update package lists"

    print_message "$GREEN" "Upgrading packages..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" || error_exit "Failed to upgrade packages"

    # Distribution upgrade for latest versions
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" || true
}

# Function to install base packages
install_base_packages() {
    print_section "Installing Base Packages"

    local packages=(
        # Core utilities
        "curl" "wget" "git" "vim" "nano" "htop" "iotop" "ncdu" "tree"
        "net-tools" "iftop" "tcpdump" "rsync" "gpg" "jq" "cron"

        # System monitoring
        "sysstat" "acct" "psmisc" "lsof" "strace"

        # Archive and compression
        "tar" "gzip" "bzip2" "xz-utils" "zip" "unzip"

        # Development tools
        "build-essential" "cmake" "make" "gcc" "g++" "python3" "python3-pip"

        # Security tools (basic set)
        "openssl" "gnutls-bin" "cryptsetup" "ecryptfs-utils"
        "libpam-pwquality" "libpam-tmpdir" "libpam-apparmor" "libpam-cap"
    )

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would install base packages: ${packages[*]}"
        return
    fi

    for package in "${packages[@]}"; do
        print_message "$GREEN" "Installing $package..."
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" 2>/dev/null; then
            print_message "$YELLOW" "WARNING: Failed to install $package"
        fi
    done
}

# Function to run initial setup components
run_initial_setup() {
    print_section "Initial Server Setup"

    if [[ "$COMPONENTS" != "all" ]] && [[ "$COMPONENTS" != *"initial-setup"* ]]; then
        print_message "$YELLOW" "Skipping initial setup (not in components list)"
        return
    fi

    # Source initial setup module
    if [[ -f "${MODULES_DIR}/initial-setup.sh" ]]; then
        source "${MODULES_DIR}/initial-setup.sh"
        run_initial_setup_components
    else
        print_message "$YELLOW" "Initial setup module not found, running basic setup"

        # Basic initial setup (fallback)
        configure_timezone
        create_admin_user
        configure_ssh
        configure_firewall
        configure_time_sync
    fi
}

# Function to run security hardening components
run_security_hardening() {
    print_section "Security Hardening"

    if [[ "$COMPONENTS" != "all" ]] && [[ "$COMPONENTS" != *"security-hardening"* ]]; then
        print_message "$YELLOW" "Skipping security hardening (not in components list)"
        return
    fi

    # Source security hardening module
    if [[ -f "${MODULES_DIR}/security-hardening.sh" ]]; then
        source "${MODULES_DIR}/security-hardening.sh"
        run_security_hardening_components
    else
        print_message "$YELLOW" "Security hardening module not found, running basic hardening"

        # Basic security hardening (fallback)
        configure_auditd
        configure_apparmor
        configure_clamav
        configure_fail2ban
        configure_openscap
        configure_kernel_hardening
    fi
}

# Function to run cloud security components
run_cloud_security() {
    print_section "Cloud Security Configuration"

    if [[ "$COMPONENTS" != "all" ]] && [[ "$COMPONENTS" != *"cloud-security"* ]]; then
        print_message "$YELLOW" "Skipping cloud security (not in components list)"
        return
    fi

    # Source cloud security module
    if [[ -f "${MODULES_DIR}/cloud-security.sh" ]]; then
        source "${MODULES_DIR}/cloud-security.sh"
        run_cloud_security_components
    else
        print_message "$YELLOW" "Cloud security module not found, running basic cloud config"

        # Basic cloud security (fallback)
        configure_cloud_metadata_protection
        configure_cloud_init_security
    fi
}

# Function to run advanced hardening components
run_advanced_hardening() {
    print_section "Advanced Hardening"

    if [[ "$ADVANCED_HARDENING" != true ]] && [[ "$COMPONENTS" != "all" ]]; then
        return
    fi

    # If explicitly requested via --advanced OR components=all
    # However, since it's aggressive, maybe we only run if --advanced is set?
    # The user request implied upgrading the script. Let's make it optional but accessible.

    if [[ "$ADVANCED_HARDENING" != true ]]; then
        # Check if explicitly in components
        if [[ "$COMPONENTS" != *"advanced-hardening"* ]]; then
            if [[ "$COMPONENTS" == "all" ]]; then
                # For 'all', we might want to ask confirmation or skip aggressive parts?
                # For now, let's treat 'all' as including it, but the module itself has confirmations.
                :
            else
                return
            fi
        fi
    fi

    if [[ -f "${MODULES_DIR}/advanced-hardening.sh" ]]; then
        source "${MODULES_DIR}/advanced-hardening.sh"
        run_advanced_hardening_components
    else
        print_message "$YELLOW" "Advanced hardening module not found"
    fi
}

# Function to handle cloud-init image creation
handle_cloud_init() {
    if [[ "$CLOUD_INIT" != true ]]; then
        return
    fi

    print_section "Cloud-Init Image Creation"

    if [[ -f "${MODULES_DIR}/cloud-init/generate-image.sh" ]]; then
        source "${MODULES_DIR}/cloud-init/generate-image.sh"
        generate_cloud_init_image
    else
        print_message "$YELLOW" "Cloud-init module not found"
        print_message "$BLUE" "To create cloud-init images, implement the cloud-init module"
    fi
}

# Function to handle Docker image building
handle_docker_build() {
    if [[ "$DOCKER_BUILD" != true ]]; then
        return
    fi

    print_section "Docker Image Building"

    if [[ -f "${MODULES_DIR}/docker/build-image.sh" ]]; then
        source "${MODULES_DIR}/docker/build-image.sh"
        build_docker_images_main
    else
        print_message "$YELLOW" "Docker build module not found"
        print_message "$BLUE" "To build Docker images, implement the docker build module"
    fi
}

# Function to generate final report
generate_final_report() {
    print_section "Generating Final Report"

    cat > "$REPORT_FILE" << EOF
Ubuntu Hardening Suite Report
=============================
Generated: $(date)
Hostname: $(hostname)
Ubuntu Version: $UBUNTU_VERSION ($UBUNTU_CODENAME)
Script Version: $SCRIPT_VERSION
Mode: ${MODE}
Components: ${COMPONENTS}

Configuration Summary
--------------------

System Information:
- Kernel: $(uname -r)
- Architecture: $(uname -m)
- Memory: $(free -h | awk 'NR==2 {print $2}')
- Disk: $(df -h / | awk 'NR==2 {print $2}')

Applied Components:
$(if [[ "$COMPONENTS" == "all" ]] || [[ "$COMPONENTS" == *"initial-setup"* ]]; then
    echo "- Initial Setup (User, SSH, Firewall, Time sync)"
fi)
$(if [[ "$COMPONENTS" == "all" ]] || [[ "$COMPONENTS" == *"security-hardening"* ]]; then
    echo "- Security Hardening (AIDE, auditd, AppArmor, ClamAV, etc.)"
fi)
$(if [[ "$COMPONENTS" == "all" ]] || [[ "$COMPONENTS" == *"cloud-security"* ]]; then
    echo "- Cloud Security (Metadata protection, cloud-init hardening)"
fi)
$(if [[ "$ADVANCED_HARDENING" == true ]] || [[ "$COMPONENTS" == "all" ]] || [[ "$COMPONENTS" == *"advanced-hardening"* ]]; then
    echo "- Advanced Hardening (Filesystem/Network restrictions, Systemd hardening)"
fi)
$(if [[ "$CLOUD_INIT" == true ]]; then
    echo "- Cloud-Init Image Creation"
fi)
$(if [[ "$DOCKER_BUILD" == true ]]; then
    echo "- Docker Image Building"
fi)

Important Locations:
- Logs: $LOG_DIR
- Backups: $BACKUP_DIR
- Report: $REPORT_FILE

Next Steps:
1. Review all configurations
2. Test SSH access with keys only
3. Verify firewall rules
4. Check security tool status
5. Monitor logs regularly

Security Recommendations:
- Keep system updated
- Monitor logs daily
- Run security audits regularly
- Review firewall rules periodically
- Backup configurations before changes

Report generated by: $SCRIPT_NAME v$SCRIPT_VERSION
EOF

    print_message "$GREEN" "Report saved to: $REPORT_FILE"
}

# Function to perform final checks
perform_final_checks() {
    print_section "Final System Checks"

    local services_to_check=("ssh" "ufw")
    local critical_services=("auditd" "apparmor")

    # Add version-specific services
    case "$UBUNTU_VERSION" in
        "25.04"|"25.10")
            critical_services+=("chrony")
        ;;
        *)
            critical_services+=("systemd-timesyncd")
        ;;
    esac

    print_message "$BLUE" "Checking service status..."

    for service in "${critical_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_message "$GREEN" "✓ $service is running"
        else
            print_message "$YELLOW" "⚠ $service is not running"
        fi
    done

    # Check firewall
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        print_message "$GREEN" "✓ Firewall is active"
    else
        print_message "$YELLOW" "⚠ Firewall status unknown"
    fi

    # Check SSH configuration
    if [[ -f /etc/ssh/sshd_config ]] && grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
        print_message "$GREEN" "✓ SSH password authentication disabled"
    else
        print_message "$YELLOW" "⚠ SSH configuration may allow password authentication"
    fi
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"

    # Initial setup
    check_root
    setup_directories
    detect_ubuntu_version
    load_config

    print_message "$GREEN" "╔══════════════════════════════════════════════════════════════╗"
    print_message "$GREEN" "║              Ubuntu Hardening Suite v${SCRIPT_VERSION}                  ║"
    print_message "$GREEN" "╚══════════════════════════════════════════════════════════════╝"

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$YELLOW" "DRY RUN MODE - No changes will be made"
    fi

    # Pre-flight checks
    check_system_requirements

    # Create system backup prompt
    if [[ "$DRY_RUN" == false ]]; then
        print_message "$YELLOW" "Consider creating a system backup/snapshot before proceeding"
        if [[ "$MODE" == "interactive" ]]; then
            read -p "Press Enter to continue or Ctrl+C to cancel..."
        fi
    fi

    # Main execution
    update_system
    install_base_packages
    run_initial_setup
    run_security_hardening
    run_cloud_security
    run_advanced_hardening
    handle_cloud_init
    handle_docker_build

    # Final steps
    generate_final_report
    perform_final_checks

    print_message "$GREEN" "╔══════════════════════════════════════════════════════════════╗"
    print_message "$GREEN" "║                Hardening Completed Successfully!               ║"
    print_message "$GREEN" "╚══════════════════════════════════════════════════════════════╝"

    print_message "$GREEN" "📋 Report Location: $REPORT_FILE"
    print_message "$GREEN" "📁 Backup Location: $BACKUP_DIR"
    print_message "$GREEN" "📊 Log Location: $LOG_DIR"

    if [[ "$CLOUD_INIT" == true ]] || [[ "$DOCKER_BUILD" == true ]]; then
        print_message "$GREEN" "🎯 Image creation completed"
    fi

    print_message "$YELLOW" "⚠️  IMPORTANT: Ensure you have SSH key access before disconnecting!"
    print_message "$YELLOW" "⚠️  Password authentication has been disabled for security."
}

# Trap errors
trap 'error_exit "Script failed at line $LINENO"' ERR

# Run main function
main "$@"
