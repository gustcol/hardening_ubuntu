#!/bin/bash
# Advanced Security Hardening Module
# Implements aggressive hardening measures for high-security environments
# Based on konstruktoid/hardening logic

# Function to disable unused filesystems
configure_filesystem_restrictions() {
    print_message "$GREEN" "Configuring filesystem restrictions..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would disable unused filesystems"
        return
    fi

    local disable_fs_conf="/etc/modprobe.d/disablefs.conf"
    local filesystems="cramfs freevxfs jffs2 ksmbd hfs hfsplus udf vfat"

    echo "# Ubuntu Hardening Suite - Disabled Filesystems" > "$disable_fs_conf"

    for fs in $filesystems; do
        if ! grep -q "install $fs /bin/true" "$disable_fs_conf"; then
            echo "install $fs /bin/true" >> "$disable_fs_conf"
        fi
    done

    print_message "$GREEN" "Disabled filesystems: $filesystems"
}

# Function to disable unused network protocols
configure_network_restrictions() {
    print_message "$GREEN" "Configuring network protocol restrictions..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would disable unused network protocols"
        return
    fi

    local disable_net_conf="/etc/modprobe.d/disablenet.conf"
    local protocols="dccp sctp rds tipc"

    echo "# Ubuntu Hardening Suite - Disabled Network Protocols" > "$disable_net_conf"

    for proto in $protocols; do
        if ! grep -q "install $proto /bin/true" "$disable_net_conf"; then
            echo "install $proto /bin/true" >> "$disable_net_conf"
        fi
    done

    print_message "$GREEN" "Disabled protocols: $protocols"
}

# Function to disable unused hardware modules
configure_hardware_restrictions() {
    print_message "$GREEN" "Configuring hardware module restrictions..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would disable unused hardware modules"
        return
    fi

    local disable_mod_conf="/etc/modprobe.d/disablemod.conf"
    local modules="bluetooth bnep btusb cpia2 firewire-core floppy n_hdlc net-pf-31 pcspkr soundcore thunderbolt usb-midi usb-storage uvcvideo v4l2_common"

    echo "# Ubuntu Hardening Suite - Disabled Hardware Modules" > "$disable_mod_conf"

    for mod in $modules; do
        if ! grep -q "install $mod /bin/true" "$disable_mod_conf"; then
            echo "install $mod /bin/true" >> "$disable_mod_conf"
        fi
    done

    print_message "$GREEN" "Disabled hardware modules: $modules"
}

# Function to configure systemd hardening
configure_systemd_hardening() {
    print_message "$GREEN" "Configuring systemd hardening..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure systemd hardening"
        return
    fi

    # 1. Disable Coredumps
    local coredump_conf="/etc/systemd/coredump.conf"
    backup_file "$coredump_conf"

    if [[ -f "$coredump_conf" ]]; then
        sed -i 's/^#Storage=.*/Storage=none/' "$coredump_conf"
        sed -i 's/^#ProcessSizeMax=.*/ProcessSizeMax=0/' "$coredump_conf"
    else
        echo -e "[Coredump]\nStorage=none\nProcessSizeMax=0" > "$coredump_conf"
    fi

    # 2. Hardening systemd-resolved
    local resolved_conf="/etc/systemd/resolved.conf"
    backup_file "$resolved_conf"

    if [[ -f "$resolved_conf" ]]; then
        # Enable DNS over TLS if possible
        sed -i 's/^#DNSOverTLS=.*/DNSOverTLS=opportunistic/' "$resolved_conf"
        sed -i 's/^#DNSSEC=.*/DNSSEC=allow-downgrade/' "$resolved_conf"
    fi

    # 3. User session hardening
    local logind_conf="/etc/systemd/logind.conf"
    backup_file "$logind_conf"

    if [[ -f "$logind_conf" ]]; then
        # Kill user processes when session ends
        sed -i 's/^#KillUserProcesses=.*/KillUserProcesses=yes/' "$logind_conf"
        # Lock session on idle
        sed -i 's/^#IdleAction=.*/IdleAction=lock/' "$logind_conf"
        sed -i 's/^#IdleActionSec=.*/IdleActionSec=15min/' "$logind_conf"
    fi

    print_message "$GREEN" "Systemd components hardened (coredump, resolved, logind)"
}

# Function to restrict compiler access
configure_compiler_restrictions() {
    print_message "$GREEN" "Configuring compiler access restrictions..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would restrict compiler access"
        return
    fi

    if ! confirm "Restrict access to compilers (gcc, g++, etc.) to root only?" "n"; then
        print_info "Skipping compiler restrictions"
        return
    fi

    local compilers=$(dpkg-query -L $(dpkg -l | grep compil | awk '{print $2}') 2>/dev/null | grep -E '/bin/.*(gcc|g\+\+|as|cc)$')

    for compiler in $compilers; do
        if [[ -f "$compiler" && -x "$compiler" && ! -L "$compiler" ]]; then
            chmod 0750 "$compiler"
            print_message "$GREEN" "Restricted: $compiler"
        fi
    done

    print_message "$GREEN" "Compiler restrictions applied"
}

# Function to install and configure USBGuard
configure_usbguard() {
    print_message "$GREEN" "Configuring USBGuard..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure USBGuard"
        return
    fi

    if ! confirm "Install USBGuard to whitelist USB devices?" "n"; then
        print_info "Skipping USBGuard configuration"
        return
    fi

    apt-get install -y usbguard

    # Generate initial policy from currently connected devices
    usbguard generate-policy > /etc/usbguard/rules.conf

    systemctl enable usbguard
    systemctl start usbguard

    print_message "$GREEN" "USBGuard installed and enabled with current device policy"
}

# Function to install and configure PSAD
configure_psad() {
    print_message "$GREEN" "Configuring PSAD (Port Scan Attack Detector)..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure PSAD"
        return
    fi

    if ! confirm "Install PSAD for advanced intrusion detection?" "n"; then
        print_info "Skipping PSAD configuration"
        return
    fi

    apt-get install -y psad

    # Update signatures
    psad --sig-update

    # Basic configuration updates could go here
    # sed -i 's/EMAIL_ALERT_DANGER_LEVEL.*/EMAIL_ALERT_DANGER_LEVEL 3;/' /etc/psad/psad.conf

    systemctl restart psad

    print_message "$GREEN" "PSAD installed and configured"
}

# Function to remove legacy and unused services
remove_legacy_services() {
    print_message "$GREEN" "Removing legacy and unused services..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would remove legacy services"
        return
    fi

    # Extended list of unnecessary services and legacy protocols
    local packages=(
        "apport"
        "autofs"
        "avahi-daemon"
        "beep"
        "pastebinit"
        "popularity-contest"
        "prelink"
        "rpcbind"
        "rsh-client"
        "talk"
        "telnet"
        "tftp"
        "whoopsie"
        "xinetd"
        "nis"
    )

    for pkg in "${packages[@]}"; do
        if dpkg -l | grep -q "^ii  $pkg"; then
            if [[ "$pkg" == "prelink" ]]; then
                # Undo prelinking before removal
                prelink -ua 2>/dev/null
            fi

            apt-get remove -y "$pkg"
            print_message "$GREEN" "Removed $pkg"
        fi
    done

    print_message "$GREEN" "Legacy services cleanup completed"
}

# Function to run all advanced hardening components
run_advanced_hardening_components() {
    print_section "Advanced Hardening Modules"

    configure_filesystem_restrictions
    configure_network_restrictions
    configure_hardware_restrictions
    configure_systemd_hardening
    remove_legacy_services

    # Optional components requiring confirmation
    configure_compiler_restrictions
    configure_usbguard
    configure_psad

    print_message "$GREEN" "Advanced hardening completed"
}
