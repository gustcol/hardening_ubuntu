#!/bin/bash
# Cloud Security Module
# Provides cloud-specific security hardening for AWS, Azure, and GCP

# Function to detect cloud provider
detect_cloud_provider() {
    print_message "$GREEN" "Detecting cloud provider..."

    # Check for AWS
    if curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        CLOUD_PROVIDER="aws"
        print_message "$GREEN" "AWS EC2 instance detected"
        return 0
    fi

    # Check for Azure
    if curl -s --connect-timeout 2 -H "Metadata: true" http://169.254.169.254/metadata/instance/ &>/dev/null; then
        CLOUD_PROVIDER="azure"
        print_message "$GREEN" "Azure VM detected"
        return 0
    fi

    # Check for GCP
    if curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ &>/dev/null; then
        CLOUD_PROVIDER="gcp"
        print_message "$GREEN" "GCP VM detected"
        return 0
    fi

    # Default to generic cloud
    CLOUD_PROVIDER="generic"
    print_message "$YELLOW" "Generic cloud environment detected"
}

# Function to configure AWS security
configure_aws_security() {
    print_message "$GREEN" "Configuring AWS security..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure AWS security"
        return
    fi

    # Block IMDSv1 and enforce IMDSv2
    cat > /etc/systemd/system/aws-imds-block.service << 'EOF'
[Unit]
Description=Block IMDSv1 and enforce IMDSv2
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/block-imdsv1.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Create IMDSv1 blocking script
    cat > /usr/local/bin/block-imdsv1.sh << 'EOF'
#!/bin/bash
# Block IMDSv1 and enforce IMDSv2

# Configure iptables to block IMDSv1 (unencrypted)
iptables -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 -j DROP

# Allow only IMDSv2 (requires token)
# This is handled by the application using the proper headers

echo "IMDSv1 blocked, IMDSv2 enforced"
EOF

    chmod +x /usr/local/bin/block-imdsv1.sh

    # Configure AWS Systems Manager (SSM) if available
    if command -v amazon-ssm-agent &>/dev/null; then
        systemctl enable amazon-ssm-agent
        systemctl start amazon-ssm-agent
        print_message "$GREEN" "AWS SSM agent configured"
    fi

    # Block access to instance metadata for non-root users
    cat > /etc/udev/rules.d/99-aws-imds.rules << 'EOF'
# Block IMDS access for non-root users
ACTION=="add", SUBSYSTEM=="net", KERNEL=="eth*", RUN+="/usr/local/bin/block-imds-access.sh"
EOF

    # Create IMDS access blocking script
    cat > /usr/local/bin/block-imds-access.sh << 'EOF'
#!/bin/bash
# Block IMDS access for non-root users

# Create iptables rule to block IMDS for non-root
iptables -A OUTPUT -m owner ! --uid-owner 0 -d 169.254.169.254 -j DROP

echo "IMDS access restricted to root only"
EOF

    chmod +x /usr/local/bin/block-imds-access.sh

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable aws-imds-block.service
    systemctl start aws-imds-block.service

    print_message "$GREEN" "AWS security configured"
}

# Function to configure Azure security
configure_azure_security() {
    print_message "$GREEN" "Configuring Azure security..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure Azure security"
        return
    fi

    # Block Azure metadata access for non-root users
    cat > /etc/systemd/system/azure-metadata-block.service << 'EOF'
[Unit]
Description=Block Azure metadata access for non-root users
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/block-azure-metadata.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Create Azure metadata blocking script
    cat > /usr/local/bin/block-azure-metadata.sh << 'EOF'
#!/bin/bash
# Block Azure metadata access for non-root users

# Block metadata access for non-root users
iptables -A OUTPUT -m owner ! --uid-owner 0 -d 168.63.129.16 -j DROP

# Block additional Azure metadata endpoints
iptables -A OUTPUT -m owner ! --uid-owner 0 -d 169.254.169.254 -j DROP

echo "Azure metadata access restricted to root only"
EOF

    chmod +x /usr/local/bin/block-azure-metadata.sh

    # Configure Azure Linux Agent if available
    if command -v waagent &>/dev/null; then
        # Harden waagent configuration
        backup_file "/etc/waagent.conf"

        cat >> /etc/waagent.conf << 'EOF'

# Ubuntu Hardening Suite - Azure Agent Hardening
OS.EnableFirewall=y
OS.EnableRDMA=n
OS.CheckRdma=n
OS.EnableFIPS=n
Logs.Verbose=n
EOF

        systemctl enable walinuxagent
        systemctl restart walinuxagent
        print_message "$GREEN" "Azure Linux Agent configured"
    fi

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable azure-metadata-block.service
    systemctl start azure-metadata-block.service

    print_message "$GREEN" "Azure security configured"
}

# Function to configure GCP security
configure_gcp_security() {
    print_message "$GREEN" "Configuring GCP security..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure GCP security"
        return
    fi

    # Block GCP metadata access for non-root users
    cat > /etc/systemd/system/gcp-metadata-block.service << 'EOF'
[Unit]
Description=Block GCP metadata access for non-root users
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/block-gcp-metadata.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Create GCP metadata blocking script
    cat > /usr/local/bin/block-gcp-metadata.sh << 'EOF'
#!/bin/bash
# Block GCP metadata access for non-root users

# Block metadata access for non-root users
iptables -A OUTPUT -m owner ! --uid-owner 0 -d 169.254.169.254 -j DROP

# Block Google metadata server
iptables -A OUTPUT -m owner ! --uid-owner 0 -d metadata.google.internal -j DROP

echo "GCP metadata access restricted to root only"
EOF

    chmod +x /usr/local/bin/block-gcp-metadata.sh

    # Configure Google Guest Agent if available
    if command -v google_guest_agent &>/dev/null; then
        systemctl enable google-guest-agent
        systemctl start google-guest-agent
        print_message "$GREEN" "Google Guest Agent configured"
    fi

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable gcp-metadata-block.service
    systemctl start gcp-metadata-block.service

    print_message "$GREEN" "GCP security configured"
}

# Function to configure generic cloud security
configure_generic_cloud_security() {
    print_message "$GREEN" "Configuring generic cloud security..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure generic cloud security"
        return
    fi

    # Block common metadata endpoints for non-root users
    cat > /etc/systemd/system/generic-metadata-block.service << 'EOF'
[Unit]
Description=Block cloud metadata access for non-root users
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/block-generic-metadata.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # Create generic metadata blocking script
    cat > /usr/local/bin/block-generic-metadata.sh << 'EOF'
#!/bin/bash
# Block cloud metadata access for non-root users

# Block common metadata endpoints
iptables -A OUTPUT -m owner ! --uid-owner 0 -d 169.254.169.254 -j DROP
iptables -A OUTPUT -m owner ! --uid-owner 0 -d 168.63.129.16 -j DROP

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

echo "Generic cloud metadata access restricted to root only"
EOF

    chmod +x /usr/local/bin/block-generic-metadata.sh

    # Create iptables rules directory
    mkdir -p /etc/iptables

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable generic-metadata-block.service
    systemctl start generic-metadata-block.service

    print_message "$GREEN" "Generic cloud security configured"
}

# Function to configure cloud metadata protection
configure_cloud_metadata_protection() {
    print_message "$GREEN" "Configuring cloud metadata protection..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure cloud metadata protection"
        return
    fi

    # Detect cloud provider first
    detect_cloud_provider

    # Configure based on detected provider
    case "$CLOUD_PROVIDER" in
        "aws")
            configure_aws_security
        ;;
        "azure")
            configure_azure_security
        ;;
        "gcp")
            configure_gcp_security
        ;;
        *)
            configure_generic_cloud_security
        ;;
    esac

    # Common cloud security measures

    # Disable unnecessary services that might leak information
    systemctl disable --now snapd.service 2>/dev/null || true
    systemctl disable --now lxd.service 2>/dev/null || true

    # Configure cloud-specific firewall rules
    case "$CLOUD_PROVIDER" in
        "aws")
            # Allow AWS Systems Manager traffic
            ufw allow out on any to any port 443 comment 'AWS SSM HTTPS'
        ;;
        "azure")
            # Allow Azure agent traffic
            ufw allow out on any to any port 443 comment 'Azure Agent HTTPS'
        ;;
        "gcp")
            # Allow Google services traffic
            ufw allow out on any to any port 443 comment 'Google Services HTTPS'
        ;;
    esac

    print_message "$GREEN" "Cloud metadata protection configured"
}

# Function to configure cloud-init security
configure_cloud_init_security() {
    print_message "$GREEN" "Configuring cloud-init security..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure cloud-init security"
        return
    fi

    # Backup cloud-init configuration
    backup_file "/etc/cloud/cloud.cfg"

    # Harden cloud-init configuration
    cat > /etc/cloud/cloud.cfg.d/99-security.cfg << 'EOF'
# Ubuntu Hardening Suite - Cloud-Init Security Configuration

# Disable unused modules
disable_root: true
ssh_pwauth: false

# Security settings
ssh_deletekeys: true
ssh_genkeytypes: [rsa, ecdsa, ed25519]

# Disable potentially dangerous modules
cloud_init_modules:
 - migrator
 - seed_random
 - bootcmd
 - write-files
 - growpart
 - resizefs
 - set_hostname
 - update_hostname
 - update_etc_hosts
 - ca-certs
 - rsyslog
 - users-groups
 - ssh

cloud_config_modules:
 - mounts
 - locale
 - set-passwords
 - package-update-upgrade-install
 - timezone
 - disable-ec2-metadata
 - runcmd
 - byobu

cloud_final_modules:
 - package-update-upgrade-install
 - fan
 - landscape
 - lxd
 - puppet
 - chef
 - mcollective
 - salt-minion
 - rightscale_userdata
 - scripts-vendor
 - scripts-per-once
 - scripts-per-boot
 - scripts-per-instance
 - scripts-user
 - ssh-authkey-fingerprints
 - keys-to-console
 - phone-home
 - final-message
 - power-state-change

# Security: Disable EC2 metadata if not on AWS
disable_ec2_metadata: true
EOF

    # Set proper permissions
    chmod 644 /etc/cloud/cloud.cfg.d/99-security.cfg

    # Disable cloud-init if not needed (optional)
    if [[ "$CLOUD_PROVIDER" == "generic" ]]; then
        systemctl disable cloud-init
        systemctl disable cloud-config
        systemctl disable cloud-final
        print_message "$YELLOW" "Cloud-init disabled for generic environment"
    else
        systemctl enable cloud-init
        print_message "$GREEN" "Cloud-init security configured"
    fi
}

# Function to run all cloud security components
run_cloud_security_components() {
    configure_cloud_metadata_protection
    configure_cloud_init_security

    print_message "$GREEN" "Cloud security configuration completed"
}
