#!/bin/bash
# Security Hardening Module
# Based on Ubuntu-Security-Hardening-Script functionality

# Function to configure auditd
configure_auditd() {
    print_message "$GREEN" "Configuring auditd..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure auditd"
        return
    fi

    # Install auditd if not present
    if ! command -v auditctl &> /dev/null; then
        apt-get install -y auditd audispd-plugins
    fi

    backup_file "/etc/audit/auditd.conf"

    # Configure auditd
    cat > /etc/audit/auditd.conf << 'EOF'
# Ubuntu Hardening Suite - Audit Configuration
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
transport = TCP
krb5_principal = auditd
distribute_network = no
q_depth = 1200
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
end_of_event_timeout = 2
EOF

    # Create comprehensive audit rules
    cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Ubuntu Hardening Suite - Security Audit Rules
# Delete all existing rules
-D

# Buffer Size
-b 16384

# Failure Mode
-f 1

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudo configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Monitor systemd
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module -k module_insertion
-a always,exit -F arch=b64 -S delete_module -k module_deletion

# Monitor privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Monitor network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Monitor cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Living Off The Land (LOTL) Detection Rules
-w /usr/bin/wget -p x -k lotl_download
-w /usr/bin/curl -p x -k lotl_download
-w /usr/bin/scp -p x -k lotl_transfer
-w /usr/bin/sftp -p x -k lotl_transfer
-w /usr/bin/rsync -p x -k lotl_transfer
-w /usr/bin/base64 -p x -k lotl_encoding
-w /usr/bin/xxd -p x -k lotl_encoding
-w /usr/bin/nc -p x -k lotl_netcat
-w /usr/bin/ncat -p x -k lotl_netcat
-w /usr/bin/nmap -p x -k lotl_recon
-w /usr/bin/tcpdump -p x -k lotl_capture
-w /usr/bin/python3 -p x -k lotl_scripting
-w /usr/bin/perl -p x -k lotl_scripting
-w /usr/bin/ruby -p x -k lotl_scripting
-w /usr/bin/socat -p x -k lotl_tunnel
-w /usr/bin/ssh -p x -k lotl_ssh
-w /usr/bin/openssl -p x -k lotl_crypto
-w /usr/bin/tar -p x -k lotl_archive
-w /usr/bin/zip -p x -k lotl_archive
-w /usr/bin/apt -p x -k lotl_package
-w /usr/bin/dpkg -p x -k lotl_package

# Container escape detection
-a always,exit -F arch=b64 -S unshare -k container_escape
-a always,exit -F arch=b64 -S setns -k container_escape

# Privilege escalation detection
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_escalation

# Process injection detection
-a always,exit -F arch=b64 -S ptrace -k process_injection

# Staging directory monitoring
-w /tmp -p x -k tmp_exec
-w /dev/shm -p x -k shm_exec
-w /var/tmp -p x -k vartmp_exec

# Make configuration immutable
-e 2
EOF

    # Load rules and restart auditd
    augenrules --load
    systemctl restart auditd
    systemctl enable auditd

    # Configure log rotation
    cat > /etc/logrotate.d/audit << 'EOF'
/var/log/audit/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s USR1 auditd.service >/dev/null 2>&1 || true
    endscript
}
EOF

    print_message "$GREEN" "Auditd configured with comprehensive rules"
}

# Function to configure AppArmor
configure_apparmor() {
    print_message "$GREEN" "Configuring AppArmor..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure AppArmor"
        return
    fi

    # Install AppArmor if not present
    if ! command -v apparmor_status &> /dev/null; then
        apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
    fi

    # Enable AppArmor
    systemctl enable apparmor
    systemctl start apparmor

    # Set kernel parameter
    if ! grep -q "apparmor=1" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
        update-grub
    fi

    # Install additional profiles
    if [[ -d /usr/share/apparmor/extra-profiles/ ]]; then
        cp -n /usr/share/apparmor/extra-profiles/* /etc/apparmor.d/ 2>/dev/null || true
    fi

    # Enable all profiles
    find /etc/apparmor.d -maxdepth 1 -type f -exec aa-enforce {} \; 2>/dev/null || true

    print_message "$GREEN" "AppArmor configured and enforced"
}

# Function to configure ClamAV
configure_clamav() {
    print_message "$GREEN" "Configuring ClamAV antivirus..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure ClamAV"
        return
    fi

    # Install ClamAV if not present
    if ! command -v clamscan &> /dev/null; then
        apt-get install -y clamav clamav-daemon clamav-freshclam clamdscan
    fi

    # Configure ClamAV
    backup_file "/etc/clamav/clamd.conf"
    backup_file "/etc/clamav/freshclam.conf"

    # Optimize ClamAV configuration
    cat >> /etc/clamav/clamd.conf << 'EOF'

# Ubuntu Hardening Suite - ClamAV Optimizations
MaxThreads 4
MaxDirectoryRecursion 20
FollowDirectorySymlinks false
FollowFileSymlinks false
CrossFilesystems false
ScanPE true
ScanELF true
DetectBrokenExecutables true
ScanOLE2 true
ScanPDF true
ScanSWF true
ScanXMLDOCS true
ScanHWP3 true
ScanArchive true
MaxScanTime 300000
MaxScanSize 400M
MaxFileSize 100M
MaxRecursion 16
MaxFiles 10000
EOF

    # Configure freshclam
    sed -i 's/^Checks.*/Checks 24/' /etc/clamav/freshclam.conf 2>/dev/null || true

    # Stop services for configuration
    systemctl stop clamav-freshclam 2>/dev/null || true
    systemctl stop clamav-daemon 2>/dev/null || true

    # Update virus database
    print_message "$GREEN" "Updating ClamAV virus database..."
    freshclam || print_message "$YELLOW" "WARNING: Failed to update ClamAV database"

    # Start services
    systemctl start clamav-freshclam
    systemctl start clamav-daemon
    systemctl enable clamav-freshclam
    systemctl enable clamav-daemon

    # Create scan script
    cat > /usr/local/bin/clamav-scan.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/clamav/scan-$(date +%Y%m%d-%H%M%S).log"
INFECTED_DIR="/var/quarantine"

mkdir -p "$INFECTED_DIR"
chmod 700 "$INFECTED_DIR"

# Exclude virtual filesystems and large directories
EXCLUDE_DIRS="--exclude-dir=^/sys --exclude-dir=^/proc --exclude-dir=^/dev --exclude-dir=^/run --exclude-dir=^/snap --exclude-dir=^/var/lib/docker --exclude-dir=^/var/lib/containerd"

# Scan with optimized settings
nice -n 19 ionice -c 3 clamscan -r -i \
    --move="$INFECTED_DIR" \
    $EXCLUDE_DIRS \
    --max-filesize=100M \
    --max-scansize=400M \
    --max-recursion=16 \
    --max-dir-recursion=20 \
    --log="$LOG_FILE" \
    / 2>/dev/null

# Send notification if infections found
if grep -q "Infected files:" "$LOG_FILE" && grep -q "Infected files: [1-9]" "$LOG_FILE"; then
    echo "ClamAV: Infections detected on $(hostname)" | systemd-cat -t clamav -p err
    if command -v mail &> /dev/null; then
        mail -s "ClamAV: Infections detected on $(hostname)" root < "$LOG_FILE"
    fi
fi
EOF
    chmod 755 /usr/local/bin/clamav-scan.sh

    # Create systemd timer for scans
    cat > /etc/systemd/system/clamav-scan.service << 'EOF'
[Unit]
Description=ClamAV Virus Scan
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/clamav-scan.sh
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    cat > /etc/systemd/system/clamav-scan.timer << 'EOF'
[Unit]
Description=Run ClamAV scan weekly
Requires=clamav-scan.service

[Timer]
OnCalendar=weekly
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable clamav-scan.timer
    systemctl start clamav-scan.timer

    print_message "$GREEN" "ClamAV configured with weekly scans"
}

# Function to configure fail2ban
configure_fail2ban() {
    print_message "$GREEN" "Configuring Fail2ban..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure Fail2ban"
        return
    fi

    # Install fail2ban if not present
    if ! command -v fail2ban-client &> /dev/null; then
        apt-get install -y fail2ban
    fi

    backup_file "/etc/fail2ban/jail.conf"

    # Create jail.local
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
usedns = warn
logencoding = utf-8
enabled = false
mode = normal
filter = %(name)s[mode=%(mode)s]

destemail = root@localhost
sender = root@localhost
mta = sendmail

action = %(action_mwl)s

ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 2h
findtime = 20m

[sshd-ddos]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 10
findtime = 5m
bantime = 10m

[port-scan]
enabled = true
filter = port-scan
logpath = /var/log/ufw.log
maxretry = 2
bantime = 1d
findtime = 1d
EOF

    # Create custom filters
    mkdir -p /etc/fail2ban/filter.d

    cat > /etc/fail2ban/filter.d/port-scan.conf << 'EOF'
[Definition]
failregex = .*UFW BLOCK.* SRC=<HOST>
ignoreregex =
EOF

    # Restart fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban

    print_message "$GREEN" "Fail2ban configured with SSH and port scan protection"
}

# Function to configure OpenSCAP
configure_openscap() {
    print_message "$GREEN" "Configuring OpenSCAP compliance scanning..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure OpenSCAP"
        return
    fi

    # Install OpenSCAP if not present
    if ! command -v oscap &> /dev/null; then
        case "$UBUNTU_VERSION" in
            "18.04")
                apt-get install -y libopenscap8 openscap-scanner
            ;;
            *)
                apt-get install -y openscap-scanner
            ;;
        esac
    fi

    # Find the appropriate SCAP content
    local ssg_file=""
    case "$UBUNTU_VERSION" in
        "18.04")
            ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml"
        ;;
        "20.04")
            ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml"
        ;;
        "22.04")
            ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
        ;;
        "24.04")
            ssg_file="/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml"
        ;;
        *)
            print_message "$YELLOW" "No SCAP content available for Ubuntu $UBUNTU_VERSION"
            return
        ;;
    esac

    if [[ ! -f "$ssg_file" ]]; then
        print_message "$YELLOW" "SCAP content file not found: $ssg_file"
        return
    fi

    # Create scan script
    cat > /usr/local/bin/openscap-scan.sh << EOF
#!/bin/bash
REPORT_DIR="/var/log/openscap"
mkdir -p "\$REPORT_DIR"

PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"

echo "Running OpenSCAP scan with profile: \$PROFILE"

oscap xccdf eval \\
    --profile "\$PROFILE" \\
    --report "\$REPORT_DIR/report_\$(date +%Y%m%d-%H%M%S).html" \\
    --results "\$REPORT_DIR/results_\$(date +%Y%m%d-%H%M%S).xml" \\
    --oval-results \\
    --fetch-remote-resources \\
    "$ssg_file" 2>&1 | tee "\$REPORT_DIR/scan_\$(date +%Y%m%d-%H%M%S).log"

# Generate remediation script
oscap xccdf generate fix \\
    --profile "\$PROFILE" \\
    --output "\$REPORT_DIR/remediation_\$(date +%Y%m%d-%H%M%S).sh" \\
    "\$REPORT_DIR"/results_*.xml 2>/dev/null || true

echo ""
echo "Scan complete. Reports saved to: \$REPORT_DIR"
echo "View HTML report in a browser for detailed results."
EOF
    chmod 755 /usr/local/bin/openscap-scan.sh

    # Create systemd timer
    cat > /etc/systemd/system/openscap-scan.service << 'EOF'
[Unit]
Description=OpenSCAP Security Compliance Scan
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openscap-scan.sh
User=root
Nice=19
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

    cat > /etc/systemd/system/openscap-scan.timer << 'EOF'
[Unit]
Description=Run OpenSCAP scan weekly
Requires=openscap-scan.service

[Timer]
OnCalendar=weekly
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable openscap-scan.timer
    systemctl start openscap-scan.timer

    print_message "$GREEN" "OpenSCAP configured with weekly CIS scans"
}

# Function to configure kernel hardening
configure_kernel_hardening() {
    print_message "$GREEN" "Configuring kernel security parameters..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure kernel hardening"
        return
    fi

    backup_file "/etc/sysctl.conf"

    # Create comprehensive sysctl configuration
    cat > /etc/sysctl.d/99-security-hardening.conf << 'EOF'
# Ubuntu Hardening Suite - Kernel Security Hardening

# Network Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

# Kernel Security
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
net.core.bpf_jit_harden = 2
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2
kernel.unprivileged_userns_clone = 0

# Performance and Resource Protection
vm.swappiness = 10
vm.vfs_cache_pressure = 50
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_fastopen = 3
fs.file-max = 65536

# IPv6 Security (if enabled)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Restrict access to kernel logs
kernel.printk = 3 3 3 3
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-security-hardening.conf

    # Configure kernel lockdown (if supported)
    if [[ -f /sys/kernel/security/lockdown ]]; then
        print_message "$BLUE" "Configuring kernel lockdown..."
        if ! grep -q "lockdown=integrity" /etc/default/grub; then
            sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="lockdown=integrity /' /etc/default/grub
            update-grub
            print_message "$YELLOW" "Kernel lockdown configured - reboot required"
        fi
    fi

    print_message "$GREEN" "Kernel security parameters configured"
}

# Function to configure PAM limits
configure_pam_limits() {
    print_message "$GREEN" "Configuring PAM limits..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure PAM limits"
        return
    fi

    backup_file "/etc/security/limits.conf"
    backup_file "/etc/pam.d/common-session"

    # Configure PAM limits in common-session
    if ! grep -q "pam_limits.so" /etc/pam.d/common-session; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session
        print_message "$GREEN" "Added pam_limits.so to common-session"
    fi

    # Configure system limits
    cat >> /etc/security/limits.conf << 'EOF'

# Ubuntu Hardening Suite - System Limits Configuration
* soft        nproc          65535
* hard        nproc          65535
* soft        nofile         65535
* hard        nofile         65535
root soft     nproc          65535
root hard     nproc          65535
root soft     nofile         65535
root hard     nofile         65535
EOF

    # Additional security limits
    cat >> /etc/security/limits.conf << 'EOF'

# Additional security limits
* soft        core           0
* hard        core           0
* soft        data           1048576
* hard        data           1048576
* soft        fsize          1048576
* hard        fsize          1048576
* soft        memlock        32
* hard        memlock        32
* soft        rss            65536
* hard        rss            65536
* soft        stack          8192
* hard        stack          8192
EOF

    # Create limits.d directory configuration for better organization
    mkdir -p /etc/security/limits.d
    cat > /etc/security/limits.d/99-hardening.conf << 'EOF'
# Ubuntu Hardening Suite - Additional Limits

# Prevent fork bombs
*               soft    nproc           65535
*               hard    nproc           65535

# File descriptor limits
*               soft    nofile          65535
*               hard    nofile          65535

# Memory limits for security
*               soft    as              1048576
*               hard    as              1048576

# Core dump prevention
*               soft    core            0
*               hard    core            0

# Process priority
*               soft    priority        0
*               hard    priority        0
EOF

    # Set proper permissions
    chmod 644 /etc/security/limits.conf
    chmod 644 /etc/security/limits.d/99-hardening.conf
    chmod 644 /etc/pam.d/common-session

    print_message "$GREEN" "PAM limits configured successfully"
}

# Function to run all security hardening components
run_security_hardening_components() {
    configure_auditd
    configure_apparmor
    configure_clamav
    configure_fail2ban
    configure_openscap
    configure_kernel_hardening
    configure_pam_limits

    print_message "$GREEN" "Security hardening completed"
}
