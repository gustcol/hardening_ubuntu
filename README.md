# Ubuntu Hardening Suite

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/your-repo/hardening-ubuntu)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-18.04%20|%2020.04%20|%2022.04%20|%2024.04%20|%2025.04%20|%2025.10-orange)](https://ubuntu.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Comprehensive Ubuntu server hardening and image creation suite** that combines initial setup, security hardening, cloud security, and container/Docker image building capabilities.

## 🎯 Overview

This suite combines the best features from multiple hardening approaches into a unified, production-ready solution for Ubuntu servers. It provides:

- **Initial Server Setup**: User creation, SSH hardening, firewall configuration, time sync
- **Security Hardening**: AIDE, auditd, AppArmor, ClamAV, Fail2ban, OpenSCAP, kernel hardening
- **Cloud Security**: AWS/Azure/GCP-specific hardening and metadata protection
- **Image Creation**: Docker images, cloud-init images for Proxmox/QEMU, Packer configs

## ⭐ Key Improvements & Recent Updates

This suite represents a significant evolution from original hardening scripts (`du_setup.sh`, `Ubuntu-Security-Hardening-Script`), introducing:

- **✅ Fixed PAM Limits Configuration**: Resolved issues with process and file descriptor limits.
- **✅ Enhanced Environment Detection**: Smart detection of Cloud (AWS/GCP/Azure) vs Personal VM environments.
- **✅ Comprehensive Backup System**: Integrated rsync-based backup with restore functionality.
- **✅ Advanced Shell Environment**: Custom `.bashrc` with 200+ productivity functions and aliases.
- **✅ Modern Ubuntu Support**: Full support for Ubuntu 20.04, 22.04, 24.04, and experimental support for 25.x.
- **✅ Container Security**: Specialized hardening for Docker containers and images.

## 🚀 Quick Start

### Basic Hardening

```bash
# Download and run
wget https://raw.githubusercontent.com/your-repo/hardening-ubuntu/main/ubuntu-hardening-suite.sh
chmod +x ubuntu-hardening-suite.sh
sudo ./ubuntu-hardening-suite.sh
```

### Selective Components

```bash
# Only initial setup and security hardening
sudo ./ubuntu-hardening-suite.sh --components initial-setup,security-hardening

# Cloud-init image creation
sudo ./ubuntu-hardening-suite.sh --cloud-init

# Docker image building
sudo ./ubuntu-hardening-suite.sh --docker
```

### Dry Run (Safe Testing)

```bash
# See what would be done without making changes
sudo ./ubuntu-hardening-suite.sh --dry-run
```

## 📋 Features

### Initial Setup Module

- ✅ **User Management**: Create admin users with SSH keys
- ✅ **SSH Hardening**: Disable root login, password auth, strong crypto
- ✅ **Firewall**: UFW configuration with rate limiting
- ✅ **Time Sync**: Chrony (25.x) or systemd-timesyncd configuration
- ✅ **Hostname**: Dynamic hostname configuration
- ✅ **VPN Integration**: Optional Tailscale VPN installation and configuration
- ✅ **Backup System**: Comprehensive rsync-based backup with restore functionality
- ✅ **Shell Enhancements**: Git integration, directory bookmarks, and system monitoring

### Security Hardening Module

- ✅ **PAM Configuration**: Properly configured limits (`limits.conf`) and `common-session`
- ✅ **File Integrity**: AIDE with automated monitoring
- ✅ **Audit System**: Comprehensive auditd rules and logging
- ✅ **MAC Security**: AppArmor enforcement and profiles
- ✅ **Antivirus**: ClamAV with weekly scans
- ✅ **Intrusion Prevention**: Fail2ban with SSH and port scan protection
- ✅ **Compliance**: OpenSCAP CIS benchmarks scanning
- ✅ **Kernel Security**: Sysctl hardening and lockdown mode
- ✅ **Rootkit Detection**: Integration with `rkhunter` and `chkrootkit`

### Advanced Hardening Module (Aggressive)

- ✅ **Filesystem Restrictions**: Disable unused filesystems (cramfs, freevxfs, jffs2, etc.)
- ✅ **Network Restrictions**: Disable unused protocols (dccp, sctp, rds, tipc)
- ✅ **Hardware Restrictions**: Disable unused hardware modules (firewire, thunderbolt, floppy)
- ✅ **Systemd Hardening**: Disable coredumps, harden resolved and logind
- ✅ **Compiler Restrictions**: Restrict access to compilers (gcc, g++, as)
- ✅ **USBGuard**: Allowlist USB devices
- ✅ **PSAD**: Port Scan Attack Detector integration
- ✅ **Legacy Cleanup**: Remove legacy services (xinetd, rpcbind, NIS)

### Cloud Security Module

- ✅ **Metadata Protection**: Block non-root access to cloud metadata
- ✅ **Cloud-Init Security**: Secure cloud-init configurations
- ✅ **Provider-Specific**: AWS IMDS, Azure/GCP metadata protection
- ✅ **Firewall Rules**: Cloud-specific service allowances
- ✅ **Provider Cleanup**: Automatic cleanup of unused provider packages

### Docker Image Building

- ✅ **Hardened Images**: Security-hardened Ubuntu containers
- ✅ **Multi-Stage Builds**: Optimized for size and security
- ✅ **Security Scanning**: Container vulnerability assessment
- ✅ **Compose Integration**: Docker Compose with security options

### Cloud-Init Image Creation

- ✅ **Proxmox Templates**: VM templates with cloud-init
- ✅ **QEMU Images**: Bootable QCOW2 images
- ✅ **Packer Configs**: Automated image building
- ✅ **Vagrant Boxes**: Development environments

## 🏗️ Architecture

```
hardening_ubuntu/
├── ubuntu-hardening-suite.sh    # Main orchestration script
├── modules/
│   ├── initial-setup.sh         # Server initialization
│   ├── security-hardening.sh    # Security hardening
│   ├── advanced-hardening.sh    # Advanced/Aggressive hardening
│   ├── cloud-security.sh        # Cloud-specific security
│   ├── docker/
│   │   └── build-image.sh       # Docker image creation
│   └── cloud-init/
│       └── generate-image.sh    # Cloud-init image tools
├── configs/
│   ├── default.conf             # Default configuration
│   ├── ubuntu-20.04.conf        # Ubuntu 20.04 specific config
│   ├── ubuntu-22.04.conf        # Ubuntu 22.04 specific config
│   ├── ubuntu-24.04.conf        # Ubuntu 24.04 specific config
│   ├── ubuntu-25.04.conf        # Ubuntu 25.04 specific config
│   └── ubuntu-25.10.conf        # Ubuntu 25.10 specific config
├── test-pam-limits.sh           # PAM limits validation script
└── README.md                    # This documentation
```

## 🎛️ Command Line Options

```
USAGE:
    ubuntu-hardening-suite.sh [OPTIONS]

OPTIONS:
    --advanced            Run advanced hardening (aggressive options)
    --cloud-init           Generate cloud-init compatible images
    --docker              Build Docker images and containers
    --dry-run             Show what would be done without changes
    --quiet               Reduce output verbosity
    --components LIST     Comma-separated components to run
                         (all, initial-setup, security-hardening, cloud-security, advanced-hardening)
    --help                Show help message

COMPONENTS:
    initial-setup        User creation, SSH hardening, firewall, time sync
    security-hardening   AIDE, auditd, AppArmor, ClamAV, Fail2ban, OpenSCAP
    advanced-hardening   Aggressive filesystem, network, and systemd hardening
    cloud-security       Cloud metadata protection, cloud-init security
    cloud-init          Cloud-init image creation tools
    docker              Docker image building tools
```

## 📖 Detailed Usage

### 1. Initial Server Setup

Perfect for fresh Ubuntu installations:

```bash
sudo ./ubuntu-hardening-suite.sh --components initial-setup
```

**What it does:**

- Creates sudo admin user with SSH key authentication
- Hardens SSH (disables root login, password auth)
- Configures UFW firewall with SSH rate limiting
- Sets up time synchronization
- Configures hostname
- Sets up environment detection and custom aliases

### 2. Security Hardening

Comprehensive security hardening:

```bash
sudo ./ubuntu-hardening-suite.sh --components security-hardening
```

**Security tools configured:**

- **PAM**: Enforces correct process and file limits
- **AIDE**: File integrity monitoring with daily checks
- **auditd**: System call auditing with 400+ rules
- **AppArmor**: Mandatory access control enforcement
- **ClamAV**: Antivirus with weekly scans
- **Fail2ban**: SSH and port scan protection
- **OpenSCAP**: CIS compliance scanning
- **Kernel**: Sysctl hardening and lockdown mode

### 3. Advanced Hardening (Aggressive)

Apply aggressive security measures (check for compatibility first):

```bash
sudo ./ubuntu-hardening-suite.sh --advanced
```

**Features:**

- **Filesystem Lockdown**: Disables `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `vfat`
- **Network Lockdown**: Disables `dccp`, `sctp`, `rds`, `tipc`
- **Systemd Hardening**: Disables coredumps, hardens DNS-over-TLS, session locking
- **Compiler Restriction**: Restricts `gcc`/`g++` to root only
- **Intrusion Detection**: PSAD and USBGuard configuration

### 4. Cloud Security

Cloud-specific hardening:

```bash
sudo ./ubuntu-hardening-suite.sh --components cloud-security
```

**Cloud providers supported:**

- **AWS**: IMDSv2 protection, SSM integration
- **Azure**: Metadata protection, monitoring
- **GCP**: Metadata protection, logging
- **Generic**: Universal cloud security measures

### 5. Docker Image Building

Create hardened container images:

```bash
sudo ./ubuntu-hardening-suite.sh --docker
```

**Generated files:**

- `Dockerfile.ubuntu-hardened` - Single-stage hardened image
- `Dockerfile.multistage-hardened` - Multi-stage optimized image
- `docker-compose.hardened.yml` - Compose with security options
- `scan-container-security.sh` - Security scanning script

### 6. Cloud-Init Images

Create VM images for cloud platforms:

```bash
sudo ./ubuntu-hardening-suite.sh --cloud-init
```

**Generated files:**

- `cloud-init-config/` - Cloud-init configuration files
- `create-proxmox-template.sh` - Proxmox VM template script
- `create-qemu-image.sh` - QEMU/KVM image creation
- `packer-ubuntu-hardened.json` - Packer configuration
- `Vagrantfile.hardened` - Vagrant box configuration

## 🧪 Testing and Validation

The suite includes comprehensive testing tools to ensure hardening is applied correctly.

### PAM Limits Verification

Use `test-pam-limits.sh` to verify that PAM limits are correctly applied for root and non-root users:

```bash
./test-pam-limits.sh
```

This tests:

- **PAM Limits**: Validates all 8 limit configurations
- **Session Testing**: Checks current session limits
- **System-wide**: Verifies `file-max` and other system limits
- **Docker Support**: Detects container environments

## 🔧 Configuration

### Default Configuration

The suite uses sensible defaults but can be customized:

```bash
# Edit configuration files
vim configs/default.conf        # Default settings for all versions
vim configs/ubuntu-20.04.conf   # Ubuntu 20.04 specific
vim configs/ubuntu-22.04.conf   # Ubuntu 22.04 specific
vim configs/ubuntu-24.04.conf   # Ubuntu 24.04 specific
vim configs/ubuntu-25.04.conf   # Ubuntu 25.04 specific
vim configs/ubuntu-25.10.conf   # Ubuntu 25.10 specific
```

### Environment Variables

```bash
# Set custom values
export UBUNTU_VERSION="22.04"
export MODE="interactive"  # or "automated"
export COMPONENTS="all"
```

## 📊 Monitoring & Maintenance

### Security Monitoring

```bash
# Check service status
sudo systemctl status auditd apparmor ufw fail2ban clamav-daemon

# View security logs
sudo tail -f /var/log/security-hardening/hardening-$(date +%Y%m%d)*.log

# Run security audit
sudo lynis audit system

# Check file integrity
sudo aide --check

# View audit events
sudo aureport --summary
```

### Automated Updates

The suite configures unattended-upgrades for automatic security updates:

```bash
# Check update status
sudo systemctl status unattended-upgrades

# View update logs
sudo tail -f /var/log/unattended-upgrades/unattended-upgrades.log
```

### Compliance Scanning

```bash
# Run OpenSCAP compliance scan
sudo /usr/local/bin/openscap-scan.sh

# View compliance reports
ls -la /var/log/openscap/
```

## 🐳 Docker Usage

### Build Hardened Images

```bash
# Build single-stage image
docker build -f Dockerfile.ubuntu-hardened -t ubuntu-hardened .

# Build multi-stage image
docker build -f Dockerfile.multistage-hardened -t ubuntu-hardened:slim .

# Run with security options
docker run --security-opt no-new-privileges:true \
           --cap-drop ALL \
           --read-only \
           -it ubuntu-hardened
```

### Docker Compose

```bash
# Start hardened service
docker-compose -f docker-compose.hardened.yml up -d

# View security status
docker-compose -f docker-compose.hardened.yml logs
```

### Security Scanning

```bash
# Scan container image
./scan-container-security.sh ubuntu-hardened:latest

# Scan with Trivy (external tool)
trivy image ubuntu-hardened:latest
```

## ☁️ Cloud-Init Usage

### Proxmox

```bash
# Create template
./create-proxmox-template.sh

# Clone and customize
qm clone 9000 101 --name ubuntu-hardened-01
qm set 101 --sshkey ~/.ssh/id_rsa.pub
qm start 101
```

### QEMU/KVM

```bash
# Create image
./create-qemu-image.sh

# Boot image
qemu-system-x86_64 \
  -m 2048 \
  -drive file=ubuntu-hardened.qcow2,if=virtio \
  -net nic,model=virtio -net user \
  -vga std
```

### Packer

```bash
# Build image
packer build packer-ubuntu-hardened.json

# Use generated image
ls -la output-ubuntu-hardened/
```

## 🔍 Troubleshooting

### Common Issues

**SSH Connection Lost**

```bash
# Emergency access via console
# Re-enable SSH if needed
ufw allow ssh
systemctl restart sshd
```

**Service Failures**

```bash
# Check service status
systemctl status <service-name>

# View service logs
journalctl -u <service-name> -n 50
```

**Firewall Blocks Everything**

```bash
# Temporarily disable UFW
ufw disable

# Add required rules
ufw allow 80/tcp
ufw allow 443/tcp

# Re-enable
ufw enable
```

### Recovery

**Restore from Backups**

```bash
# View available backups
ls -la /var/backups/hardening-suite/

# Restore configuration
cp /var/backups/hardening-suite/sshd_config.bak /etc/ssh/sshd_config
systemctl restart sshd
```

**Reset Firewall**

```bash
ufw --force reset
ufw allow ssh
ufw enable
```

## 📈 Performance Considerations

### Resource Usage

- **Memory**: ~512MB additional for security tools
- **Disk**: ~2GB for logs, databases, and quarantine
- **CPU**: Minimal impact with proper configuration

### Optimization

```bash
# Adjust ClamAV scanning frequency
vim /etc/systemd/system/clamav-scan.timer

# Reduce audit verbosity
vim /etc/audit/rules.d/hardening.rules

# Tune sysctl parameters
vim /etc/sysctl.d/99-security-hardening.conf
```

## 🔒 Security Best Practices

### Operational Security

1. **Regular Updates**: Keep system and tools updated
2. **Log Monitoring**: Review logs daily for anomalies
3. **Access Control**: Use principle of least privilege
4. **Network Security**: Configure firewalls appropriately
5. **Backup Strategy**: Regular backups with testing

### Compliance

- **CIS Benchmarks**: OpenSCAP scans for compliance
- **NIST Framework**: Security controls alignment
- **Industry Standards**: PCI DSS, HIPAA considerations

### Incident Response

1. **Detection**: Monitor logs and alerts
2. **Containment**: Isolate affected systems
3. **Eradication**: Remove threats and vulnerabilities
4. **Recovery**: Restore from clean backups
5. **Lessons Learned**: Update procedures

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- **New Features**: Additional security tools, cloud providers
- **Testing**: More Ubuntu versions, cloud platforms
- **Documentation**: Tutorials, videos, examples
- **Performance**: Optimization and resource usage
- **Compliance**: Additional security frameworks

### Development Setup

```bash
# Clone repository
git clone https://github.com/your-repo/hardening-ubuntu.git
cd hardening-ubuntu

# Run in development mode
sudo ./ubuntu-hardening-suite.sh --dry-run --verbose
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This suite is provided "AS IS" without warranty. Always test in non-production environments first. The authors are not responsible for any damages resulting from use of these scripts.

**Important**: These scripts make significant system changes. Always:

- Create backups before running
- Test in isolated environments
- Review code before execution
- Have recovery procedures ready

## 🙏 Acknowledgments

Based on and inspired by:

- [du_setup](https://github.com/your-repo/du_setup) - Initial server setup
- [Ubuntu-Security-Hardening-Script](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script) - Security hardening
- Ubuntu Security Team best practices
- CIS Ubuntu Linux Benchmarks
- NIST Cybersecurity Framework

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/hardening-ubuntu/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/hardening-ubuntu/discussions)
- **Documentation**: This README and inline comments

---

**Version**: 1.0 | **Ubuntu Support**: 18.04, 20.04, 22.04, 24.04, 25.04, 25.10
**Status**: Production Ready | **License**: MIT
