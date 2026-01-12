#!/bin/bash
# Cloud-Init Image Generation Module
# Creates VM images with cloud-init support for Proxmox, QEMU, and other platforms

# Define helper functions if not running from main script
if ! type print_message > /dev/null 2>&1; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'

    print_message() {
        local color=$1
        local message=$2
        echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}"
    }

    print_section() {
        local message=$1
        echo -e "\n${BLUE}=== $message ===${NC}"
    }

    error_exit() {
        print_message "$RED" "ERROR: $1"
        exit 1
    }

    # Default variables if not set
    DRY_RUN=${DRY_RUN:-false}
fi

# Function to create cloud-init configuration
create_cloud_init_config() {
    print_message "$GREEN" "Creating cloud-init configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create cloud-init configuration"
        return
    fi

    local config_dir="cloud-init-config"
    mkdir -p "$config_dir"

    # Create meta-data
    cat > "$config_dir/meta-data" << 'EOF'
instance-id: ubuntu-hardened-01
local-hostname: ubuntu-hardened
EOF

    # Create user-data
    cat > "$config_dir/user-data" << 'EOF'
#cloud-config
users:
  - name: admin
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2EA... # Add your SSH key here
    lock_passwd: true

package_update: true
package_upgrade: true

packages:
  - curl
  - wget
  - vim
  - htop
  - fail2ban
  - ufw

runcmd:
  - systemctl enable fail2ban
  - systemctl start fail2ban
  - ufw --force enable
  - ufw allow ssh
  - ufw allow 80/tcp
  - ufw allow 443/tcp

final_message: "Ubuntu Hardened system is ready!"
EOF

    # Create network-config
    cat > "$config_dir/network-config" << 'EOF'
version: 2
ethernets:
  eth0:
    dhcp4: true
    dhcp6: false
EOF

    print_message "$GREEN" "Cloud-init configuration created in $config_dir"
}

# Function to create Proxmox template script
create_proxmox_template_script() {
    local script_name="create-proxmox-template.sh"

    print_message "$GREEN" "Creating Proxmox template script..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create Proxmox template script"
        return
    fi

    cat > "$script_name" << 'EOF'
#!/bin/bash
# Proxmox Template Creation Script

set -euo pipefail

# Configuration
TEMPLATE_ID="9000"
TEMPLATE_NAME="ubuntu-hardened-template"
UBUNTU_VERSION="22.04"
DISK_SIZE="20G"
MEMORY="2048"
CORES="2"
STORAGE="local"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${GREEN}Creating Proxmox Ubuntu Hardened Template${NC}"

# Download Ubuntu cloud image
echo -e "${YELLOW}Downloading Ubuntu cloud image...${NC}"
wget -q --show-progress "https://cloud-images.ubuntu.com/releases/${UBUNTU_VERSION}/release/ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img"

# Convert to QCOW2
echo -e "${YELLOW}Converting image to QCOW2 format...${NC}"
qemu-img convert -f qcow2 -O qcow2 "ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img" "ubuntu-${UBUNTU_VERSION}-hardened.qcow2"

# Resize disk
echo -e "${YELLOW}Resizing disk to ${DISK_SIZE}...${NC}"
qemu-img resize "ubuntu-${UBUNTU_VERSION}-hardened.qcow2" ${DISK_SIZE}

# Create VM
echo -e "${YELLOW}Creating VM ${TEMPLATE_ID}...${NC}"
qm create ${TEMPLATE_ID} \
    --name ${TEMPLATE_NAME} \
    --memory ${MEMORY} \
    --cores ${CORES} \
    --net0 virtio,bridge=vmbr0 \
    --scsihw virtio-scsi-pci \
    --scsi0 ${STORAGE}:0,import-from="$(pwd)/ubuntu-${UBUNTU_VERSION}-hardened.qcow2"

# Configure VM
echo -e "${YELLOW}Configuring VM...${NC}"
qm set ${TEMPLATE_ID} --description "Ubuntu ${UBUNTU_VERSION} Hardened Template"
qm set ${TEMPLATE_ID} --ide2 ${STORAGE}:cloudinit
qm set ${TEMPLATE_ID} --boot c --bootdisk scsi0
qm set ${TEMPLATE_ID} --serial0 socket --vga serial0

# Convert to template
echo -e "${YELLOW}Converting to template...${NC}"
qm template ${TEMPLATE_ID}

# Cleanup
echo -e "${YELLOW}Cleaning up...${NC}"
rm -f "ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img"
rm -f "ubuntu-${UBUNTU_VERSION}-hardened.qcow2"

echo -e "${GREEN}Proxmox template created successfully!${NC}"
echo -e "Template ID: ${TEMPLATE_ID}"
echo -e "Template Name: ${TEMPLATE_NAME}"
echo -e ""
echo -e "To use the template:"
echo -e "  qm clone ${TEMPLATE_ID} 101 --name ubuntu-hardened-01"
echo -e "  qm set 101 --sshkey ~/.ssh/id_rsa.pub"
echo -e "  qm start 101"
EOF

    chmod +x "$script_name"
    print_message "$GREEN" "Proxmox template script created: $script_name"
}

# Function to create QEMU image script
create_qemu_image_script() {
    local script_name="create-qemu-image.sh"

    print_message "$GREEN" "Creating QEMU image script..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create QEMU image script"
        return
    fi

    cat > "$script_name" << 'EOF'
#!/bin/bash
# QEMU Image Creation Script

set -euo pipefail

# Configuration
UBUNTU_VERSION="22.04"
IMAGE_NAME="ubuntu-hardened.qcow2"
DISK_SIZE="20G"
MEMORY="2048"
CPUS="2"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${GREEN}Creating QEMU Ubuntu Hardened Image${NC}"

# Download Ubuntu cloud image
echo -e "${YELLOW}Downloading Ubuntu cloud image...${NC}"
wget -q --show-progress "https://cloud-images.ubuntu.com/releases/${UBUNTU_VERSION}/release/ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img"

# Convert to QCOW2
echo -e "${YELLOW}Converting image to QCOW2 format...${NC}"
qemu-img convert -f qcow2 -O qcow2 "ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img" "$IMAGE_NAME"

# Resize disk
echo -e "${YELLOW}Resizing disk to ${DISK_SIZE}...${NC}"
qemu-img resize "$IMAGE_NAME" ${DISK_SIZE}

# Inject cloud-init configuration
echo -e "${YELLOW}Injecting cloud-init configuration...${NC}"
cloud-localds seed.img cloud-init-config/user-data cloud-init-config/meta-data

echo -e "${GREEN}QEMU image created successfully!${NC}"
echo -e "Image: $IMAGE_NAME"
echo -e "Seed: seed.img"
echo -e ""
echo -e "To boot the image:"
echo -e "  qemu-system-x86_64 \\"
echo -e "    -m ${MEMORY} \\"
echo -e "    -smp ${CPUS} \\"
echo -e "    -drive file=${IMAGE_NAME},if=virtio \\"
echo -e "    -drive file=seed.img,if=virtio \\"
echo -e "    -net nic,model=virtio -net user \\"
echo -e "    -vga std"

# Cleanup
echo -e "${YELLOW}Cleaning up...${NC}"
rm -f "ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img"
EOF

    chmod +x "$script_name"
    print_message "$GREEN" "QEMU image script created: $script_name"
}

# Function to create Packer configuration
create_packer_config() {
    local config_file="packer-ubuntu-hardened.json"

    print_message "$GREEN" "Creating Packer configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create Packer configuration"
        return
    fi

    cat > "$config_file" << 'EOF'
{
  "builders": [
    {
      "type": "qemu",
      "iso_url": "https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso",
      "iso_checksum": "sha256:9bc6028870aef3f74f4e61b0cd9d0a0e8c88d3e48b32671a2b9b674a2c9f7a5e",
      "output_directory": "output-ubuntu-hardened",
      "shutdown_command": "echo 'packer' | sudo -S shutdown -P now",
      "disk_size": "20480",
      "format": "qcow2",
      "headless": false,
      "accelerator": "kvm",
      "http_directory": "http",
      "ssh_username": "packer",
      "ssh_password": "packer",
      "ssh_wait_timeout": "10000s",
      "vm_name": "ubuntu-hardened",
      "net_device": "virtio-net",
      "disk_interface": "virtio",
      "cpus": 2,
      "memory": 2048
    }
  ],
  "provisioners": [
    {
      "type": "shell",
      "inline": [
        "sudo apt-get update",
        "sudo apt-get install -y curl wget git",
        "curl -fsSL https://raw.githubusercontent.com/your-repo/hardening-ubuntu/main/ubuntu-hardening-suite.sh -o /tmp/hardening.sh",
        "chmod +x /tmp/hardening.sh",
        "sudo /tmp/hardening.sh --components initial-setup,security-hardening",
        "sudo rm /tmp/hardening.sh"
      ]
    }
  ]
}
EOF

    print_message "$GREEN" "Packer configuration created: $config_file"
}

# Function to create Vagrantfile
create_vagrantfile() {
    local vagrantfile="Vagrantfile.hardened"

    print_message "$GREEN" "Creating Vagrantfile..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create Vagrantfile"
        return
    fi

    cat > "$vagrantfile" << 'EOF'
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "ubuntu-hardened"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
    vb.name = "ubuntu-hardened"
  end

  config.vm.provider "libvirt" do |libvirt|
    libvirt.memory = 2048
    libvirt.cpus = 2
    libvirt.graphics_type = "none"
  end

  # Run hardening script
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y curl wget git
    curl -fsSL https://raw.githubusercontent.com/your-repo/hardening-ubuntu/main/ubuntu-hardening-suite.sh -o /tmp/hardening.sh
    chmod +x /tmp/hardening.sh
    /tmp/hardening.sh --components initial-setup,security-hardening
    rm /tmp/hardening.sh
  SHELL

  # Network configuration
  config.vm.network "private_network", type: "dhcp"

  # SSH configuration
  config.ssh.insert_key = false
  config.ssh.private_key_path = ["~/.vagrant.d/insecure_private_key", "~/.ssh/id_rsa"]

  # Synced folders
  config.vm.synced_folder ".", "/vagrant", disabled: true
end
EOF

    print_message "$GREEN" "Vagrantfile created: $vagrantfile"
}

# Function to generate cloud-init documentation
generate_cloud_init_documentation() {
    local doc_file="README-cloud-init.md"

    print_message "$GREEN" "Generating cloud-init documentation..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would generate cloud-init documentation"
        return
    fi

    cat > "$doc_file" << EOF
# Cloud-Init Image Creation

This directory contains tools for creating cloud-init enabled VM images for various platforms.

## Generated Files

### Configuration
- \`cloud-init-config/\` - Cloud-init configuration files
  - \`meta-data\` - Instance metadata
  - \`user-data\` - User configuration and packages
  - \`network-config\` - Network configuration

### Scripts
- \`create-proxmox-template.sh\` - Proxmox VE template creation
- \`create-qemu-image.sh\` - QEMU/KVM image creation
- \`packer-ubuntu-hardened.json\` - Packer configuration
- \`Vagrantfile.hardened\` - Vagrant development environment

## Usage

### Proxmox VE
\`\`\`bash
# Create template
./create-proxmox-template.sh

# Clone template for use
qm clone 9000 101 --name ubuntu-hardened-01
qm set 101 --sshkey ~/.ssh/id_rsa.pub
qm start 101
\`\`\`

### QEMU/KVM
\`\`\`bash
# Create image
./create-qemu-image.sh

# Boot image
qemu-system-x86_64 \\
  -m 2048 \\
  -smp 2 \\
  -drive file=ubuntu-hardened.qcow2,if=virtio \\
  -drive file=seed.img,if=virtio \\
  -net nic,model=virtio -net user \\
  -vga std
\`\`\`

### Packer
\`\`\`bash
# Build image with Packer
packer build packer-ubuntu-hardened.json

# Use generated image
ls -la output-ubuntu-hardened/
\`\`\`

### Vagrant
\`\`\`bash
# Start Vagrant environment
vagrant up

# SSH into VM
vagrant ssh

# Destroy environment
vagrant destroy -f
\`\`\`

## Cloud-Init Configuration

The cloud-init configuration includes:

- **User Setup**: Admin user with SSH key authentication
- **Package Management**: Automatic updates and security packages
- **Security Tools**: Fail2ban, UFW firewall pre-configured
- **Network**: DHCP configuration
- **Final Message**: System ready notification

## Customization

### Modify User Data
Edit \`cloud-init-config/user-data\` to:
- Add/remove users
- Install additional packages
- Configure custom commands
- Set up application deployment

### Network Configuration
Edit \`cloud-init-config/network-config\` for:
- Static IP addresses
- Multiple interfaces
- VLAN configuration
- Bonding/Teaming

### Platform-Specific
Each platform script can be customized for:
- Resource allocation (CPU, memory, disk)
- Network settings
- Storage configuration
- Cloud provider integration

## Security Features

### Pre-configured Security
- Non-root user with sudo access
- SSH key authentication only
- Automatic security updates
- Firewall with basic rules
- Fail2ban intrusion prevention

### Hardening Integration
The images are designed to work with the main hardening suite:
- Compatible with security hardening scripts
- Support for additional security tools
- Audit and compliance ready

## Troubleshooting

### Common Issues

**Cloud-Init Not Running**
\`\`\`bash
# Check cloud-init status
sudo cloud-init status
sudo cloud-init analyze show
\`\`\`

**Network Configuration Issues**
\`\`\`bash
# Check network config
sudo cloud-init query ds
sudo netplan apply
\`\`\`

**SSH Key Problems**
\`\`\`bash
# Verify SSH keys
sudo cat /home/admin/.ssh/authorized_keys
sudo chmod 600 /home/admin/.ssh/authorized_keys
sudo chown admin:admin /home/admin/.ssh/authorized_keys
\`\`\`

### Debug Mode
\`\`\`bash
# Enable debug logging
sudo cloud-init clean --logs
sudo cloud-init init --local --debug
\`\`\`

## Integration

### CI/CD Pipeline
Integrate with your build pipeline:
\`\`\`yaml
# Example GitHub Actions
- name: Build VM Image
  run: |
    packer build packer-ubuntu-hardened.json

- name: Upload Image
  run: |
    # Upload to your infrastructure
\`\`\`

### Infrastructure as Code
Use with Terraform, Ansible, or other IaC tools:
\`\`\`hcl
# Terraform example
resource "proxmox_vm_qemu" "ubuntu-hardened" {
  name = "ubuntu-hardened-01"
  template = "ubuntu-hardened-template"
  # ... additional configuration
}
\`\`\`
EOF

    print_message "$GREEN" "Cloud-init documentation created: $doc_file"
}

# Main cloud-init generation function
generate_cloud_init_image() {
    print_section "Cloud-Init Image Generation"

    create_cloud_init_config
    create_proxmox_template_script
    create_qemu_image_script
    create_packer_config
    create_vagrantfile
    generate_cloud_init_documentation

    print_message "$GREEN" "Cloud-init image generation completed"
    print_message "$BLUE" "Files created:"
    print_message "$BLUE" "  - cloud-init-config/ (Configuration directory)"
    print_message "$BLUE" "  - create-proxmox-template.sh (Proxmox template script)"
    print_message "$BLUE" "  - create-qemu-image.sh (QEMU image script)"
    print_message "$BLUE" "  - packer-ubuntu-hardened.json (Packer configuration)"
    print_message "$BLUE" "  - Vagrantfile.hardened (Vagrant configuration)"
    print_message "$BLUE" "  - README-cloud-init.md (Documentation)"
}
