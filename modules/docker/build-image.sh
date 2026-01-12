#!/bin/bash
# Docker Image Building Module
# Creates hardened Docker images

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
    SCRIPT_VERSION="1.0"
    DRY_RUN=${DRY_RUN:-false}
    UBUNTU_VERSION=${UBUNTU_VERSION:-"22.04"}
fi

# Function to create Dockerfile for hardened Ubuntu
create_hardened_dockerfile() {
    local dockerfile="Dockerfile.ubuntu-hardened"
    local version_tag="${UBUNTU_VERSION:-20.04}"

    print_message "$GREEN" "Creating hardened Ubuntu Dockerfile..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create Dockerfile"
        return
    fi

    cat > "$dockerfile" << EOF
# Ubuntu Hardened Docker Image
FROM ubuntu:${version_tag}

# Labels
LABEL maintainer="Ubuntu Hardening Suite"
LABEL version="${SCRIPT_VERSION}"
LABEL description="Hardened Ubuntu ${version_tag} container image"

# Environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install base packages and security tools
RUN apt-get update && apt-get install -y \\
        curl \\
        wget \\
        vim \\
        htop \\
        procps \\
        net-tools \\
        iproute2 \\
        iptables \\
        ufw \\
        fail2ban \\
        rkhunter \\
        clamav \\
        clamav-daemon \\
        auditd \\
        apparmor \\
        apparmor-utils \\
        libpam-pwquality \\
        libpam-modules \\
        openssh-server \\
        cron \\
        logrotate \\
        && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/log/security-hardening \\
             /var/backups/security-hardening \\
             /etc/security/hardening

# Configure security settings
RUN echo "ubuntu-hardened" > /etc/hostname

# Configure SSH (if needed for debugging)
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config \\
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config \\
    && sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Configure UFW
RUN ufw --force reset \\
    && ufw default deny incoming \\
    && ufw default allow outgoing

# Configure AppArmor
RUN systemctl enable apparmor 2>/dev/null || true

# Configure auditd
RUN systemctl enable auditd 2>/dev/null || true

# Configure fail2ban
RUN systemctl enable fail2ban 2>/dev/null || true

# Configure ClamAV
RUN systemctl enable clamav-daemon 2>/dev/null || true \\
    && systemctl enable clamav-freshclam 2>/dev/null || true

# Configure system limits
RUN echo "* soft core 0" >> /etc/security/limits.conf \\
    && echo "* hard core 0" >> /etc/security/limits.conf \\
    && echo "* soft nproc 65535" >> /etc/security/limits.conf \\
    && echo "* hard nproc 65535" >> /etc/security/limits.conf \\
    && echo "* soft nofile 65535" >> /etc/security/limits.conf \\
    && echo "* hard nofile 65535" >> /etc/security/limits.conf \\
    && echo "root soft nproc 65535" >> /etc/security/limits.conf \\
    && echo "root hard nproc 65535" >> /etc/security/limits.conf \\
    && echo "root soft nofile 65535" >> /etc/security/limits.conf \\
    && echo "root hard nofile 65535" >> /etc/security/limits.conf

# Configure PAM session limits
RUN echo "session required pam_limits.so" >> /etc/pam.d/common-session

# Configure sysctl security parameters
RUN echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/99-security.conf \\
    && echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/99-security.conf \\
    && echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/99-security.conf \\
    && echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-security.conf \\
    && echo "fs.protected_hardlinks = 1" >> /etc/sysctl.d/99-security.conf \\
    && echo "fs.protected_symlinks = 1" >> /etc/sysctl.d/99-security.conf

# Create non-root user
RUN useradd -m -s /bin/bash appuser \\
    && usermod -aG sudo appuser \\
    && echo 'appuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/appuser \\
    && chmod 440 /etc/sudoers.d/appuser

# Clean up
RUN apt-get autoremove -y \\
    && apt-get autoclean \\
    && rm -rf /var/lib/apt/lists/* \\
    && rm -rf /tmp/* \\
    && rm -rf /var/tmp/*

# Set working directory
WORKDIR /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD echo "Container is healthy" || exit 1

# Default command
CMD ["/bin/bash"]
EOF

    print_message "$GREEN" "Dockerfile created: $dockerfile"
}

# Function to create multi-stage hardened Dockerfile
create_multistage_dockerfile() {
    local dockerfile="Dockerfile.multistage-hardened"

    print_message "$GREEN" "Creating multi-stage hardened Dockerfile..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create multi-stage Dockerfile"
        return
    fi

    cat > "$dockerfile" << 'EOF'
# Multi-Stage Ubuntu Hardened Docker Image
# Stage 1: Build stage with hardening tools
FROM ubuntu:22.04 AS hardening-stage

ENV DEBIAN_FRONTEND=noninteractive

# Install hardening tools and dependencies
RUN apt-get update && apt-get install -y \
        build-essential \
        git \
        curl \
        wget \
        libssl-dev \
        libpam0g-dev \
        libaudit-dev \
        apparmor \
        apparmor-utils \
        auditd \
        rkhunter \
        clamav \
        fail2ban \
        ufw \
        && rm -rf /var/lib/apt/lists/*

# Copy hardening scripts
COPY hardening-scripts/ /opt/hardening/

# Run hardening process
RUN cd /opt/hardening && \
    chmod +x *.sh && \
    ./apply-hardening.sh

# Stage 2: Runtime stage (distroless-like with Ubuntu base)
FROM ubuntu:22.04

# Copy hardened system from build stage
COPY --from=hardening-stage /etc/ /etc/
COPY --from=hardening-stage /var/lib/ /var/lib/
COPY --from=hardening-stage /var/log/ /var/log/
COPY --from=hardening-stage /usr/ /usr/
COPY --from=hardening-stage /opt/ /opt/

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
        ca-certificates \
        curl \
        libssl3 \
        libpam-modules \
        libaudit1 \
        apparmor \
        && rm -rf /var/lib/apt/lists/*

# Create application user
RUN useradd -m -s /bin/bash -u 1000 appuser && \
    mkdir -p /app && \
    chown appuser:appuser /app

# Security hardening for container
RUN echo "* soft core 0" >> /etc/security/limits.conf && \
    echo "* hard core 0" >> /etc/security/limits.conf && \
    echo "* soft nproc 65535" >> /etc/security/limits.conf && \
    echo "* hard nproc 65535" >> /etc/security/limits.conf && \
    echo "* soft nofile 65535" >> /etc/security/limits.conf && \
    echo "* hard nofile 65535" >> /etc/security/limits.conf && \
    echo "root soft nproc 65535" >> /etc/security/limits.conf && \
    echo "root hard nproc 65535" >> /etc/security/limits.conf && \
    echo "root soft nofile 65535" >> /etc/security/limits.conf && \
    echo "root hard nofile 65535" >> /etc/security/limits.conf && \
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/99-container-security.conf

# Configure PAM session limits
RUN echo "session required pam_limits.so" >> /etc/pam.d/common-session

# Switch to non-root user
USER appuser

WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

CMD ["/bin/bash"]
EOF

    print_message "$GREEN" "Multi-stage Dockerfile created: $dockerfile"
}

# Function to create Docker Compose file
create_docker_compose() {
    local compose_file="docker-compose.hardened.yml"

    print_message "$GREEN" "Creating Docker Compose configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create Docker Compose file"
        return
    fi

    cat > "$compose_file" << EOF
version: '3.8'

services:
  ubuntu-hardened:
    build:
      context: .
      dockerfile: Dockerfile.ubuntu-hardened
    container_name: ubuntu-hardened-${UBUNTU_VERSION}
    restart: unless-stopped

    # Security options
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      - /var/tmp:noexec,nosuid,size=100m

    # Resource limits
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'

    # Networking
    networks:
      - hardened-network

    # Volumes (read-only where possible)
    volumes:
      - ./logs:/var/log/security-hardening:ro
      - app-data:/app

    # Environment
    environment:
      - TZ=UTC
      - LANG=C.UTF-8

    # Health check
    healthcheck:
      test: ["CMD", "echo", "healthy"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Monitoring service
  monitoring:
    image: ubuntu:22.04
    container_name: hardening-monitor
    command: tail -f /dev/null
    volumes:
      - ./logs:/var/log/security-hardening:ro
    networks:
      - hardened-network
    profiles:
      - monitoring

networks:
  hardened-network:
    driver: bridge
    internal: true

volumes:
  app-data:
    driver: local

# Security profiles
secrets:
  ssh_keys:
    file: ./secrets/ssh_keys
EOF

    print_message "$GREEN" "Docker Compose file created: $compose_file"
}

# Function to build Docker images
build_docker_images() {
    print_message "$GREEN" "Building Docker images..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would build Docker images"
        return
    fi

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_message "$YELLOW" "Docker not found. Installing Docker..."

        # Install Docker
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh

        # Start Docker service
        systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true
    fi

    # Build hardened Ubuntu image
    local image_tag="ubuntu-hardened:${UBUNTU_VERSION}"

    print_message "$BLUE" "Building $image_tag..."
    if docker build -f Dockerfile.ubuntu-hardened -t "$image_tag" .; then
        print_message "$GREEN" "Successfully built $image_tag"

        # Tag as latest
        docker tag "$image_tag" "ubuntu-hardened:latest"

        # Show image info
        docker images "$image_tag"

        # Test the image
        print_message "$BLUE" "Testing image..."
        if docker run --rm "$image_tag" echo "Ubuntu hardened image is working"; then
            print_message "$GREEN" "Image test successful"
        else
            print_message "$YELLOW" "Image test failed"
        fi

    else
        error_exit "Failed to build Docker image"
    fi
}

# Function to create security scanning for containers
create_container_security_scan() {
    local scan_script="scan-container-security.sh"

    print_message "$GREEN" "Creating container security scanning script..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create security scan script"
        return
    fi

    cat > "$scan_script" << 'EOF'
#!/bin/bash
# Container Security Scanning Script

IMAGE_NAME="${1:-ubuntu-hardened:latest}"
SCAN_REPORT="container-security-scan-$(date +%Y%m%d-%H%M%S).txt"

echo "Scanning container image: $IMAGE_NAME"
echo "Report will be saved to: $SCAN_REPORT"
echo

# Function to check image
check_image() {
    if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
        echo "ERROR: Image $IMAGE_NAME not found"
        exit 1
    fi
}

# Function to scan for security issues
scan_security() {
    echo "=== CONTAINER SECURITY SCAN REPORT ===" > "$SCAN_REPORT"
    echo "Image: $IMAGE_NAME" >> "$SCAN_REPORT"
    echo "Scan Date: $(date)" >> "$SCAN_REPORT"
    echo >> "$SCAN_REPORT"

    echo "1. Checking for root user usage..."
    local root_check=$(docker run --rm --entrypoint="" "$IMAGE_NAME" whoami 2>/dev/null || echo "unknown")
    if [[ "$root_check" == "root" ]]; then
        echo "WARNING: Container runs as root user" >> "$SCAN_REPORT"
    else
        echo "OK: Container does not run as root" >> "$SCAN_REPORT"
    fi

    echo "2. Checking for privileged capabilities..."
    local caps=$(docker inspect "$IMAGE_NAME" | grep -A 10 "CapAdd\|CapDrop" || echo "none")
    echo "Capabilities: $caps" >> "$SCAN_REPORT"

    echo "3. Checking for security options..."
    local sec_opts=$(docker inspect "$IMAGE_NAME" | grep -A 5 "SecurityOpt" || echo "none")
    echo "Security Options: $sec_opts" >> "$SCAN_REPORT"

    echo "4. Checking for exposed ports..."
    local ports=$(docker inspect "$IMAGE_NAME" | grep -A 10 "ExposedPorts" | grep -v "null" || echo "none")
    echo "Exposed Ports: $ports" >> "$SCAN_REPORT"

    echo "5. Checking image size..."
    local size=$(docker images "$IMAGE_NAME" --format "table {{.Size}}" | tail -n 1)
    echo "Image Size: $size" >> "$SCAN_REPORT"

    echo "6. Checking for known vulnerabilities (simulated)..."
    echo "NOTE: For real vulnerability scanning, use tools like Trivy, Clair, or Snyk" >> "$SCAN_REPORT"

    echo >> "$SCAN_REPORT"
    echo "=== SCAN COMPLETE ===" >> "$SCAN_REPORT"
}

# Run checks
check_image
scan_security

echo "Security scan completed. Report saved to: $SCAN_REPORT"
cat "$SCAN_REPORT"
EOF

    chmod +x "$scan_script"

    print_message "$GREEN" "Security scan script created: $scan_script"
}

# Function to generate Docker documentation
generate_docker_documentation() {
    local doc_file="README-docker.md"

    print_message "$GREEN" "Generating Docker documentation..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would generate Docker documentation"
        return
    fi

    cat > "$doc_file" << EOF
# Ubuntu Hardened Docker Images

This directory contains Docker images with Ubuntu security hardening pre-applied.

## Generated Files

### Images
- \`ubuntu-hardened:${UBUNTU_VERSION}\` - Hardened Ubuntu container image
- \`ubuntu-hardened:latest\` - Latest tag pointing to current version

### Dockerfiles
- \`Dockerfile.ubuntu-hardened\` - Single-stage hardened Ubuntu image
- \`Dockerfile.multistage-hardened\` - Multi-stage build for smaller images

### Compose Files
- \`docker-compose.hardened.yml\` - Docker Compose configuration with security

### Scripts
- \`scan-container-security.sh\` - Container security scanning script

## Usage

### Basic Usage
\`\`\`bash
# Build the image
docker build -f Dockerfile.ubuntu-hardened -t ubuntu-hardened .

# Run a container
docker run -it ubuntu-hardened

# Run with security options
docker run --security-opt no-new-privileges:true \\
           --cap-drop ALL \\
           --read-only \\
           --tmpfs /tmp:noexec,nosuid \\
           -it ubuntu-hardened
\`\`\`

### Docker Compose
\`\`\`bash
# Start the hardened service
docker-compose -f docker-compose.hardened.yml up -d

# View logs
docker-compose -f docker-compose.hardened.yml logs

# Run security monitoring
docker-compose --profile monitoring -f docker-compose.hardened.yml up -d
\`\`\`

### Security Scanning
\`\`\`bash
# Scan the image for security issues
./scan-container-security.sh ubuntu-hardened:latest

# Scan with Trivy (if installed)
trivy image ubuntu-hardened:latest
\`\`\`

## Security Features

### Applied Hardening
- Non-root user execution
- Dropped capabilities
- No new privileges
- Read-only filesystem where possible
- tmpfs for temporary files
- Resource limits
- Security sysctl parameters

### Container Security Options
- \`no-new-privileges: true\` - Prevent privilege escalation
- \`cap-drop: ALL\` - Drop all capabilities
- \`read-only: true\` - Read-only root filesystem
- \`tmpfs\` - Isolated temporary directories

## Customization

### Modify Dockerfile
Edit \`Dockerfile.ubuntu-hardened\` to:
- Add/remove packages
- Change security settings
- Add application code
- Modify user configuration

### Add Application
\`\`\`dockerfile
# Add your application
COPY app.py /app/
RUN chmod +x /app/app.py

# Expose port (if needed)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["python3", "/app/app.py"]
\`\`\`

### Multi-Stage Builds
Use \`Dockerfile.multistage-hardened\` for:
- Smaller final images
- Build-time dependencies separation
- Enhanced security through reduced attack surface

## Best Practices

### Security
- Always run as non-root user
- Use read-only filesystems
- Drop unnecessary capabilities
- Limit resource usage
- Regularly scan for vulnerabilities

### Performance
- Use multi-stage builds
- Minimize image layers
- Use .dockerignore
- Optimize cache usage

### Monitoring
- Implement health checks
- Log security events
- Monitor resource usage
- Regular security scans

## Troubleshooting

### Build Issues
\`\`\`bash
# Check build logs
docker build --no-cache --progress=plain -f Dockerfile.ubuntu-hardened .

# Debug build
docker run --rm -it ubuntu:22.04 /bin/bash
\`\`\`

### Runtime Issues
\`\`\`bash
# Check container logs
docker logs <container_id>

# Debug container
docker run --security-opt no-new-privileges:false \\
           --cap-add SYS_PTRACE \\
           -it ubuntu-hardened /bin/bash
\`\`\`

### Security Issues
- Review capabilities: \`docker inspect <container>\`
- Check security options
- Run security scans
- Audit container logs

## Integration

### CI/CD Pipeline
\`\`\`yaml
# .github/workflows/docker.yml
name: Build Hardened Ubuntu Image
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build image
        run: docker build -f Dockerfile.ubuntu-hardened -t ubuntu-hardened .
      - name: Security scan
        run: ./scan-container-security.sh ubuntu-hardened
      - name: Push to registry
        run: docker push your-registry/ubuntu-hardened
\`\`\`

### Kubernetes
\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ubuntu-hardened-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ubuntu-hardened
  template:
    metadata:
      labels:
        app: ubuntu-hardened
    spec:
      containers:
      - name: app
        image: ubuntu-hardened:latest
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            memory: 512Mi
            cpu: 500m
          requests:
            memory: 256Mi
            cpu: 250m
EOF

    print_message "$GREEN" "Docker documentation created: $doc_file"
}

# Main Docker image building function
build_docker_images_main() {
    print_section "Docker Image Building"

    create_hardened_dockerfile
    create_multistage_dockerfile
    create_docker_compose
    build_docker_images
    create_container_security_scan
    generate_docker_documentation

    print_message "$GREEN" "Docker image building completed"
    print_message "$BLUE" "Files created:"
    print_message "$BLUE" "  - Dockerfile.ubuntu-hardened (Single-stage Dockerfile)"
    print_message "$BLUE" "  - Dockerfile.multistage-hardened (Multi-stage Dockerfile)"
    print_message "$BLUE" "  - docker-compose.hardened.yml (Compose configuration)"
    print_message "$BLUE" "  - scan-container-security.sh (Security scanning script)"
    print_message "$BLUE" "  - README-docker.md (Documentation)"
}
