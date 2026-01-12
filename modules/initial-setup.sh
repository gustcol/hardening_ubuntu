#!/bin/bash
# Initial Server Setup Module
# Based on du_setup.sh functionality with enhanced features

# Function to detect environment (cloud vs personal VM)
detect_environment() {
    print_message "$GREEN" "Detecting environment..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would detect environment"
        return
    fi

    local VIRT_TYPE=""
    local MANUFACTURER=""
    local PRODUCT=""
    local IS_CLOUD_VPS=false
    local ENVIRONMENT_TYPE="unknown"
    local DETECTED_PROVIDER_NAME=""

    # systemd-detect-virt
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    fi

    # dmidecode for hardware info
    if command -v dmidecode &>/dev/null && [[ $(id -u) -eq 0 ]]; then
        MANUFACTURER=$(dmidecode -s system-manufacturer 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "unknown")
        PRODUCT=$(dmidecode -s system-product-name 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "unknown")
    fi

    # Check /sys/class/dmi/id/ (fallback)
    if [[ -z "$MANUFACTURER" || "$MANUFACTURER" == "unknown" ]]; then
        if [[ -r /sys/class/dmi/id/sys_vendor ]]; then
            MANUFACTURER=$(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "unknown")
        fi
    fi

    if [[ -z "$PRODUCT" || "$PRODUCT" == "unknown" ]]; then
        if [[ -r /sys/class/dmi/id/product_name ]]; then
            PRODUCT=$(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_name 2>/dev/null || echo "unknown")
        fi
    fi

    # Cloud provider detection patterns
    local CLOUD_PATTERNS=(
        "digitalocean" "linode" "vultr" "hetzner" "ovh" "scaleway" "contabo"
        "netcup" "ionos" "hostinger" "racknerd" "upcloud" "dreamhost"
        "amazon" "aws" "google" "gce" "microsoft" "azure" "oracle"
    )

    # Check if manufacturer or product matches cloud patterns
    for pattern in "${CLOUD_PATTERNS[@]}"; do
        if [[ "$MANUFACTURER" == *"$pattern"* ]] || [[ "$PRODUCT" == *"$pattern"* ]]; then
            IS_CLOUD_VPS=true
            break
        fi
    done

    # Determine environment type
    case "$VIRT_TYPE" in
        none)
            ENVIRONMENT_TYPE="bare-metal"
        ;;
        kvm|qemu)
            if [[ "$IS_CLOUD_VPS" == "true" ]]; then
                ENVIRONMENT_TYPE="commercial-cloud"
            else
                ENVIRONMENT_TYPE="personal-vm"
            fi
        ;;
        vmware|virtualbox|oracle)
            ENVIRONMENT_TYPE="personal-vm"
        ;;
        xen)
            ENVIRONMENT_TYPE="commercial-cloud"
        ;;
        *)
            ENVIRONMENT_TYPE="unknown"
        ;;
    esac

    # Set provider name
    case "$ENVIRONMENT_TYPE" in
        commercial-cloud)
            if [[ "$MANUFACTURER" == *"digitalocean"* ]]; then
                DETECTED_PROVIDER_NAME="DigitalOcean"
                elif [[ "$MANUFACTURER" == *"hetzner"* ]]; then
                DETECTED_PROVIDER_NAME="Hetzner Cloud"
                elif [[ "$MANUFACTURER" == *"amazon"* ]] || [[ "$PRODUCT" == *"ec2"* ]]; then
                DETECTED_PROVIDER_NAME="Amazon Web Services (AWS)"
                elif [[ "$MANUFACTURER" == *"google"* ]]; then
                DETECTED_PROVIDER_NAME="Google Cloud Platform"
                elif [[ "$MANUFACTURER" == *"microsoft"* ]]; then
                DETECTED_PROVIDER_NAME="Microsoft Azure"
            else
                DETECTED_PROVIDER_NAME="Cloud VPS Provider"
            fi
        ;;
        personal-vm)
            if [[ "$VIRT_TYPE" == "virtualbox" ]]; then
                DETECTED_PROVIDER_NAME="VirtualBox"
                elif [[ "$VIRT_TYPE" == "vmware" ]]; then
                DETECTED_PROVIDER_NAME="VMware"
            else
                DETECTED_PROVIDER_NAME="Personal VM"
            fi
        ;;
    esac

    # Export as global variables
    export DETECTED_VIRT_TYPE="$VIRT_TYPE"
    export DETECTED_MANUFACTURER="$MANUFACTURER"
    export DETECTED_PRODUCT="$PRODUCT"
    export ENVIRONMENT_TYPE="$ENVIRONMENT_TYPE"
    export DETECTED_PROVIDER_NAME="$DETECTED_PROVIDER_NAME"

    print_message "$GREEN" "Environment detected: $ENVIRONMENT_TYPE"
    if [[ -n "$DETECTED_PROVIDER_NAME" ]]; then
        print_message "$GREEN" "Provider: $DETECTED_PROVIDER_NAME"
    fi
}

# Function to configure timezone with locale support
configure_timezone() {
    print_message "$GREEN" "Configuring timezone..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure timezone"
        return
    fi

    # Detect timezone or prompt user
    if [[ "$MODE" == "interactive" ]]; then
        echo "Available timezones:"
        timedatectl list-timezones | head -20
        read -p "Enter timezone (default: UTC): " timezone
        timezone=${timezone:-UTC}
    else
        timezone="UTC"
    fi

    timedatectl set-timezone "$timezone"
    print_message "$GREEN" "Timezone set to: $timezone"

    # Configure locales if interactive
    if [[ "$MODE" == "interactive" ]] && confirm "Configure system locales interactively?"; then
        dpkg-reconfigure locales
        print_info "Applying new locale settings to the current session..."
        if [[ -f /etc/default/locale ]]; then
            source /etc/default/locale
            export $(grep -v '^#' /etc/default/locale | cut -d= -f1)
            print_message "$GREEN" "Locale environment updated for this session."
        fi
    fi
}

# Function to configure custom .bashrc (from du_setup.sh)
configure_custom_bashrc() {
    local USER_HOME="$1"
    local USERNAME="$2"
    local BASHRC_PATH="$USER_HOME/.bashrc"

    if ! confirm "Replace default .bashrc for '$USERNAME' with a custom feature-rich one?" "n"; then
        print_info "Skipping custom .bashrc configuration."
        return 0
    fi

    print_info "Preparing custom .bashrc for '$USERNAME'..."

    # Create comprehensive .bashrc
    cat > "$BASHRC_PATH" << 'EOF'
# shellcheck shell=bash
# ===================================================================
#   Universal Portable .bashrc for Modern Terminals
#   Optimized for Debian/Ubuntu servers with multi-terminal support
# ===================================================================

# If not running interactively, don't do anything.
case $- in
    *i*) ;;
      *) return;;
esac

# --- History Control ---
# Don't put duplicate lines or lines starting with space in the history.
HISTCONTROL=ignoreboth:erasedups
# Append to the history file, don't overwrite it.
shopt -s histappend
# Set history length with reasonable values for server use.
HISTSIZE=10000
HISTFILESIZE=20000
# Allow editing of commands recalled from history.
shopt -s histverify
# Add timestamp to history entries for audit trail (ISO 8601 format).
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
# Ignore common commands from history to reduce clutter.
HISTIGNORE="ls:ll:la:l:cd:pwd:exit:clear:c:history:h"

# --- General Shell Behavior & Options ---
# Check the window size after each command and update LINES and COLUMNS.
shopt -s checkwinsize
# Allow using '**' for recursive globbing (Bash 4.0+, suppress errors on older versions).
shopt -s globstar 2>/dev/null
# Allow changing to a directory by just typing its name (Bash 4.0+).
shopt -s autocd 2>/dev/null
# Autocorrect minor spelling errors in directory names (Bash 4.0+).
shopt -s cdspell 2>/dev/null
shopt -s dirspell 2>/dev/null
# Correct multi-line command editing.
shopt -s cmdhist 2>/dev/null

# Set command-line editing mode. Emacs (default) or Vi.
set -o emacs

# Make `less` more friendly for non-text input files.
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# --- Better Less Configuration ---
# Make less more friendly - R shows colors, F quits if one screen, X prevents screen clear.
export LESS='-R -F -X -i -M -w'
# Colored man pages using less (TERMCAP sequences).
export LESS_TERMCAP_mb=$'\e[1;31m'      # begin blink
export LESS_TERMCAP_md=$'\e[1;36m'      # begin bold
export LESS_TERMCAP_me=$'\e[0m'         # reset bold/blink
export LESS_TERMCAP_so=$'\e[01;44;33m'  # begin reverse video
export LESS_TERMCAP_se=$'\e[0m'         # reset reverse video
export LESS_TERMCAP_us=$'\e[1;32m'      # begin underline
export LESS_TERMCAP_ue=$'\e[0m'         # reset underline

# --- Terminal & SSH Compatibility Fixes ---
# Handle Kitty terminal over SSH - fallback to xterm-256color if terminfo unavailable.
if [[ "$TERM" == "xterm-kitty" ]]; then
    # Check if kitty terminfo is available, otherwise fallback.
    if ! infocmp xterm-kitty &>/dev/null; then
        export TERM=xterm-256color
    fi
    # Ensure the shell looks for user-specific terminfo files.
    [[ -d "$HOME/.terminfo" ]] && export TERMINFO="$HOME/.terminfo"
fi

# Fix for other modern terminals that might not be recognized on older servers.
case "$TERM" in
    alacritty|wezterm)
        if ! infocmp "$TERM" &>/dev/null; then
            export TERM=xterm-256color
        fi
        ;;
esac

# --- Prompt Configuration ---
# Set variable identifying the chroot you work in (used in the prompt below).
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(</etc/debian_chroot)
fi

# Set a colored prompt only if the terminal has color capability.
case "$TERM" in
    xterm-color|*-256color|xterm-kitty|alacritty|wezterm) color_prompt=yes;;
esac

# Force color prompt support check using tput.
if [ -z "${color_prompt}" ] && [ -x /usr/bin/tput ] && tput setaf 1 &>/dev/null; then
    color_prompt=yes
fi

# --- Function to parse git branch only if in a git repo ---
parse_git_branch() {
    if git rev-parse --git-dir &>/dev/null; then
        git branch 2>/dev/null | sed -n '/^\*/s/\* \(.*\)/\1/p'
    fi
    return 0
}

# --- Main prompt command function ---
__bash_prompt_command() {
    local rc=$?  # Capture last command exit status
    history -a
    history -n

    # --- Initialize prompt components ---
    local prompt_err="" prompt_git="" prompt_jobs="" prompt_venv=""
    local git_branch job_count

    # Error indicator
    (( rc != 0 )) && prompt_err="\[\e[31m\]✗\[\e[0m\]"

    # Git branch (dim yellow)
    git_branch=$(parse_git_branch)
    [[ -n "$git_branch" ]] && prompt_git="\[\e[2;33m\]($git_branch)\[\e[0m\]"

    # Background jobs (cyan)
    job_count=$(jobs -p | wc -l)
    (( job_count > 0 )) && prompt_jobs="\[\e[36m\]⚡${job_count}\[\e[0m\]"

    # Python virtualenv (dim green)
    [[ -n "$VIRTUAL_ENV" ]] && prompt_venv="\[\e[2;32m\][${VIRTUAL_ENV##*/}]\[\e[0m\]"

    # Ensure spacing between components
    [[ -n "$prompt_venv" ]] && prompt_venv=" $prompt_venv"
    [[ -n "$prompt_git" ]] && prompt_git=" $prompt_git"
    [[ -n "$prompt_jobs" ]] && prompt_jobs=" $prompt_jobs"
    [[ -n "$prompt_err" ]] && prompt_err=" $prompt_err"

    # --- Assemble PS1 ---
    if [ "$color_prompt" = yes ]; then
        PS1='${debian_chroot:+($debian_chroot)}\[\e[32m\]\u@\h\[\e[0m\]:\[\e[34m\]\w\[\e[0m\]'"${prompt_venv}${prompt_git}${prompt_jobs}${prompt_err}"' \$ '
    else
        PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w'"${prompt_venv}${git_branch}${prompt_jobs}${prompt_err}"' \$ '
    fi

    # --- Set Terminal Window Title ---
    case "$TERM" in
      xterm*|rxvt*|xterm-kitty|alacritty|wezterm)
        PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
        ;;
    esac
}

# --- Activate dynamic prompt ---
PROMPT_COMMAND=__bash_prompt_command

# --- Editor Configuration ---
if command -v vim &>/dev/null; then
    export EDITOR=vim
    export VISUAL=vim
elif command -v nano &>/dev/null; then
    export EDITOR=nano
    export VISUAL=nano
else
    export EDITOR=vi
    export VISUAL=vi
fi

# --- Additional Environment Variables ---
# Set default pager.
export PAGER=less
# Prevent Ctrl+S from freezing the terminal.
stty -ixon 2>/dev/null

# --- Useful Functions ---
# Create a directory and change into it.
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# Create a backup of a file with timestamp.
backup() {
    if [ -f "$1" ]; then
        local backup_file; backup_file="$1.backup-$(date +%Y%m%d-%H%M%S)"
        cp "$1" "$backup_file"
        echo "Backup created: $backup_file"
    else
        echo "'$1' is not a valid file" >&2
        return 1
    fi
}

# Extract any archive file with a single command.
extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2)   tar xjf "$1"      ;;
            *.tar.gz)    tar xzf "$1"      ;;
            *.tar.xz)    tar xJf "$1"      ;;
            *.bz2)       bunzip2 "$1"      ;;
            *.rar)       unrar x "$1"      ;;
            *.gz)        gunzip "$1"       ;;
            *.tar)       tar xf "$1"       ;;
            *.tbz2)      tar xjf "$1"      ;;
            *.tgz)       tar xzf "$1"      ;;
            *.zip)       unzip "$1"        ;;
            *.Z)         uncompress "$1"   ;;
            *.7z)        7z x "$1"         ;;
            *.tar.zst)
                if command -v zstd &>/dev/null; then
                    zstd -dc "$1" | tar xf -
                else
                    tar --zstd -xf "$1"
                fi
                ;;
            *)
                echo "'$1' cannot be extracted via extract()" >&2
                return 1
                ;;
        esac
    else
        echo "'$1' is not a valid file" >&2
        return 1
    fi
}

# Quick directory navigation up multiple levels.
up() {
    local d=""
    local limit="${1:-1}"
    for ((i=1; i<=limit; i++)); do
        d="../$d"
    done
    cd "$d" || return
}

# Find files by name in current directory tree.
ff() {
    find . -type f -iname "*$1*" 2>/dev/null
}

# Find directories by name in current directory tree.
fd() {
    find . -type d -iname "*$1*" 2>/dev/null
}

# Search for text in files recursively.
ftext() {
    grep -rnw . -e "$1" 2>/dev/null
}

# Search history easily
hgrep() { history | grep -i --color=auto "$@"; }

# Create a tarball of a directory.
targz() {
    if [ -d "$1" ]; then
        tar czf "${1%%/}.tar.gz" "${1%%/}"
        echo "Created ${1%%/}.tar.gz"
    else
        echo "'$1' is not a valid directory" >&2
        return 1
    fi
}

# Show disk usage of current directory, sorted by size.
duh() {
    du -h --max-depth=1 "${1:-.}" | sort -hr
}

# Get the size of a file or directory.
sizeof() {
    du -sh "$1" 2>/dev/null
}

# Show most used commands from history.
histop() {
    history | awk -v ig="$HISTIGNORE" 'BEGIN{OFS="\t";gsub(/:/,"|",ig);ir="^("ig")($| )";sr="(^|\\s)\\./"}
    {cmd=$4;for(i=5;i<=NF;i++)cmd=cmd" "$i}
    (cmd==""||cmd~ir||cmd~sr){next}
    {C[cmd]++;t++}
    END{if(t>0)for(a in C)printf"%d\t%.2f%%\t%s\n",C[a],(C[a]/t*100),a}' |
    sort -nr | head -n20 |
    awk 'BEGIN{
        FS="\t";
        maxc=length("COUNT");
        maxp=length("PERCENT");
    }
    {
        data[NR]=$0;
        len1=length($1);
        len2=length($2);
        if(len1>maxc)maxc=len1;
        if(len2>maxp)maxp=len2;
    }
    END{
        fmt="  %-4s %-*s  %-*s  %s\n";
        printf fmt,"RANK",maxc,"COUNT",maxp,"PERCENT","COMMAND";
        sep_c=sep_p="";
        for(i=1;i<=maxc;i++)sep_c=sep_c"-";
        for(i=1;i<=maxp;i++)sep_p=sep_p"-";
        printf fmt,"----",maxc,sep_c,maxp,sep_p,"-------";
        for(i=1;i<=NR;i++){
            split(data[i],f,"\t");
            printf fmt,i".",maxc,f[1],maxp,f[2],f[3]
        }
    }'
}

# Quick server info display
sysinfo() {
    # --- Self-Contained Color Detection ---
    local color_support=""
    case "$TERM" in
        xterm-color|*-256color|xterm-kitty|alacritty|wezterm) color_support="yes";;
    esac
    if [ -z "$color_support" ] && [ -x /usr/bin/tput ] && tput setaf 1 &>/dev/null; then
        color_support="yes"
    fi

    # --- Color Definitions ---
    if [ "$color_support" = "yes" ]; then
        local CYAN='\e[1;36m'
        local YELLOW='\e[1;33m'
        local BOLD_RED='\e[1;31m'
        local BOLD_WHITE='\e[1;37m'
        local GREEN='\e[1;32m'
        local DIM='\e[2m'
        local RESET='\e[0m'
    else
        local CYAN='' YELLOW='' BOLD_RED='' BOLD_WHITE='' GREEN='' DIM='' RESET=''
    fi

    # --- Header ---
    printf "\n${BOLD_WHITE}=== System Information ===${RESET}\n"

    # --- CPU Info ---
    local cpu_info
    cpu_info=$(lscpu | awk -F: '/Model name/ {print $2; exit}' | xargs || grep -m1 'model name' /proc/cpuinfo | cut -d ':' -f2 | xargs)
    [ -z "$cpu_info" ] && cpu_info="Unknown"

    # --- IP Detection ---
    local ip_addr public_ipv4 public_ipv6

    # Try to get public IPv4 first
    public_ipv4=$(curl -4 -s -m 2 --connect-timeout 1 https://checkip.amazonaws.com 2>/dev/null || \
                  curl -4 -s -m 2 --connect-timeout 1 https://ipconfig.io 2>/dev/null || \
                  curl -4 -s -m 2 --connect-timeout 1 https://api.ipify.org 2>/dev/null)
    # If no IPv4, try IPv6
    if [ -z "$public_ipv4" ]; then
        public_ipv6=$(curl -6 -s -m 2 --connect-timeout 1 https://ipconfig.io 2>/dev/null || \
                      curl -6 -s -m 2 --connect-timeout 1 https://icanhazip.co 2>/dev/null || \
                      curl -6 -s -m 2 --connect-timeout 1 https://api64.ipify.org 2>/dev/null)
    fi
    # Get local/internal IP as fallback
    for iface in eth0 ens3 enp0s3 enp0s6 wlan0 ens33 eno1; do
        ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1)
        [ -n "$ip_addr" ] && break
    done
    [ -z "$ip_addr" ] && ip_addr=$(ip -4 addr show scope global 2>/dev/null | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1)

    # --- System Info ---
    if [ -n "$public_ipv4" ]; then
        # Show public IPv4 (preferred)
        printf "${CYAN}%-15s${RESET} %s  ${YELLOW}[%s]${RESET}" "Hostname:" "$(hostname)" "$public_ipv4"
        # Show local IP if different from public
        if [ -n "$ip_addr" ] && [ "$ip_addr" != "$public_ipv4" ]; then
            printf " ${DIM}(local: %s)${RESET}\n" "$ip_addr"
        else
            printf "\n"
        fi
    elif [ -n "$public_ipv6" ]; then
        # Show public IPv6 if no IPv4
        printf "${CYAN}%-15s${RESET} %s  ${YELLOW}[%s]${RESET}" "Hostname:" "$(hostname)" "$public_ipv6"
        [ -n "$ip_addr" ] && printf " ${DIM}(local: %s)${RESET}\n" "$ip_addr" || printf "\n"
    elif [ -n "$ip_addr" ]; then
        # Show local IP only
        printf "${CYAN}%-15s${RESET} %s  ${YELLOW}[%s]${RESET}\n" "Hostname:" "$(hostname)" "$ip_addr"
    else
        # No IP detected
        printf "${CYAN}%-15s${RESET} %s\n" "Hostname:" "$(hostname)"
    fi
    printf "${CYAN}%-15s${RESET} %s\n" "OS:" "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo 'Unknown')"
    printf "${CYAN}%-15s${RESET} %s\n" "Kernel:" "$(uname -r)"
    printf "${CYAN}%-15s${RESET} %s\n" "Uptime:" "$(uptime -p 2>/dev/null || uptime | sed 's/.*up //' | sed 's/,.*//')"
    printf "${CYAN}%-15s${RESET} %s\n" "Server time:" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf "${CYAN}%-15s${RESET} %s\n" "CPU:" "$cpu_info"
    printf "${CYAN}%-15s${RESET} " "Memory:"
    free -m | awk '/Mem/ {
        used = $3; total = $2; percent = int((used/total)*100);
        if (used >= 1024) { used_fmt = sprintf("%.1fGi", used/1024); } else { used_fmt = sprintf("%dMi", used); }
        if (total >= 1024) { total_fmt = sprintf("%.1fGi", total/1024); } else { total_fmt = sprintf("%dMi", total); }
        printf "%s / %s (%d%% used)\n", used_fmt, total_fmt, percent;
    }'
    printf "${CYAN}%-15s${RESET} %s\n" "Disk (/):" "$(df -h / | awk 'NR==2 {print $3 " / " $2 " (" $5 " used)"}')"

    # --- Reboot Status ---
    if [ -f /var/run/reboot-required ]; then
        printf "${CYAN}%-15s${RESET} ${BOLD_RED}⚠ REBOOT REQUIRED${RESET}\n" "System:"
        [ -s /var/run/reboot-required.pkgs ] && \
            printf "               ${DIM}Reason:${RESET} %s\n" "$(paste -sd ' ' /var/run/reboot-required.pkgs)"
    fi

    # --- Available Updates (APT) ---
    if command -v apt-get &>/dev/null; then
        local total security
        local upgradable_all upgradable_list security_list
        if [ -x /usr/lib/update-notifier/apt-check ]; then
            local apt_check_output
            apt_check_output=$(/usr/lib/update-notifier/apt-check 2>/dev/null)
            if [ -n "$apt_check_output" ]; then
                total="${apt_check_output%%;}"
                security="${apt_check_output##*;}"
            fi
        fi

        # Fallback if apt-check didn't provide values
        if [ -z "$total" ] && [ -r /var/lib/update-notifier/updates-available ]; then
            total=$(awk '/[0-9]+ (update|package)s? can be (updated|applied|installed)/ {print $1; exit}' /var/lib/update-notifier/updates-available 2>/dev/null)
            security=$(awk '/[0-9]+ (update|package)s? .*security/ {print $1; exit}' /var/lib/update-notifier/updates-available 2>/dev/null)
        fi

        # Final fallback
        if [ -z "$total" ]; then
            total=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
            security=$(apt list --upgradable 2>/dev/null | grep -ci security)
        fi

        total="${total:-0}"
        security="${security:-0}"

        # Display updates if available
        if [ -n "$total" ] && [ "$total" -gt 0 ] 2>/dev/null; then
            printf "${CYAN}%-15s${RESET} " "Updates:"
            if [ -n "$security" ] && [ "$security" -gt 0 ] 2>/dev/null; then
                printf "${YELLOW}%s packages (%s security)${RESET}\n" "$total" "$security"
            else
                printf "%s packages available\n" "$total"
            fi

            # List upgradable packages (up to 5) and highlight security
            mapfile -t upgradable_all < <(apt list --upgradable 2>/dev/null | tail -n +2)
            upgradable_list=$(printf "%s\n" "${upgradable_all[@]}" | head -n5 | awk -F/ '{print $1}')
            security_list=$(printf "%s\n" "${upgradable_all[@]}" | grep -i security | head -n5 | awk -F/ '{print $1}')

            [ -n "$upgradable_list" ] && \
                printf "               ${DIM}Upgradable:${RESET} %s" "$(echo "$upgradable_list" | paste -sd ', ')"
            [ "$total" -gt 5 ] && printf " ... (+%s more)\n" $((total - 5)) || printf "\n"

            [ -n "$security_list" ] && \
                printf "               ${YELLOW}Security:${RESET} %s" "$(echo "$security_list" | paste -sd ', ')"
            [ "$security" -gt 5 ] && printf " ... (+%s more)\n" $((security - 5)) || printf "\n"
        fi
    fi

    # --- Docker Info ---
    if command -v docker &>/dev/null; then
        mapfile -t docker_states < <(docker ps -a --format '{{.State}}' 2>/dev/null)
        total=${#docker_states[@]}
        if (( total > 0 )); then
            running=$(printf "%s\n" "${docker_states[@]}" | grep -c '^running$')
            printf "${CYAN}%-15s${RESET} ${GREEN}%s running${RESET} / %s total containers\n" "Docker:" "$running" "$total"
        fi
    fi

    # --- Tailscale Info (if installed and connected) ---
    if command -v tailscale &>/dev/null; then
        local ts_ipv4 ts_ipv6 ts_hostname
        # Get Tailscale IPs
        ts_ipv4=$(tailscale ip -4 2>/dev/null)
        ts_ipv6=$(tailscale ip -6 2>/dev/null)
        # Only show if connected
        if [ -n "$ts_ipv4" ] || [ -n "$ts_ipv6" ]; then
            # Get hostname from status (FIXED: use head -n1 to get only first line)
            ts_hostname=$(tailscale status --self --peers=false 2>/dev/null | head -n1 | awk '{print $2}')
            printf "${CYAN}%-15s${RESET} " "Tailscale:"
            printf "${GREEN}Connected${RESET}"
            [ -n "$ts_ipv4" ] && printf " - %s" "$ts_ipv4"
            [ -n "$ts_hostname" ] && printf " ${DIM}(%s)${RESET}" "$ts_hostname"
            printf "\n"
            # Optional: Show IPv6 on second line if available
            if [ -n "$ts_ipv6" ]; then
                printf "                ${DIM}IPv6: %s${RESET}\n" "$ts_ipv6"
            fi
        fi
    fi

    printf "\n"
}

# Check for available updates
checkupdates() {
    if [ -x /usr/lib/update-notifier/apt-check ]; then
        echo "Checking for updates..."
        /usr/lib/update-notifier/apt-check --human-readable
    elif command -v apt &>/dev/null; then
        apt list --upgradable 2>/dev/null
    else
        echo "No package manager found"
        return 1
    fi
}

# Disk space alert (warns if any partition > 80%)
diskcheck() {
    df -h | awk '
        NR > 1 {
            usage = $5
            gsub(/%/, "", usage)
            if (usage > 80) {
                printf "⚠️  %s\n", $0
                found = 1
            }
        }
        END {
            if (!found) print "✓ All disks below 80%"
        }
    '
}

# Directory bookmarks
export MARKPATH=$HOME/.marks
[ -d "$MARKPATH" ] || mkdir -p "$MARKPATH"
mark() { ln -sfn "$(pwd)" "$MARKPATH/${1:-$(basename "$PWD")}"; }
jump() { cd -P "$MARKPATH/$1" 2>/dev/null || ls -l "$MARKPATH"; }

# Service status shortcut (cleaner output)
svc() { sudo systemctl status "$1" --no-pager -l | head -20; }
alias failed='systemctl --failed --no-pager'

# Show top 10 processes by CPU
topcpu() { ps aux --sort=-%cpu | head -11; }

# Show top 10 processes by memory
topmem() { ps aux --sort=-%mem | head -11; }

# Network connections summary
netsum() {
    echo "=== Active Connections ==="
    ss -s
    echo -e "\n=== Listening Ports ==="
    sudo ss -tulnp | grep LISTEN | awk '{print $5, $7}' | sort -u
}

# --- Aliases ---
# Enable color support for common commands.
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'
    alias grep='grep --color=auto'
    alias egrep='grep -E --color=auto'
    alias fgrep='grep -F --color=auto'
    alias diff='diff --color=auto'
    alias ip='ip --color=auto'
fi

# Standard ls aliases with human-readable sizes.
alias ll='ls -alFh'
alias la='ls -A'
alias l='ls -CF'
alias lt='ls -alFht'       # Sort by modification time, newest first
alias ltr='ls -alFhtr'     # Sort by modification time, oldest first
alias lS='ls -alFhS'       # Sort by size, largest first

# Last command with sudo
alias please='sudo $(history -p !!)'

# Safety aliases to prompt before overwriting.
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias ln='ln -i'

# Convenience & Navigation aliases.
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias .....='cd ../../../..'
alias -- -='cd -'           # Go to previous directory
alias ~='cd ~'
alias h='history'
alias c='clear'
alias cls='clear'
alias reload='source ~/.bashrc && echo "Bashrc reloaded!"'

# PATH printer as a function (portable, no echo -e)
unalias path 2>/dev/null
path() {
    printf '%s\n' "${PATH//:/$'\n'}"
}

# Enhanced directory listing.
alias lsd='ls -d */ 2>/dev/null'      # List only directories
alias lsf='find . -maxdepth 1 -type f -printf "%f\n"'

# System resource helpers.
alias df='df -h'
alias du='du -h'
alias free='free -h'
# psgrep as a function to accept patterns reliably
# Ensure no alias conflict before defining the function
unalias psgrep 2>/dev/null
psgrep() {
    if [ $# -eq 0 ]; then
        echo "Usage: psgrep <pattern>" >&2
        return 1
    fi
    # Build a pattern like '[n]ginx' to avoid matching the grep process itself
    local pattern
    local term="$1"
    pattern="[${term:0:1}]${term:1}"
    ps aux | grep -i "$pattern"
}
alias ports='ss -tuln'
alias listening='ss -tlnp'
alias meminfo='free -h -l -t'
alias psmem='ps auxf | sort -nr -k 4 | head -10'
alias pscpu='ps auxf | sort -nr -k 3 | head -10'
alias top10='ps aux --sort=-%mem | head -n 11'

# Quick network info.
alias myip='curl -s ifconfig.me || curl -s icanhazip.com' # Alternatives: api.ipify.org, icanhazip.co
# Show local IP address(es), excluding loopback.
localip() {
    ip -4 addr | awk '/inet/ {print $2}' | cut -d/ -f1 | grep -v '127.0.0.1'
}

alias netstat='ss'
alias ping='ping -c 5'
alias fastping='ping -c 100 -i 0.2'

# Date and time helpers.
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias nowdate='date +"%Y-%m-%d"'
alias timestamp='date +%s'

# File operations.
alias count='find . -type f | wc -l'  # Count files in current directory
alias cpv='rsync -ah --info=progress2'  # Copy with progress
alias wget='wget -c'  # Resume wget by default

# Git shortcuts (if git is available).
if command -v git &>/dev/null; then
    alias gs='git status'
    alias ga='git add'
    alias gc='git commit'
    alias gp='git push'
    alias gl='git log --oneline --graph --decorate'
    alias gd='git diff'
    alias gb='git branch'
    alias gco='git checkout'
fi

# Systemd shortcuts.
if command -v systemctl &>/dev/null; then
    alias sysstart='sudo systemctl start'
    alias sysstop='sudo systemctl stop'
    alias sysrestart='sudo systemctl restart'
    alias sysstatus='sudo systemctl status'
    alias sysenable='sudo systemctl enable'
    alias sysdisable='sudo systemctl disable'
    alias sysreload='sudo systemctl daemon-reload'
fi

# Apt aliases for Debian/Ubuntu (only if apt is available).
if command -v apt &>/dev/null; then
    alias aptup='sudo apt update && sudo apt upgrade'
    alias aptin='sudo apt install'
    alias aptrm='sudo apt remove'
    alias aptsearch='apt search'
    alias aptshow='apt show'
    alias aptclean='sudo apt autoremove && sudo apt autoclean'
    alias aptlist='apt list --installed'
fi

# --- PATH Configuration ---
# Add user's local bin directories to PATH if they exist.
[ -d "$HOME/.local/bin" ] && export PATH="$HOME/.local/bin:$PATH"
[ -d "$HOME/bin" ] && export PATH="$HOME/bin:$PATH"

# --- Server-Specific Configuration ---
# Load hostname-specific configurations if they exist.
if [ -f ~/.bashrc."$(hostname -s)" ]; then
    source ~/.bashrc."$(hostname -s)"
fi

# --- Bash Completion & Personal Aliases ---
# Enable programmable completion features.
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
      . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
      . /etc/bash_completion
  fi
fi

# Source personal aliases if the file exists.
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# Source local machine-specific settings that shouldn't be in version control.
if [ -f ~/.bashrc.local ]; then
    . ~/.bashrc.local
fi

# --- Welcome Message for SSH Sessions ---
# Show system info and context on login for SSH sessions.
if [ -n "$SSH_CONNECTION" ]; then
    # Use the existing sysinfo function for a full system overview.
    sysinfo

    # Display previous login information (skip current session)
    last_login=$(last -R "$USER" 2>/dev/null | sed -n '2p' | awk '{$1=""; print}' | xargs)
    [ -n "$last_login" ] && printf "Last login: %s\n" "$last_login"

    # Show active sessions
    printf "Active sessions: %s\n" "$(who | wc -l)"
    printf -- "-----------------------------------------------------\n\n"
fi

# --- Help System ---
# Display all custom functions and aliases with descriptions
bashhelp() {
    local category="${1:-all}"

    case "$category" in
        all|"")
            cat << 'HELPTEXT'

╔════════════════════════════════════════════════════════╗
║               .bashrc - Quick Reference                ║
╚════════════════════════════════════════════════════════╝

Usage: bashhelp [category]
Categories: navigation, files, system, docker, git, network

═══════════════════════════════════════════════════════════════════
📁 NAVIGATION & DIRECTORY
═══════════════════════════════════════════════════════════════════
  ..                Go up one directory
  ...               Go up two directories
  ....              Go up three directories
  .....             Go up four directories
  -                 Go to previous directory
  ~                 Go to home directory

  mkcd <dir>        Create directory and cd into it
  up <n>            Go up N directories (e.g., up 3)
  path              Display PATH variable (one per line)
  mark <name>       Bookmark current directory
  jump <name>       Jump to a bookmarked directory

═══════════════════════════════════════════════════════════════════
📄 FILE OPERATIONS
═══════════════════════════════════════════════════════════════════
  ll                List all files with details (human-readable)
  la                List all files including hidden
  l                 List files in column format
  lt                List by time, newest first
  ltr               List by time, oldest first
  lS                List by size, largest first
  lsd               List only directories
  lsf               List only files

  ff <name>         Find files by name (case-insensitive)
  fd <name>         Find directories by name (case-insensitive)
  ftext <text>      Search for text in files recursively

  extract <file>    Extract any archive (tar, zip, 7z, etc.)
  targz <dir>       Create tar.gz of directory
  backup <file>     Create timestamped backup of file

  sizeof <path>     Get size of file or directory
  duh [path]        Disk usage sorted by size
  count             Count files in current directory
  cpv <src> <dst>   Copy with progress (rsync)

═══════════════════════════════════════════════════════════════════
💻 SYSTEM & MONITORING
═══════════════════════════════════════════════════════════════════
  sysinfo           Display comprehensive system information
  checkupdates      Check for available system updates
  diskcheck         Check for disk partitions over 80%

  psgrep <pat>      Search for process by name
  topcpu            Show top 10 processes by CPU
  topmem            Show top 10 processes by Memory
  pscpu             Show top 10 processes by CPU (tree view)
  psmem             Show top 10 processes by Memory (tree view)

  ports             Show listening ports (TCP/UDP)
  listening         Show listening ports with process info
  meminfo           Display detailed memory information

  h                 Show command history
  hgrep <pat>       Search command history
  histop            Show most used commands
  c, cls            Clear the screen
  reload            Reload bashrc configuration

═══════════════════════════════════════════════════════════════════
🐳 DOCKER & DOCKER COMPOSE
═══════════════════════════════════════════════════════════════════
Docker Commands:
  d                 docker (shortcut)
  dps               List running containers
  dpsa              List all containers
  di                List images
  dv                List volumes
  dn                List networks
  dex <id>          Execute interactive shell in container
  dlog <id>         Follow container logs

  dsh <id>          Enter container shell (bash/sh)
  dip [id]          Show container IP addresses
  dsize             Show disk usage by containers
  dbinds [id]       Show bind mounts for containers
  denv <id>         Show environment variables
  dfollow <id>      Follow logs with tail (default 100 lines)

  dstats            Container stats snapshot
  dstatsa           Container stats live
  dst               Container stats formatted table

  dprune            Prune system (remove unused data)
  dprunea           Prune all (including images)
  dvprune           Prune unused volumes
  diprune           Prune unused images
  drmall            Remove all stopped containers

Docker Compose:
  dc                docker compose (shortcut)
  dcup              Start services in background
  dcdown            Stop and remove services
  dclogs            Follow compose logs
  dcps              List compose services
  dcex <srv>        Execute command in service
  dcsh <srv>        Enter service shell (bash/sh)

  dcbuild           Build services
  dcbn              Build with no cache
  dcrestart         Restart services
  dcrecreate        Recreate services
  dcpull            Pull service images
  dcstop            Stop services
  dcstart           Start services

  dcstatus          Show service status & resource usage
  dcreload <srv>    Restart & follow logs
  dcupdate <srv>    Pull & update service
  dcgrep <s> <p>    Filter service logs
  dcvalidate        Validate compose file

═══════════════════════════════════════════════════════════════════
🔀 GIT SHORTCUTS
═══════════════════════════════════════════════════════════════════
  gs                git status
  ga                git add
  gc                git commit
  gp                git push
  gl                git log (graph view)
  gd                git diff
  gb                git branch
  gco               git checkout

═══════════════════════════════════════════════════════════════════
🌐 NETWORK
═══════════════════════════════════════════════════════════════════
  myip              Show external IP address
  localip           Show local IP address(es)
  netsum            Network connection summary
  kssh              SSH wrapper for kitty terminal
  ping              Ping with 5 packets (default)
  fastping          Fast ping (100 packets, 0.2s interval)
  netstat           Network connections (ss)

═══════════════════════════════════════════════════════════════════
⚙️  SYSTEM ADMINISTRATION
═══════════════════════════════════════════════════════════════════
Systemd:
  svc <srv>         Show service status (brief)
  failed            List failed systemd services
  sysstart <srv>    Start service
  sysstop <srv>     Stop service
  sysrestart <srv>  Restart service
  sysstatus <srv>   Show service status
  sysenable <srv>   Enable service
  sysdisable <srv>  Disable service
  sysreload         Reload systemd daemon

APT (Debian/Ubuntu):
  aptup             Update and upgrade packages
  aptin <pkg>       Install package
  aptrm <pkg>       Remove package
  aptsearch <term>  Search for packages
  aptshow <pkg>     Show package information
  aptclean          Remove unused packages
  aptlist           List installed packages

Sudo:
  please            Run last command with sudo

═══════════════════════════════════════════════════════════════════
🕒 DATE & TIME
═══════════════════════════════════════════════════════════════════
  now               Current date and time (YYYY-MM-DD HH:MM:SS)
  nowdate           Current date (YYYY-MM-DD)
  timestamp         Unix timestamp

═══════════════════════════════════════════════════════════════════
ℹ️  HELP & INFORMATION
═══════════════════════════════════════════════════════════════════
  bashhelp          Show this help (all categories)
  bh                Alias for bashhelp
  commands          List all custom functions and aliases
  bashhelp navigation Show navigation commands only
  bashhelp files    Show file operation commands
  bashhelp system   Show system monitoring commands
  bashhelp docker   Show docker commands only
  bashhelp git      Show git shortcuts
  bashhelp network  Show network commands

═══════════════════════════════════════════════════════════════════

💡 TIP: Most commands support --help or -h for more information
     The prompt shows: ✗ for failed commands, (git branch) when in repo

HELPTEXT
            ;;

        navigation)
            cat << 'HELPTEXT'

═══ NAVIGATION & DIRECTORY COMMANDS ═══

  ..                Go up one directory
  ...               Go up two directories
  ....              Go up three directories
  .....             Go up four directories
  -                 Go to previous directory
  ~                 Go to home directory

  mkcd <dir>        Create directory and cd into it
  up <n>            Go up N directories
  path              Display PATH variable
  mark <name>       Bookmark current directory
  jump <name>       Jump to a bookmarked directory

Examples:
  mkcd ~/projects/newapp    # Create and enter directory
  up 3                      # Go up 3 levels
  mark proj1                # Bookmark current dir as 'proj1'
  jump proj1                # Jump back to 'proj1'

HELPTEXT
            ;;

        files)
            cat << 'HELPTEXT'

═══ FILE OPERATION COMMANDS ═══

Listing:
  ll, la, l, lt, ltr, lS, lsd, lsf

Finding:
  ff <name>         Find files by name
  fd <name>         Find directories by name
  ftext <text>      Search text in files

Archives:
  extract <file>    Extract any archive type
  targz <dir>       Create tar.gz archive
  backup <file>     Create timestamped backup

Size Info:
  sizeof <path>     Get size of file/directory
  duh [path]        Disk usage sorted by size
  count             Count files in directory
  cpv               Copy with progress (rsync)

Examples:
  ff README         # Find files named *README*
  extract data.tar.gz
  backup ~/.bashrc

HELPTEXT
            ;;

        system)
            cat << 'HELPTEXT'

═══ SYSTEM MONITORING COMMANDS ═══

Overview:
  sysinfo           Comprehensive system info
  checkupdates      Check for package updates
  diskcheck         Check for disks > 80%

Processes:
  psgrep <pat>      Search processes
  topcpu            Top 10 by CPU
  topmem            Top 10 by Memory
  pscpu             Top 10 by CPU (tree view)
  psmem             Top 10 by Memory (tree view)

Network:
  ports             Listening ports
  listening         Ports with process info

Memory:
  meminfo           Detailed memory info
  free              Free memory (human-readable)

Shell:
  h                 Show history
  hgrep <pat>       Search history
  histop            Most used commands
  c, cls            Clear screen
  reload            Reload bashrc

Examples:
  psgrep nginx
  psmem | grep docker

HELPTEXT
            ;;

        docker)
            cat << 'HELPTEXT'

═══ DOCKER COMMANDS ═══

Basic:
  dps, dpsa, di, dv, dn, dex, dlog

Management:
  dsh <id>          Enter container shell
  dip [id]          Show IP addresses
  dsize             Show disk usage
  dbinds [id]       Show bind mounts
  denv <id>         Show environment variables
  dfollow <id>      Follow logs

Stats & Cleanup:
  dstats, dstatsa, dst
  dprune, dprunea, dvprune, diprune
  drmall            Remove stopped containers

Docker Compose:
  dcup, dcdown, dclogs, dcps, dcex, dcsh
  dcbuild, dcrestart, dcrecreate
  dcstatus          Status & resource usage
  dcreload <srv>    Restart & follow logs
  dcupdate <srv>    Pull & update service
  dcgrep <s> <p>    Filter logs
  dcvalidate        Validate compose file

Examples:
  dsh mycontainer
  dcsh web bash
  dcupdate nginx
  dcgrep app "error"

HELPTEXT
            ;;

        git)
            cat << 'HELPTEXT'

═══ GIT SHORTCUTS ═══

  gs                git status
  ga                git add
  gc                git commit
  gp                git push
  gl                git log (graph view)
  gd                git diff
  gb                git branch
  gco               git checkout

Examples:
  gs                # Check status
  ga .              # Add all changes
  gc -m "Update docs"   # Commit
  gp                # Push to remote

HELPTEXT
            ;;

        network)
            cat << 'HELPTEXT'

═══ NETWORK COMMANDS ═══

  myip              Show external IP
  localip           Show local IP(s)
  netsum            Network connection summary
  kssh              SSH wrapper for kitty
  ports             Show listening ports
  listening         Ports with process info
  ping              Ping (5 packets)
  fastping          Fast ping (100 packets)
  netstat           Network connections (ss)

Examples:
  myip              # Get public IP
  listening | grep 80
  ping google.com

HELPTEXT
            ;;

        *)
            echo "Unknown category: $category"
            echo "Available categories: navigation, files, system, docker, git, network"
            echo "Use 'bashhelp' or 'bashhelp all' for complete reference"
            return 1
            ;;
    esac
}

# Shorter alias for bashhelp (not for help - that's a function now)
alias bh='bashhelp'

# Quick command list (compact)
alias commands='compgen -A function -A alias | grep -v "^_" | sort | column'
EOF

    # Set ownership and permissions
    chown "$USERNAME:$USERNAME" "$BASHRC_PATH"
    chmod 644 "$BASHRC_PATH"

    print_success "Custom .bashrc created for '$USERNAME'"
    print_info "The new .bashrc includes: enhanced prompt, git integration, docker shortcuts, system monitoring functions, and comprehensive help system."
}

# Function to setup SSH key with advanced options
setup_ssh_key() {
    local username=$1
    local ssh_dir="/home/$username/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would setup SSH key for $username"
        return
    fi

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "$username:$username" "$ssh_dir"

    if [[ "$MODE" == "interactive" ]]; then
        echo "Paste your SSH public key (press Ctrl+D when done):"
        cat > "$auth_keys"
        chmod 600 "$auth_keys"
        chown "$username:$username" "$auth_keys"
    else
        # Generate SSH key pair for automated setup
        ssh-keygen -t ed25519 -f "$ssh_dir/id_ed25519" -N "" -C "$username@$(hostname)"
        cat "$ssh_dir/id_ed25519.pub" >> "$auth_keys"
        chmod 600 "$auth_keys"
        chown "$username:$username" "$ssh_dir"/*
        print_message "$YELLOW" "Generated SSH key pair. Public key:"
        cat "$ssh_dir/id_ed25519.pub"
    fi

    print_message "$GREEN" "SSH key configured for $username"
}

# Function to create admin user
create_admin_user() {
    print_message "$GREEN" "Creating admin user..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would create admin user"
        return
    fi

    # Get username
    if [[ "$MODE" == "interactive" ]]; then
        read -p "Enter admin username: " username
        while [[ -z "$username" ]] || ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; do
            read -p "Invalid username. Enter admin username: " username
        done
    else
        username="admin"
    fi

    # Check if user exists
    if id "$username" &>/dev/null; then
        print_message "$YELLOW" "User $username already exists"
        return
    fi

    # Create user
    useradd -m -s /bin/bash "$username"
    usermod -aG sudo "$username"

    # Set password
    if [[ "$MODE" == "interactive" ]]; then
        echo "Set password for $username:"
        passwd "$username"
    else
        # Generate random password for automated setup
        password=$(openssl rand -base64 12)
        echo "$username:$password" | chpasswd
        print_message "$YELLOW" "Generated password for $username: $password"
        print_message "$YELLOW" "IMPORTANT: Change this password after first login!"
    fi

    # Configure SSH key
    setup_ssh_key "$username"

    # Configure custom .bashrc
    configure_custom_bashrc "/home/$username" "$username"

    print_message "$GREEN" "Admin user $username created successfully"
}

# Function to configure swap with intelligent detection
configure_swap() {
    print_message "$GREEN" "Configuring swap..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure swap"
        return
    fi

    # Check if swap already exists
    if swapon --show | grep -q "swap"; then
        print_info "Swap already configured"
        return
    fi

    # Get total RAM in MB
    local total_ram=$(free -m | awk '/Mem:/ {print $2}')
    local swap_size=""

    # Calculate swap size based on RAM
    if [[ $total_ram -lt 2048 ]]; then
        swap_size="$((total_ram * 2))M"
        elif [[ $total_ram -lt 8192 ]]; then
        swap_size="$((total_ram))M"
    else
        swap_size="8192M"
    fi

    # Create swap file
    local swap_file="/swapfile"
    dd if=/dev/zero of="$swap_file" bs=1M count="${swap_size%M}" status=progress
    chmod 600 "$swap_file"
    mkswap "$swap_file"
    swapon "$swap_file"

    # Make swap permanent
    echo "$swap_file none swap sw 0 0" >> /etc/fstab

    # Configure swappiness
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf

    print_message "$GREEN" "Swap configured: $swap_size"
}

# Function to install and configure Tailscale VPN
configure_tailscale() {
    print_message "$GREEN" "Configuring Tailscale VPN..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would install Tailscale"
        return
    fi

    if ! confirm "Install and configure Tailscale VPN?" "n"; then
        print_info "Skipping Tailscale installation"
        return
    fi

    # Install Tailscale
    curl -fsSL https://tailscale.com/install.sh | sh

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    sysctl -p

    # Start and enable Tailscale
    systemctl enable --now tailscaled

    print_message "$GREEN" "Tailscale installed. Run 'tailscale up' to connect."
}

# Function to configure comprehensive backup system with rsync
configure_backup_system() {
    print_message "$GREEN" "Configuring backup system..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure backup system"
        return
    fi

    # Install required packages
    apt-get install -y rsync cron

    # Create backup directories
    mkdir -p /opt/backup/{scripts,logs,config}

    # Create backup script
    cat > /opt/backup/scripts/system-backup.sh << 'EOF'
#!/bin/bash
# System Backup Script

BACKUP_DIR="/opt/backup"
LOG_FILE="$BACKUP_DIR/logs/backup-$(date +%Y%m%d-%H%M%S).log"
RETENTION_DAYS=30

# Create log directory
mkdir -p "$BACKUP_DIR/logs"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to backup important directories
backup_directory() {
    local src="$1"
    local dest="$2"
    local name="$3"

    if [[ -d "$src" ]]; then
        log_message "Backing up $name..."
        rsync -av --delete "$src/" "$dest/" >> "$LOG_FILE" 2>&1
        if [[ $? -eq 0 ]]; then
            log_message "$name backup completed successfully"
        else
            log_message "ERROR: $name backup failed"
        fi
    else
        log_message "WARNING: Source directory $src not found"
    fi
}

# Main backup process
log_message "Starting system backup"

# Backup system configuration
backup_directory "/etc" "$BACKUP_DIR/config/etc" "system configuration"

# Backup user home directories (excluding cache and temp files)
for user_home in /home/*; do
    if [[ -d "$user_home" ]]; then
        username=$(basename "$user_home")
        if [[ "$username" != "lost+found" ]]; then
            log_message "Backing up user $username home directory..."
            rsync -av --delete --exclude='.cache' --exclude='.local/share/Trash' \
                  "$user_home/" "$BACKUP_DIR/home/$username/" >> "$LOG_FILE" 2>&1
        fi
    fi
done

# Backup root user home
if [[ -d "/root" ]]; then
    backup_directory "/root" "$BACKUP_DIR/home/root" "root home directory"
fi

# Backup package lists
log_message "Backing up package lists..."
dpkg --get-selections > "$BACKUP_DIR/config/package-selections.txt"
apt-mark showmanual > "$BACKUP_DIR/config/manual-packages.txt"

# Backup cron jobs
log_message "Backing up cron jobs..."
crontab -l > "$BACKUP_DIR/config/root-crontab.txt" 2>/dev/null
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l > "$BACKUP_DIR/config/${user}-crontab.txt" 2>/dev/null
done

# Clean old backups
log_message "Cleaning old backups..."
find "$BACKUP_DIR" -name "*.log" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR/home" -type d -mtime +$RETENTION_DAYS -exec rm -rf {} + 2>/dev/null

log_message "Backup process completed"
EOF

    chmod +x /opt/backup/scripts/system-backup.sh

    # Create restore script
    cat > /opt/backup/scripts/system-restore.sh << 'EOF'
#!/bin/bash
# System Restore Script

BACKUP_DIR="/opt/backup"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <backup-date>"
    echo "Available backups:"
    ls -1 "$BACKUP_DIR/config/" 2>/dev/null | grep -E '^[0-9]{8}-[0-9]{6}$' || echo "No backups found"
    exit 1
fi

BACKUP_DATE="$1"
BACKUP_PATH="$BACKUP_DIR/config/$BACKUP_DATE"

if [[ ! -d "$BACKUP_PATH" ]]; then
    echo "Backup not found: $BACKUP_DATE"
    exit 1
fi

echo "Restoring from backup: $BACKUP_DATE"
echo "WARNING: This will overwrite current configuration!"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restore cancelled"
    exit 0
fi

# Restore system configuration
if [[ -d "$BACKUP_PATH/etc" ]]; then
    echo "Restoring system configuration..."
    rsync -av "$BACKUP_PATH/etc/" "/etc/"
fi

# Restore package selections
if [[ -f "$BACKUP_PATH/package-selections.txt" ]]; then
    echo "Restoring package selections..."
    dpkg --set-selections < "$BACKUP_PATH/package-selections.txt"
    apt-get dselect-upgrade
fi

echo "Restore completed. Some services may need to be restarted."
EOF

    chmod +x /opt/backup/scripts/system-restore.sh

    # Add cron job for daily backups
    (crontab -l 2>/dev/null; echo "0 2 * * * /opt/backup/scripts/system-backup.sh") | crontab -

    print_message "$GREEN" "Backup system configured"
    print_info "Daily backups scheduled at 2:00 AM"
    print_info "Backup location: /opt/backup"
}

# Function to clean up provider-specific packages
cleanup_provider_packages() {
    print_message "$GREEN" "Cleaning up provider-specific packages..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would cleanup provider packages"
        return
    fi

    # Detect provider and remove unnecessary packages
    case "$DETECTED_PROVIDER_NAME" in
        "DigitalOcean")
            # Remove DigitalOcean monitoring agent if not needed
            if confirm "Remove DigitalOcean monitoring agent?" "n"; then
                apt-get remove -y do-agent
            fi
        ;;
        "Amazon Web Services (AWS)")
            # Remove AWS CLI v1 if v2 is available
            if command -v aws &>/dev/null && [[ -f /usr/local/bin/aws ]]; then
                if confirm "Remove AWS CLI v1 (v2 detected)?" "n"; then
                    apt-get remove -y awscli
                fi
            fi
        ;;
        "Google Cloud Platform")
            # Remove Google Cloud SDK if not needed
            if confirm "Remove Google Cloud SDK?" "n"; then
                apt-get remove -y google-cloud-sdk
            fi
        ;;
        "Microsoft Azure")
            # Remove Azure CLI if not needed
            if confirm "Remove Azure CLI?" "n"; then
                apt-get remove -y azure-cli
            fi
        ;;
    esac

    # Clean up orphaned packages
    apt-get autoremove -y
    apt-get autoclean

    print_message "$GREEN" "Provider package cleanup completed"
}

# Function to configure SSH
configure_ssh() {
    print_message "$GREEN" "Configuring SSH..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure SSH"
        return
    fi

    backup_file "/etc/ssh/sshd_config"

    # Get SSH port
    if [[ "$MODE" == "interactive" ]]; then
        read -p "Enter SSH port (default: 22): " ssh_port
        ssh_port=${ssh_port:-22}
    else
        ssh_port=22
    fi

    # Configure SSH
    cat >> /etc/ssh/sshd_config << EOF

# Hardened SSH Configuration
Port $ssh_port
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30s
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintMotd no
PrintLastLog yes
EOF

    # Test configuration
    if sshd -t; then
        systemctl restart sshd
        print_message "$GREEN" "SSH configured successfully on port $ssh_port"
    else
        error_exit "SSH configuration test failed"
    fi
}

# Function to configure firewall
configure_firewall() {
    print_message "$GREEN" "Configuring firewall..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure firewall"
        return
    fi

    # Install UFW if not present
    if ! command -v ufw &> /dev/null; then
        apt-get update && apt-get install -y ufw
    fi

    # Reset firewall
    ufw --force reset

    # Set defaults
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH
    ufw limit ssh comment 'SSH with rate limiting'

    # Allow additional ports if specified
    if [[ "$MODE" == "interactive" ]]; then
        read -p "Allow HTTP (80/tcp)? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ufw allow 80/tcp comment 'HTTP'
        fi

        read -p "Allow HTTPS (443/tcp)? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ufw allow 443/tcp comment 'HTTPS'
        fi
    fi

    # Enable firewall
    echo "y" | ufw enable

    print_message "$GREEN" "Firewall configured and enabled"
}

# Function to configure time synchronization
configure_time_sync() {
    print_message "$GREEN" "Configuring time synchronization..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure time sync"
        return
    fi

    # Choose time sync service based on Ubuntu version
    case "$UBUNTU_VERSION" in
        "25.04"|"25.10")
            # Use Chrony with NTS for Ubuntu 25.x
            if ! command -v chronyc &> /dev/null; then
                apt-get install -y chrony
            fi

            backup_file "/etc/chrony/chrony.conf"

            cat > /etc/chrony/chrony.conf << 'EOF'
# Ubuntu 25.x Chrony Configuration
server time.cloudflare.com iburst nts
server nts.ntp.se iburst nts
server ptbtime1.ptb.de iburst nts
server time.dfm.dk iburst nts

pool ntp.ubuntu.com iburst maxsources 4

driftfile /var/lib/chrony/chrony.drift
rtcsync
makestep 1.0 3

log measurements statistics tracking
EOF

            systemctl restart chrony
            systemctl enable chrony
        ;;
        *)
            # Use systemd-timesyncd for older versions
            systemctl restart systemd-timesyncd
            systemctl enable systemd-timesyncd
        ;;
    esac

    # Verify time sync
    sleep 2
    if command -v chronyc &> /dev/null; then
        chronyc tracking
    else
        timedatectl status
    fi

    print_message "$GREEN" "Time synchronization configured"
}

# Function to configure hostname
configure_hostname() {
    print_message "$GREEN" "Configuring hostname..."

    if [[ "$DRY_RUN" == true ]]; then
        print_message "$BLUE" "[DRY RUN] Would configure hostname"
        return
    fi

    # Get hostname
    if [[ "$MODE" == "interactive" ]]; then
        read -p "Enter hostname (default: $(hostname)): " new_hostname
        new_hostname=${new_hostname:-$(hostname)}
    else
        new_hostname="ubuntu-server"
    fi

    hostnamectl set-hostname "$new_hostname"

    # Update hosts file
    sed -i "s/127.0.1.1.*/127.0.1.1\t$new_hostname/" /etc/hosts

    print_message "$GREEN" "Hostname set to: $new_hostname"
}

# Function to run all initial setup components
run_initial_setup_components() {
    detect_environment
    configure_timezone
    create_admin_user
    configure_hostname
    configure_ssh
    configure_firewall
    configure_time_sync
    configure_swap
    configure_tailscale
    configure_backup_system
    cleanup_provider_packages

    print_message "$GREEN" "Initial setup completed"
}
