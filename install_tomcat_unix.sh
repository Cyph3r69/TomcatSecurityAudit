#!/bin/bash

# tomcat_manager.sh
# Manages installation and uninstallation of Apache Tomcat 7, 8.5, and 9 on Kali Linux
# Run as root or with sudo: sudo ./tomcat_manager.sh [install 7|8.5|9] [uninstall]

# Exit on error
set -e

# Global Variables
TOMCAT_DIR="/opt/tomcat"
JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
LOG_FILE="/tmp/TomcatManager.log"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check root privileges
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root or with sudo."
        exit 1
    fi
}

# Uninstall Tomcat
uninstall_tomcat() {
    log "Starting Tomcat uninstallation process..."

    log "Stopping Tomcat service..."
    systemctl stop tomcat.service > /dev/null 2>&1 || true

    log "Disabling Tomcat service..."
    systemctl disable tomcat.service > /dev/null 2>&1 || true

    log "Removing systemd service..."
    rm -f /etc/systemd/system/tomcat.service
    systemctl daemon-reload

    log "Removing Tomcat directory..."
    rm -rf "$TOMCAT_DIR"

    log "Removing tomcat user..."
    if id "tomcat" > /dev/null 2>&1; then
        userdel tomcat || log "Failed to remove tomcat user"
        groupdel tomcat || log "Failed to remove tomcat group"
    else
        log "Tomcat user not found"
    fi

    log "Tomcat uninstallation completed successfully"
}

# Install Tomcat
install_tomcat() {
    local TOMCAT_MAJOR=$1
    local TOMCAT_VERSION
    local TOMCAT_URL

    case $TOMCAT_MAJOR in
        7)
            TOMCAT_VERSION="7.0.114"
            TOMCAT_URL="https://archive.apache.org/dist/tomcat/tomcat-7/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            ;;
        8.5)
            TOMCAT_VERSION="8.5.94"
            TOMCAT_URL="https://dlcdn.apache.org/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            ;;
        9)
            TOMCAT_VERSION="9.0.104"
            TOMCAT_URL="https://dlcdn.apache.org/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            ;;
        *)
            log "ERROR: Unsupported Tomcat version. Choose 7, 8.5, or 9."
            exit 1
            ;;
    esac

    log "Starting installation of Tomcat ${TOMCAT_MAJOR} (${TOMCAT_VERSION})"

    # Check internet connectivity
    log "Checking internet connectivity..."
    if ! ping -c 1 google.com > /dev/null 2>&1; then
        log "ERROR: No internet connection. Please connect to the internet and try again."
        exit 1
    fi

    # Update package list
    log "Updating package list..."
    apt update -y

    # Install OpenJDK 11
    log "Installing OpenJDK 11..."
    if ! apt install -y openjdk-11-jdk; then
        log "ERROR: Failed to install OpenJDK 11."
        exit 1
    fi

    # Verify Java installation
    log "Verifying Java installation..."
    if ! java -version 2>&1 | grep -q "11\."; then
        log "ERROR: Java 11 not detected."
        exit 1
    fi

    # Create tomcat user
    log "Creating tomcat user..."
    if ! id tomcat > /dev/null 2>&1; then
        useradd -m -d "$TOMCAT_DIR" -s /bin/false -U tomcat
    else
        log "Tomcat user already exists"
    fi

    # Download Tomcat
    log "Downloading Apache Tomcat ${TOMCAT_VERSION}..."
    cd /tmp
    if ! wget -q "$TOMCAT_URL"; then
        log "ERROR: Failed to download Tomcat archive"
        exit 1
    fi

    # Remove existing installation
    log "Removing previous installations..."
    systemctl stop tomcat.service > /dev/null 2>&1 || true
    rm -rf "$TOMCAT_DIR"

    # Extract Tomcat
    log "Extracting Tomcat to ${TOMCAT_DIR}..."
    mkdir -p "$TOMCAT_DIR"
    tar xzf "apache-tomcat-${TOMCAT_VERSION}.tar.gz" -C "$TOMCAT_DIR" --strip-components=1
    rm "apache-tomcat-${TOMCAT_VERSION}.tar.gz"

    # Set permissions
    log "Setting permissions..."
    chown -R tomcat:tomcat "$TOMCAT_DIR"
    chmod -R u+rwx "$TOMCAT_DIR"
    chmod +x "$TOMCAT_DIR/bin/"*.sh

    # Create systemd service
    log "Configuring systemd service..."
    cat > /etc/systemd/system/tomcat.service << EOF
[Unit]
Description=Apache Tomcat Web Application Container
After=network.target

[Service]
Type=forking
Environment="JAVA_HOME=${JAVA_HOME}"
Environment="CATALINA_PID=${TOMCAT_DIR}/temp/tomcat.pid"
Environment="CATALINA_HOME=${TOMCAT_DIR}"
Environment="CATALINA_BASE=${TOMCAT_DIR}"
Environment="CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC"
Environment="JAVA_OPTS=-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
ExecStart=${TOMCAT_DIR}/bin/startup.sh
ExecStop=${TOMCAT_DIR}/bin/shutdown.sh
User=tomcat
Group=tomcat
UMask=0007
RestartSec=10
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start service
    log "Starting Tomcat service..."
    systemctl daemon-reload
    systemctl enable tomcat
    systemctl start tomcat

    # Verify installation
    log "Verifying installation..."
    sleep 5
    if curl -s -f "http://localhost:8080" > /dev/null; then
        log "SUCCESS: Tomcat ${TOMCAT_VERSION} is running at http://localhost:8080"
    else
        log "WARNING: Tomcat service started but web interface not accessible"
    fi

    log "Installation complete. Configure tomcat-users.xml in ${TOMCAT_DIR}/conf for auditing."
}

# Main script execution
check_root

case "$1" in
    install)
        if [ -z "$2" ]; then
            log "ERROR: Please specify a Tomcat version (7, 8.5, or 9)"
            exit 1
        fi
        install_tomcat "$2"
        ;;
    uninstall)
        uninstall_tomcat
        ;;
    *)
        echo "Usage: $0 [install 7|8.5|9] [uninstall]"
        exit 1
        ;;
esac

exit 0
