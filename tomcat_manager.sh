#!/bin/bash

# tomcat_manager.sh
# Manages installation and uninstallation of Apache Tomcat 7, 8.5, and 9 on Kali Linux
# Run as root or with sudo: sudo ./tomcat_manager.sh [install 7|8.5|9] [uninstall]

# Exit on error
set -e

# Global Variables
TOMCAT_DIR="/opt/tomcat"
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
        userdel -r tomcat || log "Failed to remove tomcat user"
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
    local JAVA_HOME
    local JAVA_VERSION
    local JAVA_OPTS

    case $TOMCAT_MAJOR in
        7)
            TOMCAT_VERSION="7.0.114"
            TOMCAT_URL="https://archive.apache.org/dist/tomcat/tomcat-7/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            JAVA_VERSION="8"
            JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
            JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
            ;;
        8.5)
            TOMCAT_VERSION="8.5.100"
            TOMCAT_URL="https://dlcdn.apache.org/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            JAVA_VERSION="11"
            JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
            JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED"
            ;;
        9)
            TOMCAT_VERSION="9.0.104"
            TOMCAT_URL="https://dlcdn.apache.org/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            JAVA_VERSION="11"
            JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
            JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
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

    # Install required Java version
    log "Installing OpenJDK ${JAVA_VERSION}..."
    if ! apt install -y openjdk-${JAVA_VERSION}-jdk; then
        if [ "$JAVA_VERSION" = "8" ]; then
            log "ERROR: Failed to install OpenJDK 8. OpenJDK 8 may not be available in Kali repositories."
            log "For Tomcat 7, you must manually install OpenJDK 8 or use a compatible Java version."
            log "See https://adoptium.net/temurin/releases/?version=8 for manual installation."
            exit 1
        else
            log "ERROR: Failed to install OpenJDK ${JAVA_VERSION}. Ensure the package is available."
            exit 1
        fi
    fi

    # Verify Java installation
    log "Verifying Java installation..."
    if ! java -version 2>&1 | grep -q "${JAVA_VERSION}\."; then
        log "ERROR: Java ${JAVA_VERSION} not detected."
        exit 1
    fi

    # Verify JAVA_HOME
    if [ ! -d "$JAVA_HOME" ]; then
        log "ERROR: JAVA_HOME directory ${JAVA_HOME} does not exist."
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
    if ! wget --tries=3 --timeout=30 -q "$TOMCAT_URL"; then
        log "ERROR: Failed to download Tomcat archive from ${TOMCAT_URL}. Verify the URL and network."
        exit 1
    fi

    # Verify downloaded file
    if [ ! -f "apache-tomcat-${TOMCAT_VERSION}.tar.gz" ]; then
        log "ERROR: Downloaded Tomcat archive not found."
        exit 1
    fi

    # Remove existing installation
    log "Removing previous installations..."
    systemctl stop tomcat.service > /dev/null 2>&1 || true
    rm -rf "$TOMCAT_DIR"

    # Extract Tomcat
    log "Extracting Tomcat to ${TOMCAT_DIR}..."
    mkdir -p "$TOMCAT_DIR"
    if ! tar xzf "apache-tomcat-${TOMCAT_VERSION}.tar.gz" -C "$TOMCAT_DIR" --strip-components=1; then
        log "ERROR: Failed to extract Tomcat archive."
        exit 1
    fi
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
Environment="JAVA_OPTS=${JAVA_OPTS}"
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
    if ! systemctl start tomcat; then
        log "ERROR: Failed to start Tomcat service. Check logs in ${TOMCAT_DIR}/logs/catalina.out."
        exit 1
    fi

    # Verify installation
    log "Verifying installation..."
    sleep 10
    if curl -s -f "http://localhost:8080" > /dev/null; then
        log "SUCCESS: Tomcat ${TOMCAT_VERSION} is running at http://localhost:8080"
    else
        log "WARNING: Tomcat service started but web interface not accessible. Check ${TOMCAT_DIR}/logs/catalina.out."
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
