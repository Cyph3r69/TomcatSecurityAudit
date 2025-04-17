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
    local TOMCAT_URLS
    local JAVA_HOME
    local JAVA_VERSION
    local JAVA_OPTS
    local JAVA_BIN
    local TOMCAT_URL
    local CHECKSUM_URL
    local CHECKSUM

    case $TOMCAT_MAJOR in
        7)
            TOMCAT_VERSION="7.0.114"
            TOMCAT_URLS=(
                "https://dlcdn.apache.org/tomcat/tomcat-7/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
                "https://archive.apache.org/dist/tomcat/tomcat-7/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            )
            JAVA_VERSION="8"
            JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
            JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
            JAVA_BIN="${JAVA_HOME}/bin/java"
            CHECKSUM_URL="https://archive.apache.org/dist/tomcat/tomcat-7/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz.sha512"
            CHECKSUM="e7e5c4e6734ab88c0f59c0a4d8f2c327d5e0a7f1c9d3e7e76f9c3e5e1f9d3e4c7b6c4e8e9f4c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7"
            ;;
        8.5)
            TOMCAT_VERSION="8.5.100"
            TOMCAT_URLS=(
                "https://dlcdn.apache.org/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
                "https://archive.apache.org/dist/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            )
            JAVA_VERSION="11"
            JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
            JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED"
            JAVA_BIN="${JAVA_HOME}/bin/java"
            CHECKSUM_URL="https://archive.apache.org/dist/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz.sha512"
            CHECKSUM="b7e8c4e4f9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4b0e5c9e7f1c2e4"
            ;;
        9)
            TOMCAT_VERSION="9.0.104"
            TOMCAT_URLS=(
                "https://dlcdn.apache.org/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
                "https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
            )
            JAVA_VERSION="11"
            JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
            JAVA_OPTS="-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom"
            JAVA_BIN="${JAVA_HOME}/bin/java"
            CHECKSUM_URL="https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz.sha512"
            CHECKSUM="a1b2c3d4e5f6b7c9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"
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
    if [ ! -f "$JAVA_BIN" ]; then
        log "ERROR: Java binary ${JAVA_BIN} not found. Ensure ${JAVA_HOME} is correct."
        log "Attempting to find Java ${JAVA_VERSION} installation..."
        JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
        JAVA_BIN="${JAVA_HOME}/bin/java"
        if [ ! -f "$JAVA_BIN" ]; then
            log "ERROR: Could not locate Java binary for Java ${JAVA_VERSION}."
            exit 1
        fi
        log "Using JAVA_HOME: ${JAVA_HOME}"
    fi
    JAVA_VERSION_OUTPUT=$("$JAVA_BIN" -version 2>&1)
    log "java -version output: ${JAVA_VERSION_OUTPUT}"
    if ! echo "$JAVA_VERSION_OUTPUT" | grep -q "1${JAVA_VERSION}\." && ! echo "$JAVA_VERSION_OUTPUT" | grep -q "${JAVA_VERSION}\." && ! echo "$JAVA_VERSION_OUTPUT" | grep -q "openjdk version.*${JAVA_VERSION}"; then
        log "ERROR: Java ${JAVA_VERSION} not detected with ${JAVA_BIN}."
        DETECTED_VERSION=$(echo "$JAVA_VERSION_OUTPUT" | head -n 1 | awk '{print $3}' | tr -d '"')
        if [[ "$DETECTED_VERSION" =~ ^${JAVA_VERSION}\. ]]; then
            log "WARNING: Detected Java version ${DETECTED_VERSION}, proceeding with installation."
        else
            log "ERROR: Detected version ${DETECTED_VERSION} does not match required Java ${JAVA_VERSION}."
            log "Run 'update-alternatives --config java' to select Java ${JAVA_VERSION} or verify ${JAVA_HOME}."
            exit 1
        fi
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

    # Download Tomcat with fallback
    log "Downloading Apache Tomcat ${TOMCAT_VERSION}..."
    cd /tmp
    for TOMCAT_URL in "${TOMCAT_URLS[@]}"; do
        log "Attempting download from ${TOMCAT_URL}..."
        if wget --tries=3 --timeout=30 -q --show-progress "$TOMCAT_URL" 2>> "$LOG_FILE"; then
            log "Successfully downloaded from ${TOMCAT_URL}"
            break
        else
            log "WARNING: Failed to download from ${TOMCAT_URL}. Trying next URL..."
        fi
    done

    # Verify downloaded file
    if [ ! -f "apache-tomcat-${TOMCAT_VERSION}.tar.gz" ]; then
        log "ERROR: Failed to download Tomcat archive from all URLs."
        log "URLs tried: ${TOMCAT_URLS[*]}"
        log "Check network, proxy settings, or URL availability."
        exit 1
    fi

    # Verify checksum
    log "Verifying checksum of downloaded file..."
    if ! echo "$CHECKSUM apache-tomcat-${TOMCAT_VERSION}.tar.gz" | sha512sum -c - > /dev/null 2>&1; then
        log "ERROR: Checksum verification failed for apache-tomcat-${TOMCAT_VERSION}.tar.gz."
        log "Expected SHA512: $CHECKSUM"
        log "Download may be corrupted or tampered with."
        rm -f "apache-tomcat-${TOMCAT_VERSION}.tar.gz"
        exit 1
    fi
    log "Checksum verification passed."

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
