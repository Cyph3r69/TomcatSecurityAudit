#!/bin/bash

# install.sh
# Installs Apache Tomcat 9.0 on Kali Linux for use with Tomcat Configuration Security Auditor
# Run as root or with sudo: sudo ./install.sh

# Exit on error
set -e

# Variables
TOMCAT_VERSION="9.0.104"
TOMCAT_URL="https://dlcdn.apache.org/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
TOMCAT_DIR="/opt/tomcat"
JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
LOG_FILE="/tmp/TestTomcatConfig.log"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if running as root or with sudo
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root or with sudo."
    exit 1
fi

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

# Verify Java
log "Verifying Java installation..."
JAVA_BIN="${JAVA_HOME}/bin/java"
if [ -x "$JAVA_BIN" ]; then
    JAVA_VERSION=$("$JAVA_BIN" -version 2>&1)
    log "Java version output: $JAVA_VERSION"
    if echo "$JAVA_VERSION" | grep -q "11\."; then
        log "Java 11 detected successfully."
    else
        log "ERROR: Java 11 not detected at $JAVA_BIN."
        exit 1
    fi
else
    log "ERROR: Java binary not found at $JAVA_BIN."
    exit 1
fi

# Create tomcat user
log "Creating tomcat user..."
if ! id tomcat > /dev/null 2>&1; then
    useradd -m -d "$TOMCAT_DIR" -s /bin/false -U tomcat
else
    log "Tomcat user already exists."
fi

# Download and verify Tomcat
log "Downloading Apache Tomcat ${TOMCAT_VERSION}..."
cd /tmp
if ! wget -q "$TOMCAT_URL"; then
    log "ERROR: Failed to download Tomcat."
    exit 1
fi

# Extract Tomcat
log "Extracting Tomcat to ${TOMCAT_DIR}..."
if [ -d "$TOMCAT_DIR" ]; then
    log "Removing existing Tomcat directory..."
    rm -rf "$TOMCAT_DIR"
fi
mkdir -p "$TOMCAT_DIR"
tar xzf "apache-tomcat-${TOMCAT_VERSION}.tar.gz" -C "$TOMCAT_DIR" --strip-components=1
rm "apache-tomcat-${TOMCAT_VERSION}.tar.gz"

# Set permissions
log "Setting permissions..."
chown -R tomcat:tomcat "$TOMCAT_DIR"
chmod -R u+rwx "$TOMCAT_DIR"
chmod +x "$TOMCAT_DIR/bin/"*.sh

# Create systemd service
log "Creating systemd service..."
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

# Reload systemd and enable service
log "Enabling Tomcat service..."
systemctl daemon-reload
systemctl enable tomcat
systemctl start tomcat

# Wait for Tomcat to start
log "Waiting for Tomcat to start..."
sleep 5

# Verify Tomcat
log "Verifying Tomcat installation..."
if systemctl is-active --quiet tomcat; then
    log "Tomcat is running. Checking web interface..."
    if curl -s -f "http://localhost:8080" > /dev/null; then
        log "SUCCESS: Tomcat ${TOMCAT_VERSION} installed and accessible at http://localhost:8080"
    else
        log "WARNING: Tomcat is running but web interface is not accessible. Check logs in ${TOMCAT_DIR}/logs."
    fi
else
    log "ERROR: Tomcat service failed to start. Check logs in ${TOMCAT_DIR}/logs."
    exit 1
fi

log "Installation complete. Configure tomcat-users.xml in ${TOMCAT_DIR}/conf for auditing."
log "Run test_config_unix.py or CheckTomcatConfigUnix.py to audit configurations."