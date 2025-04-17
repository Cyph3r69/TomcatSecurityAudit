#!/usr/bin/env python3
# test_config_unix.py
# Tests CheckTomcatConfigUnix.py for various Tomcat configurations

import os
import shutil
import datetime
import xml.etree.ElementTree as ET
import subprocess
import sys
from pathlib import Path

# Log setup
log_file = os.path.expanduser("~/TestTomcatConfig.log")

def write_log(message, indent=0, console_only=False):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{'  ' * indent}{message}"
    if not console_only:
        log_message = f"[{timestamp}] {log_message}"
        try:
            with open(log_file, "a") as f:
                f.write(log_message + "\n")
        except PermissionError:
            print(f"Warning: Cannot write to {log_file}. Logging to console only.", file=sys.stderr)
    print(log_message)

write_log("Starting tests for CheckTomcatConfigUnix.py...", console_only=True)

# Verify script exists
if not os.path.exists("./CheckTomcatConfigUnix.py"):
    write_log("Error: CheckTomcatConfigUnix.py not found")
    sys.exit(1)
write_log("Verified file exists: ./CheckTomcatConfigUnix.py")

# Clear existing log
try:
    if os.path.exists(log_file):
        open(log_file, "w").close()
        write_log(f"Cleared existing log file: {log_file}")
except PermissionError:
    write_log(f"Warning: Cannot clear {log_file}. Proceeding with existing log.")

# Function to detect Tomcat path and version
def get_tomcat_config_path():
    catalina_home = os.getenv("CATALINA_HOME")
    if catalina_home:
        conf_path = os.path.join(catalina_home, "conf")
        if os.path.exists(conf_path) and os.path.exists(os.path.join(conf_path, "server.xml")):
            version = detect_tomcat_version(catalina_home)
            write_log(f"Found Tomcat at CATALINA_HOME: {catalina_home}, version: {version}")
            return {"path": conf_path, "version": version}

    possible_paths = [
        "/usr/local/tomcat/conf",
        "/opt/tomcat/conf",
        "/opt/tomcat9/conf",
        "/var/lib/tomcat7/conf",
        "/var/lib/tomcat8/conf",
        "/var/lib/tomcat9/conf",
        "/usr/share/tomcat7/conf",
        "/usr/share/tomcat8/conf",
        "/usr/share/tomcat9/conf"
    ]
    for path in possible_paths:
        if os.path.exists(path) and os.path.exists(os.path.join(path, "server.xml")):
            version = detect_tomcat_version(os.path.dirname(path))
            write_log(f"Found Tomcat at {path}, version: {version}")
            return {"path": path, "version": version}
    
    write_log("Error: No Tomcat configuration directory found in CATALINA_HOME or known paths")
    return None

# Function to detect Tomcat version
def detect_tomcat_version(tomcat_home):
    version_file = os.path.join(tomcat_home, "RELEASE-NOTES")
    if os.path.exists(version_file):
        with open(version_file, "r") as f:
            for line in f:
                if line.startswith("Apache Tomcat Version"):
                    version = line.split()[-1]
                    if version.startswith("7."):
                        return "7.0"
                    elif version.startswith("8."):
                        return "8.5"
                    elif version.startswith("9."):
                        return "9.0"
    if "tomcat7" in tomcat_home.lower():
        return "7.0"
    elif "tomcat8" in tomcat_home.lower():
        return "8.5"
    elif "tomcat9" in tomcat_home.lower():
        return "9.0"
    return "Unknown"

# Detect Tomcat installation
tomcat_info = get_tomcat_config_path()
if not tomcat_info:
    write_log("Error: No Tomcat configuration directory found")
    sys.exit(1)
tomcat_conf_path = tomcat_info["path"]
tomcat_version = tomcat_info["version"]
write_log(f"Detected Tomcat version {tomcat_version} at {tomcat_conf_path}", console_only=True)

# Backup directory
backup_dir = "/tmp/TomcatConfigBackup"
os.makedirs(backup_dir, exist_ok=True)

# Define test cases
password_tests = [
    "Plaintext",
    "Hashed_MD5",
    "Hashed_SHA1",
    "Hashed_SHA256",
    "Hashed_SHA512",
    "Salted_MD5",
    "Salted_PBKDF2"
]

server_tests = [
    "NoCredentialHandler",
    "MessageDigestCredentialHandler_MD5",
    "MessageDigestCredentialHandler_SHA256"
]
if tomcat_version in ["8.5", "9.0"]:
    server_tests.extend([
        "MessageDigestCredentialHandler_SHA512",
        "NestedCredentialHandle
