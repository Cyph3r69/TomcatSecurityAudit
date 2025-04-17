#!/usr/bin/env python3
# test_config_unix.py
# Tests CheckTomcatConfigUnix.py for various Tomcat configurations (7.0, 8.5, 9.0)

import os
import shutil
import datetime
import xml.etree.ElementTree as ET
import subprocess
import sys
from pathlib import Path

# Log setup
log_file = os.path.expanduser("~/TestTomcatConfig.log")

def write_log(message, indent=0):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {'  ' * indent}{message}"
    try:
        with open(log_file, "a") as f:
            f.write(log_message + "\n")
    except PermissionError:
        print(f"Warning: Cannot write to {log_file}. Logging to console only.")
    print(log_message)

write_log("Starting tests for CheckTomcatConfigUnix.py...")

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
write_log(f"Detected Tomcat version {tomcat_version} at {tomcat_conf_path}")

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
        "NestedCredentialHandler"
    ])
if tomcat_version == "9.0":
    server_tests.append("SecretKeyCredentialHandler_PBKDF2")
if tomcat_version == "7.0":
    write_log("Limiting tests for Tomcat 7.0: Excluding SHA-512, NestedCredentialHandler, and SecretKeyCredentialHandler")

# Password examples
password_values = {
    "Plaintext": "s3cret",
    "Hashed_MD5": "5ebe2294ecd0e0f08eab7690d2a6ee69",
    "Hashed_SHA1": "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4",
    "Hashed_SHA256": "94f9b6c88f1b2b3b3363b7f4174480c1b3913b8200cb0a50f2974f2bc90bc774",
    "Hashed_SHA512": "eede1e3b1840e3a3c2283ff623e3db6b4d8abfad6bded83fd36f9db08e7c3f2c2df0b5b7e6c9c0d1ebfe7e3b3c3d8b0e7f9d0c1f7e6b4c3b2a1f0e9d8c7b6a5f",
    "Salted_MD5": "8208b5051cdd2b35cfba7f0b70b57e7f:1234567890abcdef",
    "Salted_PBKDF2": "4b6f7e8c9d0a1b2c3d4e5f60718293a4:1234567890abcdef"
}

# Server configurations
server_configs = {
    "NoCredentialHandler": "",
    "MessageDigestCredentialHandler_MD5": '<CredentialHandler className="org.apache.catalina.realm.MessageDigestCredentialHandler" algorithm="MD5"/>',
    "MessageDigestCredentialHandler_SHA256": '<CredentialHandler className="org.apache.catalina.realm.MessageDigestCredentialHandler" algorithm="SHA-256" iterations="10000" saltLength="16"/>',
    "MessageDigestCredentialHandler_SHA512": '<CredentialHandler className="org.apache.catalina.realm.MessageDigestCredentialHandler" algorithm="SHA-512" iterations="10000" saltLength="16"/>',
    "NestedCredentialHandler": '<CredentialHandler className="org.apache.catalina.realm.NestedCredentialHandler"><CredentialHandler className="org.apache.catalina.realm.MessageDigestCredentialHandler" algorithm="SHA-256"/></CredentialHandler>',
    "SecretKeyCredentialHandler_PBKDF2": '<CredentialHandler className="org.apache.catalina.realm.SecretKeyCredentialHandler" algorithm="PBKDF2WithHmacSHA512" iterations="10000" saltLength="16" keyLength="256"/>'
}

# Expected outcomes for validation
expected_outcomes = {
    "NoCredentialHandler": {
        "Plaintext": ["Warning: No CredentialHandler defined in Realm", "Warning: Plaintext password detected for user testuser"],
        "Hashed_MD5": ["Warning: No CredentialHandler defined in Realm", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA1": ["Warning: No CredentialHandler defined in Realm", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA256": ["Warning: No CredentialHandler defined in Realm", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA512": ["Warning: No CredentialHandler defined in Realm", "Warning: Plain
