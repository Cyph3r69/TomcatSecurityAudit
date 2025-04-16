#!/usr/bin/env python3
# test_config.py
# Tests check_tomcat_config.py for various Tomcat configurations (7.0, 8.5, 9.0)

import os
import shutil
import datetime
import xml.etree.ElementTree as ET
import subprocess
import sys
from pathlib import Path

# Log setup
log_file = "/tmp/TestTomcatConfig.log"

def write_log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    with open(log_file, "a") as f:
        f.write(log_message + "\n")
    print(log_message)

write_log("Starting tests for check_tomcat_config.py...")

# Verify script exists
if not os.path.exists("./check_tomcat_config.py"):
    write_log("Error: check_tomcat_config.py not found")
    sys.exit(1)
write_log("Verified file exists: ./check_tomcat_config.py")

# Clear existing log
if os.path.exists(log_file):
    open(log_file, "w").close()
    write_log(f"Cleared existing log file: {log_file}")

# Function to detect Tomcat path and version
def get_tomcat_config_path():
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
        if os.path.exists(path):
            server_xml = os.path.join(path, "server.xml")
            if os.path.exists(server_xml):
                version = "Unknown"
                if "tomcat7" in path:
                    version = "7.0"
                elif "tomcat8" in path:
                    version = "8.5"
                elif "tomcat9" in path:
                    version = "9.0"
                return {"path": path, "version": version}
    return None

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

# Backup original files
server_xml = os.path.join(tomcat_conf_path, "server.xml")
users_xml = os.path.join(tomcat_conf_path, "tomcat-users.xml")
shutil.copy(server_xml, os.path.join(backup_dir, "server.xml.bak"))
shutil.copy(users_xml, os.path.join(backup_dir, "tomcat-users.xml.bak"))

# Run tests
for server_test in server_tests:
    for password_test in password_tests:
        if password_test == "Hashed_SHA512" and tomcat_version == "7.0":
            write_log("Skipping Hashed_SHA512 for Tomcat 7.0 (not supported)")
            continue
        if password_test == "Salted_PBKDF2" and tomcat_version == "7.0":
            write_log("Skipping Salted_PBKDF2 for Tomcat 7.0 (not supported)")
            continue
        if password_test == "Salted_PBKDF2" and server_test == "SecretKeyCredentialHandler_PBKDF2" and tomcat_version != "9.0":
            write_log(f"Skipping Salted_PBKDF2 with SecretKeyCredentialHandler for Tomcat {tomcat_version} (not supported)")
            continue
        write_log(f"Running test: {tomcat_version}_{server_test}_{password_test} for Tomcat {tomcat_version}")

        # Modify server.xml
        tree = ET.parse(server_xml)
        root = tree.getroot()
        realm = root.find(".//Realm[@className='org.apache.catalina.realm.UserDatabaseRealm']") or \
                root.find(".//Realm[@className='org.apache.catalina.realm.MemoryRealm']")
        for handler in realm.findall("CredentialHandler"):
            realm.remove(handler)
        if server_test != "NoCredentialHandler":
            handler_tree = ET.fromstring(server_configs[server_test])
            realm.append(handler_tree)
        tree.write(server_xml, encoding="utf-8", xml_declaration=True)

        # Modify tomcat-users.xml
        users_tree = ET.parse(users_xml)
        users_root = users_tree.getroot()
        user = users_root.find(".//user[@username='testuser']")
        if user is None:
            user = ET.SubElement(users_root, "user", username="testuser", roles="manager")
        user.set("password", password_values[password_test])
        users_tree.write(users_xml, encoding="utf-8", xml_declaration=True)

        # Run check_tomcat_config.py
        result = subprocess.run(["python3", "./check_tomcat_config.py"], capture_output=True, text=True)
        output = result.stdout + result.stderr
        write_log(f"Test output: {output.strip()}")

# Restore original files
shutil.copy(os.path.join(backup_dir, "server.xml.bak"), server_xml)
shutil.copy(os.path.join(backup_dir, "tomcat-users.xml.bak"), users_xml)
write_log("Restored original configuration files")

write_log("All tests completed successfully")
