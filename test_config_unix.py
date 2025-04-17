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
        "Hashed_SHA512": ["Warning: No CredentialHandler defined in Realm", "Warning: Plaintext password detected for user testuser"],
        "Salted_MD5": ["Warning: No CredentialHandler defined in Realm"],
        "Salted_PBKDF2": ["Warning: No CredentialHandler defined in Realm"]
    },
    "MessageDigestCredentialHandler_MD5": {
        "Plaintext": ["Found CredentialHandler with algorithm: MD5", "Warning: Insecure CredentialHandler algorithm (MD5) detected", "Warning: Plaintext password detected for user testuser"],
        "Hashed_MD5": ["Found CredentialHandler with algorithm: MD5", "Warning: Insecure CredentialHandler algorithm (MD5) detected", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA1": ["Found CredentialHandler with algorithm: MD5", "Warning: Insecure CredentialHandler algorithm (MD5) detected", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA256": ["Found CredentialHandler with algorithm: MD5", "Warning: Insecure CredentialHandler algorithm (MD5) detected", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA512": ["Found CredentialHandler with algorithm: MD5", "Warning: Insecure CredentialHandler algorithm (MD5) detected", "Warning: Plaintext password detected for user testuser"],
        "Salted_MD5": ["Found CredentialHandler with algorithm: MD5", "Warning: Insecure CredentialHandler algorithm (MD5) detected"],
        "Salted_PBKDF2": ["Found CredentialHandler with algorithm: MD5", "Warning: Insecure CredentialHandler algorithm (MD5) detected"]
    },
    "MessageDigestCredentialHandler_SHA256": {
        "Plaintext": ["Found CredentialHandler with algorithm: SHA-256", "Warning: Plaintext password detected for user testuser"],
        "Hashed_MD5": ["Found CredentialHandler with algorithm: SHA-256", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA1": ["Found CredentialHandler with algorithm: SHA-256", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA256": ["Found CredentialHandler with algorithm: SHA-256", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA512": ["Found CredentialHandler with algorithm: SHA-256", "Warning: Plaintext password detected for user testuser"],
        "Salted_MD5": ["Found CredentialHandler with algorithm: SHA-256"],
        "Salted_PBKDF2": ["Found CredentialHandler with algorithm: SHA-256"]
    },
    "MessageDigestCredentialHandler_SHA512": {
        "Plaintext": ["Found CredentialHandler with algorithm: SHA-512", "Warning: Plaintext password detected for user testuser"],
        "Hashed_MD5": ["Found CredentialHandler with algorithm: SHA-512", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA1": ["Found CredentialHandler with algorithm: SHA-512", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA256": ["Found CredentialHandler with algorithm: SHA-512", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA512": ["Found CredentialHandler with algorithm: SHA-512", "Warning: Plaintext password detected for user testuser"],
        "Salted_MD5": ["Found CredentialHandler with algorithm: SHA-512"],
        "Salted_PBKDF2": ["Found CredentialHandler with algorithm: SHA-512"]
    },
    "NestedCredentialHandler": {
        "Plaintext": ["Found CredentialHandler with algorithm: None", "Warning: Plaintext password detected for user testuser"],
        "Hashed_MD5": ["Found CredentialHandler with algorithm: None", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA1": ["Found CredentialHandler with algorithm: None", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA256": ["Found CredentialHandler with algorithm: None", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA512": ["Found CredentialHandler with algorithm: None", "Warning: Plaintext password detected for user testuser"],
        "Salted_MD5": ["Found CredentialHandler with algorithm: None"],
        "Salted_PBKDF2": ["Found CredentialHandler with algorithm: None"]
    },
    "SecretKeyCredentialHandler_PBKDF2": {
        "Plaintext": ["Found CredentialHandler with algorithm: PBKDF2WithHmacSHA512", "Warning: Plaintext password detected for user testuser"],
        "Hashed_MD5": ["Found CredentialHandler with algorithm: PBKDF2WithHmacSHA512", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA1": ["Found CredentialHandler with algorithm: PBKDF2WithHmacSHA512", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA256": ["Found CredentialHandler with algorithm: PBKDF2WithHmacSHA512", "Warning: Plaintext password detected for user testuser"],
        "Hashed_SHA512": ["Found CredentialHandler with algorithm: PBKDF2WithHmacSHA512", "Warning: Plaintext password detected for user testuser"],
        "Salted_MD5": ["Found CredentialHandler with algorithm: PBKDF2WithHmacSHA512"],
        "Salted_PBKDF2": ["Found CredentialHandler with algorithm: PBKDF2WithHmacSHA512"]
    }
}

# Backup original files
server_xml = os.path.join(tomcat_conf_path, "server.xml")
users_xml = os.path.join(tomcat_conf_path, "tomcat-users.xml")
shutil.copy(server_xml, os.path.join(backup_dir, "server.xml.bak"))
shutil.copy(users_xml, os.path.join(backup_dir, "tomcat-users.xml.bak"))
write_log(f"Backed up original files to {backup_dir}")

# Test tracking
test_results = {"total": 0, "passed": 0, "failed": 0}

# Run tests
for server_test in server_tests:
    for password_test in password_tests:
        if password_test == "Hashed_SHA512" and tomcat_version == "7.0":
            write_log(f"Skipping Hashed_SHA512 for Tomcat 7.0 (not supported)", 1)
            continue
        if password_test == "Salted_PBKDF2" and tomcat_version == "7.0":
            write_log(f"Skipping Salted_PBKDF2 for Tomcat 7.0 (not supported)", 1)
            continue
        if password_test == "Salted_PBKDF2" and server_test == "SecretKeyCredentialHandler_PBKDF2" and tomcat_version != "9.0":
            write_log(f"Skipping Salted_PBKDF2 with SecretKeyCredentialHandler for Tomcat {tomcat_version} (not supported)", 1)
            continue

        test_name = f"{tomcat_version}_{server_test}_{password_test}"
        write_log(f"Running test: {test_name} for Tomcat {tomcat_version}", 1)
        write_log(f"Description: Testing {password_test} password with {server_test} CredentialHandler", 2)

        # Modify server.xml
        tree = ET.parse(server_xml)
        root = tree.getroot()
        realm = root.find(".//Realm[@className='org.apache.catalina.realm.UserDatabaseRealm']")
        if realm is None:
            realm = root.find(".//Realm[@className='org.apache.catalina.realm.MemoryRealm']")
        if realm is None:
            write_log("Error: No UserDatabaseRealm or MemoryRealm found in server.xml. Skipping test.", 2)
            continue
        for handler in realm.findall("CredentialHandler"):
            realm.remove(handler)
        if server_test != "NoCredentialHandler":
            handler_tree = ET.fromstring(server_configs[server_test])
            realm.append(handler_tree)
            write_log(f"Modified server.xml: Added {server_test} CredentialHandler", 2)
        else:
            write_log(f"Modified server.xml: Removed all CredentialHandlers", 2)
        tree.write(server_xml, encoding="utf-8", xml_declaration=True)

        # Modify tomcat-users.xml
        users_tree = ET.parse(users_xml)
        users_root = users_tree.getroot()
        user = users_root.find(".//user[@username='testuser']")
        if user is None:
            user = ET.SubElement(users_root, "user", username="testuser", roles="manager")
        user.set("password", password_values[password_test])
        write_log(f"Modified tomcat-users.xml: Set password for testuser to {password_test} ({password_values[password_test]})", 2)
        users_tree.write(users_xml, encoding="utf-8", xml_declaration=True)

        # Expected output
        expected = expected_outcomes[server_test][password_test]
        write_log(f"Expected output: {', '.join(expected)}", 2)

        # Run CheckTomcatConfigUnix.py
        result = subprocess.run(["python3", "./CheckTomcatConfigUnix.py"], capture_output=True, text=True)
        output = result.stdout + result.stderr
        output_lines = [line.strip() for line in output.split("\n") if line.strip() and not line.startswith("[2025")]
        write_log(f"Actual output: {', '.join(output_lines)}", 2)

        # Validate test
        test_results["total"] += 1
        passed = all(exp in output for exp in expected)
        if passed:
            write_log(f"Test {test_name}: PASSED", 2)
            test_results["passed"] += 1
        else:
            write_log(f"Test {test_name}: FAILED (Expected: {expected}, Got: {output_lines})", 2)
            test_results["failed"] += 1

# Restore original files
shutil.copy(os.path.join(backup_dir, "server.xml.bak"), server_xml)
shutil.copy(os.path.join(backup_dir, "tomcat-users.xml.bak"), users_xml)
write_log("Restored original configuration files")

# Summary report
write_log("Test Summary:")
write_log(f"Total tests run: {test_results['total']}", 1)
write_log(f"Tests passed: {test_results['passed']}", 1)
write_log(f"Tests failed: {test_results['failed']}", 1)
write_log("All tests completed")

if test_results["failed"] > 0:
    sys.exit(1)
