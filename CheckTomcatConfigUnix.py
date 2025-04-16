#!/usr/bin/env python3
# CheckTomcatConfigUnix.py
# Audits Tomcat configuration for password security and compliance (7.0, 8.5, 9.0)

import os
import re
import datetime
import xml.etree.ElementTree as ET
import sys

# Log setup
log_file = os.path.expanduser("~/TestTomcatConfig.log")  # User home directory for logging

def write_log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    try:
        with open(log_file, "a") as f:
            f.write(log_message + "\n")
    except PermissionError:
        print(f"Warning: Cannot write to {log_file}. Logging to console only.")
    print(message)

write_log("Checking Apache Tomcat configuration security...")

# Detect Tomcat path and version
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

tomcat_info = get_tomcat_config_path()
if not tomcat_info:
    write_log("Error: No Tomcat configuration directory found")
    sys.exit(1)
tomcat_conf_path = tomcat_info["path"]
tomcat_version = tomcat_info["version"]
write_log(f"Detected Tomcat version {tomcat_version} at {tomcat_conf_path}")

# Load configuration files
server_xml_path = os.path.join(tomcat_conf_path, "server.xml")
users_xml_path = os.path.join(tomcat_conf_path, "tomcat-users.xml")

if not os.path.exists(server_xml_path) or not os.path.exists(users_xml_path):
    write_log("Error: server.xml or tomcat-users.xml not found")
    sys.exit(1)

server_tree = ET.parse(server_xml_path)
users_tree = ET.parse(users_xml_path)
server_root = server_tree.getroot()
users_root = users_tree.getroot()

# Analyze CredentialHandler
realm = server_root.find(".//Realm[@className='org.apache.catalina.realm.UserDatabaseRealm']") or \
        server_root.find(".//Realm[@className='org.apache.catalina.realm.MemoryRealm']")
credential_handler = realm.find("CredentialHandler") if realm else None

# Initialize overall security status
is_secure = True

# Analyze users and passwords
users = users_root.findall("user")
if not users:
    write_log("- No users defined in tomcat-users.xml")
    write_log("- Status: Compliant (no passwords to evaluate)")
    write_log("Overall Configuration: Secure (no vulnerabilities detected)")
    write_log("Audit completed")
    sys.exit(0)

for user in users:
    username = user.get("username")
    password = user.get("password")

    # Skip users without passwords
    if not password:
        write_log(f"- User '{username}': No password defined")
        write_log("  - Status: Compliant (no password to evaluate)")
        continue

    # Detect password type
    password_type = "Plaintext"
    if re.match(r"^[a-f0-9]{32}$", password):
        password_type = "Hashed_MD5"
    elif re.match(r"^[a-f0-9]{40}$", password):
        password_type = "Hashed_SHA1"
    elif re.match(r"^[a-f0-9]{64}$", password):
        password_type = "Hashed_SHA256"
    elif re.match(r"^[a-f0-9]{128}$", password):
        password_type = "Hashed_SHA512"
    elif re.match(r"^[a-f0-9]{32}:[a-f0-9]{16}$", password):
        password_type = "Salted_MD5" if "Salted_MD5" in password else "Salted_PBKDF2"

    security_status = "insecure" if password_type in ["Plaintext", "Hashed_MD5", "Hashed_SHA1", "Salted_MD5"] else "secure"
    write_log(f"- User '{username}': {password_type} password ({security_status})")

    # Parameter checks
    params = []
    params.append(f"- Parameter: Password Type = {password_type} [{'FAIL' if security_status == 'insecure' else 'PASS'}]")
    handler_class = credential_handler.get("className") if credential_handler else "None"
    params.append(f"- Parameter: CredentialHandler = {handler_class} [{'PASS' if credential_handler else 'FAIL'}]")
    algorithm = credential_handler.get("algorithm") if credential_handler else "None"
    params.append(f"- Parameter: Algorithm = {algorithm} [{'PASS' if algorithm in ['SHA-256', 'SHA-512', 'PBKDF2WithHmacSHA512'] else 'FAIL'}]")
    iterations = int(credential_handler.get("iterations", "0")) if credential_handler else 0
    params.append(f"- Parameter: Iterations = {iterations} [{'PASS' if iterations >= 10000 else 'FAIL'}]")
    salt_length = int(credential_handler.get("saltLength", "0")) if credential_handler else 0
    params.append(f"- Parameter: Salt Length = {salt_length} [{'PASS' if salt_length >= 16 else 'FAIL'}]")

    for param in params:
        write_log(f"  {param}")

    # Compliance check
    if password_type == "Plaintext":
        write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
        write_log("    - Plaintext passwords detected in tomcat-users.xml")
        write_log("    - Recommendation: Use salted and iterated passwords (e.g., SHA-256 or PBKDF2)")
        is_secure = False
    elif password_type in ["Hashed_MD5", "Salted_MD5"]:
        write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
        write_log(f"    - Weak password hashing ({password_type}) detected")
        write_log("    - Recommendation: Use SHA-256, SHA-512, or PBKDF2")
        is_secure = False
    elif password_type == "Hashed_SHA1":
        write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
        write_log("    - Weak password hashing (SHA-1) detected")
        write_log("    - Recommendation: Use SHA-256, SHA-512, or PBKDF2")
        is_secure = False
    elif password_type == "Hashed_SHA256":
        if tomcat_version == "7.0":
            write_log("  - Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark for Tomcat 7.0")
        elif not credential_handler or credential_handler.get("algorithm") != "SHA-256" or iterations < 10000 or salt_length < 16:
            write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
            write_log("    - Hashed_SHA256 passwords should use salt and iterations")
            write_log("    - Recommendation: Configure MessageDigestCredentialHandler with saltLength >= 16 and iterations >= 10000")
            is_secure = False
        else:
            write_log("  - Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
    elif password_type == "Hashed_SHA512":
        if tomcat_version == "7.0":
            write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
            write_log("    - SHA-512 not supported in Tomcat 7.0")
            write_log("    - Recommendation: Use SHA-256")
            is_secure = False
        elif not credential_handler or credential_handler.get("algorithm") != "SHA-512" or iterations < 10000 or salt_length < 16:
            write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
            write_log("    - Hashed_SHA512 passwords should use salt and iterations")
            write_log("    - Recommendation: Configure MessageDigestCredentialHandler with saltLength >= 16 and iterations >= 10000")
            is_secure = False
        else:
            write_log("  - Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
    elif password_type == "Salted_PBKDF2":
        if tomcat_version == "7.0":
            write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
            write_log("    - PBKDF2 not supported in Tomcat 7.0")
            write_log("    - Recommendation: Use SHA-256")
            is_secure = False
        elif tomcat_version == "8.5":
            if not credential_handler or credential_handler.get("algorithm") not in ["SHA-256", "SHA-512"] or iterations < 10000 or salt_length < 16:
                write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
                write_log("    - Salted_PBKDF2 requires compatible MessageDigestCredentialHandler")
                write_log("    - Recommendation: Configure MessageDigestCredentialHandler with SHA-256/SHA-512, saltLength >= 16, iterations >= 10000")
                is_secure = False
            else:
                write_log("  - Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
        else:  # Tomcat 9.0
            if credential_handler and credential_handler.get("className") == "org.apache.catalina.realm.SecretKeyCredentialHandler" and \
               credential_handler.get("algorithm") == "PBKDF2WithHmacSHA512" and iterations >= 10000 and salt_length >= 16:
                write_log("  - Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
            else:
                write_log("  - Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark")
                write_log("    - Salted_PBKDF2 requires SecretKeyCredentialHandler with PBKDF2")
                write_log("    - Recommendation: Configure SecretKeyCredentialHandler with PBKDF2, saltLength >= 16, iterations >= 10000")
                is_secure = False

write_log(f"Overall Configuration: {'Secure' if is_secure else 'Insecure'}")
write_log("Audit completed")
