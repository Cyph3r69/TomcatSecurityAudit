#!/usr/bin/env python3
# CheckTomcatConfigUnix.py
# Audits Apache Tomcat configuration for security issues

import os
import sys
import xml.etree.ElementTree as ET
import datetime
import re

# Log setup
log_file = os.path.expanduser("~/TestTomcatConfig.log")

def write_log(message, indent=0):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {'  ' * indent}{message}"
    try:
        with open(log_file, "a") as f:
            f.write(log_message + "\n")
    except PermissionError:
        print(f"Warning: Cannot write to {log_file}. Logging to console only.", file=sys.stderr)
    print(log_message)

write_log("Checking Apache Tomcat configuration security...")

# Function to detect Tomcat path
def get_tomcat_config_path():
    catalina_home = os.getenv("CATALINA_HOME")
    if catalina_home:
        conf_path = os.path.join(catalina_home, "conf")
        if os.path.exists(conf_path) and os.path.exists(os.path.join(conf_path, "server.xml")):
            write_log(f"Found Tomcat configuration at CATALINA_HOME: {conf_path}")
            return conf_path

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
            write_log(f"Found Tomcat configuration at {path}")
            return path
    
    write_log("Error: No Tomcat configuration directory found")
    return None

# Detect Tomcat version
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

# Detect Tomcat configuration directory
tomcat_conf_path = get_tomcat_config_path()
if not tomcat_conf_path:
    write_log("Error: No Tomcat configuration directory found")
    sys.exit(1)

tomcat_version = detect_tomcat_version(os.path.dirname(tomcat_conf_path))
write_log(f"Detected Tomcat version {tomcat_version} at {tomcat_conf_path}")

# Audit server.xml
server_xml = os.path.join(tomcat_conf_path, "server.xml")
try:
    tree = ET.parse(server_xml)
    root = tree.getroot()
except FileNotFoundError:
    write_log(f"Error: {server_xml} not found")
    sys.exit(1)
except ET.ParseError:
    write_log(f"Error: Invalid XML in {server_xml}")
    sys.exit(1)

write_log(f"Auditing server.xml at {server_xml}", 1)
realm = root.find(".//Realm[@className='org.apache.catalina.realm.UserDatabaseRealm']")
if realm is None:
    realm = root.find(".//Realm[@className='org.apache.catalina.realm.MemoryRealm']")
credential_handler = None
if realm is not None:
    credential_handler = realm.find("CredentialHandler")

# Initialize overall security status
is_secure = True

# Audit tomcat-users.xml
users_xml = os.path.join(tomcat_conf_path, "tomcat-users.xml")
try:
    users_tree = ET.parse(users_xml)
    users_root = users_tree.getroot()
except FileNotFoundError:
    write_log(f"Error: {users_xml} not found", 1)
    sys.exit(1)
except ET.ParseError:
    write_log(f"Error: Invalid XML in {users_xml}", 1)
    sys.exit(1)

write_log(f"Auditing tomcat-users.xml at {users_xml}", 1)
users = users_root.findall(".//user")
if not users:
    write_log("No users defined in tomcat-users.xml", 2)
    write_log("Status: Compliant (no passwords to evaluate)", 2)
    write_log("Overall Configuration: Secure (no vulnerabilities detected)")
    write_log("Audit completed")
    sys.exit(0)

for user in users:
    username = user.get("username", "unknown")
    password = user.get("password", "")
    write_log(f"User '{username}': Analyzing password", 2)

    if not password:
        write_log(f"No password defined", 3)
        write_log("Status: Compliant (no password to evaluate)", 3)
        continue

    # Detect password type
    password_type = "Plaintext"
    if re.match(r"^[a-f0-9]{32}$", password.lower()):
        password_type = "Hashed_MD5"
    elif re.match(r"^[a-f0-9]{40}$", password.lower()):
        password_type = "Hashed_SHA1"
    elif re.match(r"^[a-f0-9]{64}$", password.lower()):
        password_type = "Hashed_SHA256"
    elif re.match(r"^[a-f0-9]{128}$", password.lower()):
        password_type = "Hashed_SHA512"
    elif re.match(r"^[a-f0-9]{32}:[a-f0-9]{16}$", password.lower()):
        if credential_handler is not None and credential_handler.get("className") == "org.apache.catalina.realm.SecretKeyCredentialHandler":
            password_type = "Salted_PBKDF2"
        else:
            password_type = "Salted_MD5"

    write_log(f"Password Type: {password_type} ({'insecure' if password_type in ['Plaintext', 'Hashed_MD5', 'Hashed_SHA1', 'Salted_MD5'] else 'secure'})", 3)

    # Parameter checks
    params = []

    # Parameter: Password Type
    params.append(f"Parameter: Password Type = {password_type} [{'FAIL' if password_type in ['Plaintext', 'Hashed_MD5', 'Hashed_SHA1', 'Salted_MD5'] else 'PASS'}]")

    # Parameter: CredentialHandler Presence
    handler_class = credential_handler.get("className", "None") if credential_handler is not None else "None"
    params.append(f"Parameter: CredentialHandler = {handler_class} [{'PASS' if credential_handler is not None else 'FAIL'}]")

    # Parameter: Algorithm
    algorithm = credential_handler.get("algorithm", "None") if credential_handler is not None else "None"
    params.append(f"Parameter: Algorithm = {algorithm} [{'PASS' if algorithm in ['SHA-256', 'SHA-512', 'PBKDF2WithHmacSHA512'] else 'FAIL'}]")

    # Parameter: Iterations
    iterations = int(credential_handler.get("iterations", 0)) if credential_handler is not None else 0
    params.append(f"Parameter: Iterations = {iterations} [{'PASS' if iterations >= 10000 else 'FAIL'}]")

    # Parameter: Salt Length
    salt_length = int(credential_handler.get("saltLength", 0)) if credential_handler is not None else 0
    params.append(f"Parameter: Salt Length = {salt_length} [{'PASS' if salt_length >= 16 else 'FAIL'}]")

    # Log parameters
    for param in params:
        write_log(param, 3)

    # Compliance check
    if password_type == "Plaintext":
        write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
        write_log("Plaintext passwords detected in tomcat-users.xml", 4)
        write_log("Recommendation: Use salted and iterated passwords (e.g., SHA-256 or PBKDF2)", 4)
        is_secure = False
    elif password_type in ["Hashed_MD5", "Salted_MD5"]:
        write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
        write_log(f"Weak password hashing ({password_type}) detected", 4)
        write_log("Recommendation: Use SHA-256, SHA-512, or PBKDF2", 4)
        is_secure = False
    elif password_type == "Hashed_SHA1":
        write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
        write_log("Weak password hashing (SHA-1) detected", 4)
        write_log("Recommendation: Use SHA-256, SHA-512, or PBKDF2", 4)
        is_secure = False
    elif password_type == "Hashed_SHA256":
        if tomcat_version == "7.0":
            write_log("Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark for Tomcat 7.0", 3)
        elif credential_handler is None or algorithm != "SHA-256" or iterations < 10000 or salt_length < 16:
            write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
            write_log("Hashed_SHA256 passwords should use salt and iterations", 4)
            write_log("Recommendation: Configure MessageDigestCredentialHandler with saltLength >= 16 and iterations >= 10000", 4)
            is_secure = False
        else:
            write_log("Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
    elif password_type == "Hashed_SHA512":
        if tomcat_version == "7.0":
            write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
            write_log("SHA-512 not supported in Tomcat 7.0", 4)
            write_log("Recommendation: Use SHA-256", 4)
            is_secure = False
        elif credential_handler is None or algorithm != "SHA-512" or iterations < 10000 or salt_length < 16:
            write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
            write_log("Hashed_SHA512 passwords should use salt and iterations", 4)
            write_log("Recommendation: Configure MessageDigestCredentialHandler with saltLength >= 16 and iterations >= 10000", 4)
            is_secure = False
        else:
            write_log("Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
    elif password_type == "Salted_PBKDF2":
        if tomcat_version == "7.0":
            write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
            write_log("PBKDF2 not supported in Tomcat 7.0", 4)
            write_log("Recommendation: Use SHA-256", 4)
            is_secure = False
        elif tomcat_version == "8.5":
            if credential_handler is None or algorithm not in ["SHA-256", "SHA-512"] or iterations < 10000 or salt_length < 16:
                write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
                write_log("Salted_PBKDF2 requires compatible MessageDigestCredentialHandler", 4)
                write_log("Recommendation: Configure MessageDigestCredentialHandler with SHA-256/SHA-512, saltLength >= 16, iterations >= 10000", 4)
                is_secure = False
            else:
                write_log("Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
        else:  # Tomcat 9.0
            if credential_handler is not None and handler_class == "org.apache.catalina.realm.SecretKeyCredentialHandler" and \
               algorithm == "PBKDF2WithHmacSHA512" and iterations >= 10000 and salt_length >= 16:
                write_log("Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
            else:
                write_log("Status: Non-compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark", 3)
                write_log("Salted_PBKDF2 requires SecretKeyCredentialHandler with PBKDF2", 4)
                write_log("Recommendation: Configure SecretKeyCredentialHandler with PBKDF2, saltLength >= 16, iterations >= 10000", 4)
                is_secure = False

write_log(f"Overall Configuration: {'Secure' if is_secure else 'Insecure'}")
write_log("Audit completed")
