#!/usr/bin/env python3
# CheckTomcatConfigUnix.py
# Audits Apache Tomcat configuration for security issues

import os
import sys
import xml.etree.ElementTree as ET
import datetime

# Log setup
log_file = os.path.expanduser("~/TestTomcatConfig.log")

def write_log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    try:
        with open(log_file, "a") as f:
            f.write(log_message + "\n")
    except PermissionError:
        print(f"Warning: Cannot write to {log_file}. Logging to console only.")
    print(log_message)

write_log("Checking Apache Tomcat configuration security...")

# Function to detect Tomcat path
def get_tomcat_config_path():
    # Check CATALINA_HOME environment variable first
    catalina_home = os.getenv("CATALINA_HOME")
    if catalina_home:
        conf_path = os.path.join(catalina_home, "conf")
        if os.path.exists(conf_path) and os.path.exists(os.path.join(conf_path, "server.xml")):
            write_log(f"Found Tomcat configuration at CATALINA_HOME: {conf_path}")
            return conf_path

    # Fallback to possible paths
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

# Detect Tomcat configuration directory
tomcat_conf_path = get_tomcat_config_path()
if not tomcat_conf_path:
    write_log("Error: No Tomcat configuration directory found")
    sys.exit(1)

# Audit server.xml
server_xml = os.path.join(tomcat_conf_path, "server.xml")
try:
    tree = ET.parse(server_xml)
    root = tree.getroot()

    # Check for Realm elements
    realm = (root.find(".//Realm[@className='org.apache.catalina.realm.UserDatabaseRealm']") or
             root.find(".//Realm[@className='org.apache.catalina.realm.MemoryRealm']"))
    if realm is None:
        write_log("Warning: No UserDatabaseRealm or MemoryRealm found in server.xml")
    else:
        handler = realm.find("CredentialHandler")
        if handler is None:
            write_log("Warning: No CredentialHandler defined in Realm")
        else:
            algorithm = handler.get("algorithm", "None")
            write_log(f"Found CredentialHandler with algorithm: {algorithm}")
            if algorithm in ["MD5", "SHA-1"]:
                write_log(f"Warning: Insecure CredentialHandler algorithm ({algorithm}) detected")
except FileNotFoundError:
    write_log(f"Error: {server_xml} not found")
    sys.exit(1)
except ET.ParseError:
    write_log(f"Error: Invalid XML in {server_xml}")
    sys.exit(1)

# Audit tomcat-users.xml
users_xml = os.path.join(tomcat_conf_path, "tomcat-users.xml")
try:
    users_tree = ET.parse(users_xml)
    users_root = users_tree.getroot()
    users = users_root.findall(".//user")
    if not users:
        write_log("Warning: No users defined in tomcat-users.xml")
    for user in users:
        username = user.get("username")
        password = user.get("password")
        if password and ":" not in password and not password.startswith("{"):
            write_log(f"Warning: Plaintext password detected for user {username}")
except FileNotFoundError:
    write_log(f"Error: {users_xml} not found")
    sys.exit(1)
except ET.ParseError:
    write_log(f"Error: Invalid XML in {users_xml}")
    sys.exit(1)

write_log("Tomcat configuration audit completed")
