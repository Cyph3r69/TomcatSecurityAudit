# Tomcat Configuration Security Auditor
## Executive Summary
The Tomcat Configuration Security Auditor consists of two PowerShell scripts, test_config.ps1 and CheckTomcatConfig.ps1, designed to evaluate the security of Apache Tomcat user authentication configurations. These scripts ensure compliance with NIST 800-53 IA-5 and CIS Tomcat Benchmark standards by analyzing password hashing and credential handler settings.
Features

### Automated Testing: 
test_config.ps1 runs comprehensive tests across multiple password types and server configurations, modifying tomcat-users.xml and server.xml to simulate various scenarios and validating them with CheckTomcatConfig.ps1.
### Manual Auditing: 
CheckTomcatConfig.ps1 allows standalone analysis of existing configurations, reporting user passwords, credential handlers, and compliance status.
### Detailed Reporting: 
Outputs include password type, security status (secure/insecure), checked parameters (e.g., algorithm, iterations, salt length), and compliance details with recommendations.
### Backup and Restore: 
Automatically backs up configuration files before testing and restores them afterward to prevent unintended changes.
Logging: Detailed logs are saved to %LOCALAPPDATA%\Temp\TestTomcatConfig.log for troubleshooting and record-keeping.
### Robust Error Handling: 
Uses UTF-8 encoding to avoid XML parsing issues and supports both UserDatabaseRealm and MemoryRealm.

## Supported Tomcat Versions
7.0: Limited to basic MessageDigestCredentialHandler (MD5, SHA-1, SHA-256).
8.5: Adds support for SHA-512 and NestedCredentialHandler.
9.0: Includes SecretKeyCredentialHandler for PBKDF2-based hashing.

## Recommended Password Hashes
SHA-256: With MessageDigestCredentialHandler, minimum 10,000 iterations, and 16-byte salt (8.5, 9.0).
SHA-512: With MessageDigestCredentialHandler, minimum 10,000 iterations, and 16-byte salt (8.5, 9.0).
PBKDF2: With SecretKeyCredentialHandler (PBKDF2WithHmacSHA512), minimum 10,000 iterations, and 16-byte salt (9.0 only).
Note: Plaintext, MD5, SHA-1, and unsalted hashes are insecure and non-compliant.

## Detected Password Hashes
The scripts identify the following password types in tomcat-users.xml:

Plaintext: Insecure, non-compliant.
Hashed_MD5: 32-character hex (insecure).
Hashed_SHA1: 40-character hex (insecure).
Hashed_SHA256: 64-character hex (secure with proper handler).
Hashed_SHA512: 128-character hex (secure with proper handler, 8.5/9.0 only).
Salted_MD5: 32-character hex with 16-character salt (insecure).
Salted_PBKDF2: 32-character hex with 16-character salt (secure with proper handler, 9.0 preferred).

## Overview
These scripts audit Apache Tomcat configurations to ensure secure password storage and compliance with industry standards. test_config.ps1 automates testing by simulating various password and credential handler configurations, while CheckTomcatConfig.ps1 provides a manual audit of existing setups. They are designed for system administrators and security professionals managing Tomcat 7.0, 8.5, or 9.0 installations.
Prerequisites

Windows OS with PowerShell 5.1 or later.
Apache Tomcat 7.0, 8.5, or 9.0 installed (e.g., C:\Program Files (x86)\Apache Software Foundation\Tomcat 9.0).
Write access to conf\server.xml and conf\tomcat-users.xml.
Both scripts placed in the same directory (e.g., C:\Users\Admin\Desktop).

## Setup

## Download Scripts:
Save test_config.ps1 and CheckTomcatConfig.ps1 to a working directory (e.g., C:\Users\Admin\Desktop).

## Verify Tomcat Installation:
Ensure Tomcat is installed and running.
Confirm server.xml and tomcat-users.xml exist in the conf directory.

Set Execution Policy (if needed):Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

## Usage
### Automated Testing with test_config.ps1

Tests multiple password types and credential handlers, restoring original configurations afterward.
Command:PS C:\Users\Admin\Desktop> .\test_config.ps1


Example Output (Tomcat 9.0):[2025-04-16 14:10:00] Detected Tomcat version 9.0 at C:\Program Files (x86)\Apache Software Foundation\Tomcat 9.0\conf
[2025-04-16 14:10:00] Running test: 9.0_SecretKeyCredentialHandler_PBKDF2_Salted_PBKDF2 for Tomcat 9.0
Test output: - User 'testuser': Salted_PBKDF2 password (secure)
...
[2025-04-16 14:10:05] All tests completed successfully


## Test Counts:
Tomcat 7.0: 15 tests (3 server configs × 5 password types).
Tomcat 8.5: 35 tests (5 server configs × 7 password types).
Tomcat 9.0: 42 tests (6 server configs × 7 password types).

### Manual Auditing with CheckTomcatConfig.ps1

Analyzes the current configuration for security and compliance.
Command:PS C:\Users\Admin\Desktop> .\CheckTomcatConfig.ps1


Example Output (secure setup):Checking Apache Tomcat configuration security...
Detected Tomcat version 9.0 at C:\Program Files (x86)\Apache Software Foundation\Tomcat 9.0\conf
- User 'testuser': Hashed_SHA256 password (secure)
  - Parameter: Password Type = Hashed_SHA256 [PASS]
  - Parameter: CredentialHandler = org.apache.catalina.realm.MessageDigestCredentialHandler [PASS]
  - Parameter: Algorithm = SHA-256 [PASS]
  - Parameter: Iterations = 10000 [PASS]
  - Parameter: Salt Length = 16 [PASS]
  - Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark
Overall Configuration: Secure
Audit completed


Empty Configuration:Checking Apache Tomcat configuration security...
Detected Tomcat version 9.0 at C:\Program Files (x86)\Apache Software Foundation\Tomcat 9.0\conf
- No users defined in tomcat-users.xml
- Status: Compliant (no passwords to evaluate)
Overall Configuration: Secure (no vulnerabilities detected)
Audit completed



## Log File

Both scripts log details to %LOCALAPPDATA%\Temp\TestTomcatConfig.log (e.g., C:\Users\Admin\AppData\Local\Temp\TestTomcatConfig.log).
Use for debugging or compliance records.

Configuration Notes

Adding Test Users (for manual audits):Edit tomcat-users.xml to include users, e.g.:<tomcat-users>
  <user username="testuser" password="94f9b6c88f1b2b3b3363b7f4174480c1b3913b8200cb0a50f2974f2bc90bc774" roles="manager"/>
</tomcat-users>


Credential Handler (recommended for 9.0):<Realm className="org.apache.catalina.realm.UserDatabaseRealm">
  <CredentialHandler className="org.apache.catalina.realm.SecretKeyCredentialHandler" algorithm="PBKDF2WithHmacSHA512" iterations="10000" saltLength="16" keyLength="256"/>
</Realm>



## Limitations

Password detection uses simplified regex for testing; custom hash formats may require script adjustments.
Tomcat 7.0 lacks support for SHA-512 and PBKDF2, limiting compliance options.
Assumes standard Tomcat installation paths; custom paths may need script modification.

Support
For issues or enhancements:

Check the log file for errors.
Contact the administrator with log details and tomcat-users.xml (sanitized).
Specify Tomcat version and observed behavior.
