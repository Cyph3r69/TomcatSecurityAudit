# TomcatSecurityAudit
PowerShell scripts designed to audit the security of Apache Tomcat configurations, focusing on password storage and compliance with NIST 800-53 IA-5 and CIS Tomcat Benchmark 4.1. The scripts identify insecure configurations, such as plaintext passwords or weak hashing, and provide recommendations to ensure a secure Tomcat environment.

Configuration Audit: Analyzes server.xml and tomcat-users.xml for secure password handling.
Compliance Checks: Validates against NIST 800-53 IA-5 and CIS Tomcat Benchmark 4.1 standards.
Automated Testing: Tests 42 scenarios covering various password types and authentication handlers.
Actionable Reports: Generates detailed logs with compliance status and remediation steps.

# Prerequisites
Windows environment with PowerShell 5.1 or later.
Apache Tomcat (e.g., version 9.0) installed.
Administrative privileges to read/write Tomcat configuration files.

# Installation
Clone the repository:git clone https://github.com/your-username/TomcatSecurityAudit.git
Navigate to the repository directory:cd TomcatSecurityAudit

# Usage
Run the Audit:
Execute CheckTomcatConfig.ps1 to audit your Tomcat configuration:.\CheckTomcatConfig.ps1
Output is logged to C:\Users\<YourUser>\AppData\Local\Temp\TestTomcatConfig.log.

# Run Automated Tests:
Execute test_config.ps1 to validate the audit script across 42 test cases:.\test_config.ps1
Results are logged to the same temp directory.

# Scripts
CheckTomcatConfig.ps1: Core script that evaluates password types (e.g., plaintext, PBKDF2) and authentication handlers (e.g., SecretKeyCredentialHandler).
test_config.ps1: Tests CheckTomcatConfig.ps1 by simulating various configurations, ensuring accurate detection of secure and insecure setups.

# Recommended Configurations
To ensure compliance and security:

Use SecretKeyCredentialHandler with PBKDF2, 16-byte salt, 10,000 iterations, and 256-bit key length in server.xml.
Store passwords in tomcat-users.xml using salted PBKDF2 or SHA-256/SHA-512.
Avoid plaintext, MD5, SHA-1, or unsalted hashes.
Example server.xml configuration:<Realm className="org.apache.catalina.realm.LockOutRealm">
  <Realm className="org.apache.catalina.realm.UserDatabaseRealm" resourceName="UserDatabase">
    <CredentialHandler className="org.apache.catalina.realm.SecretKeyCredentialHandler"
                      algorithm="PBKDF2WithHmacSHA512"
                      iterations="10000"
                      saltLength="16"
                      keyLength="256"/>
  </Realm>
</Realm>

# Output
Logs detail password types, compliance status, and recommendations.
Example:- User 'testuser': Salted_PBKDF2 password (secure)
- Status: Compliant with NIST 800-53 IA-5 and CIS Tomcat Benchmark 4.1

# Contributing
Contributions are welcome! Please:

# Fork the repository.
Create a feature branch (git checkout -b feature/YourFeature).
Commit changes (git commit -m "Add YourFeature").
Push to the branch (git push origin feature/YourFeature).
Open a pull request.

# License
This project is licensed under the MIT License. See the LICENSE file for details.
Contact
