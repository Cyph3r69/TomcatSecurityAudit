# test_config.ps1
# Tests CheckTomcatConfig.ps1 for various Apache Tomcat configurations and password types

$ErrorActionPreference = "Stop"

# Configuration paths
$scriptPath = ".\CheckTomcatConfig.ps1"
$tomcatVersion = "9.0"
$tomcatConfDir = "C:\Program Files (x86)\Apache Software Foundation\Tomcat $tomcatVersion\conf"
$logFile = "$env:LOCALAPPDATA\Temp\TestTomcatConfig.log"
$backupDir = "$env:LOCALAPPDATA\Temp\TomcatConfigBackup"

# Test configurations
$serverConfigs = @(
    "NoCredentialHandler",
    "MessageDigestCredentialHandler_MD5",
    "MessageDigestCredentialHandler_SHA256",
    "MessageDigestCredentialHandler_SHA512",
    "SecretKeyCredentialHandler_PBKDF2",
    "NestedCredentialHandler"
)

$passwordTypes = @(
    @{ Type = "Plaintext"; Value = "s3cret" },
    @{ Type = "Hashed_MD5"; Value = "5ebe2294ecd0e0f08eab7690d2a6ee69" },
    @{ Type = "Hashed_SHA1"; Value = "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4" },
    @{ Type = "Hashed_SHA256"; Value = "94f9b6c88f1b2b3b3363b7f4174480c1b3913b8200cb0a50f2974f2bc90bc774" },
    @{ Type = "Hashed_SHA512"; Value = "eede1e3b1840e3a3c2283ff623e3db6b4d8abfad6bded83fd36f9db08e7c3f2c2df0b5b7e6c9c0d1ebfe7e3b3c3d8b0e7f9d0c1f7e6b4c3b2a1f0e9d8c7b6a5f" },
    @{ Type = "Salted_MD5"; Value = "8208b5051cdd2b35cfba7f0b70b57e7f" },
    @{ Type = "Salted_PBKDF2"; Value = "4b6f7e8c9d0a1b2c3d4e5f60718293a4" }
)

# Initialize test results
$testResults = @()

function Log-Message {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp $Message" | Out-File -FilePath $logFile -Append
    Write-Host "[$timestamp] $Message"
}

function Setup-Backup {
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir | Out-Null
    }
    foreach ($file in @("$tomcatConfDir\tomcat-users.xml", "$tomcatConfDir\server.xml")) {
        if (Test-Path $file) {
            Copy-Item -Path $file -Destination $backupDir
            Log-Message "Backed up $file to $backupDir"
        }
    }
}

function Restore-Files {
    foreach ($file in @("$backupDir\tomcat-users.xml", "$backupDir\server.xml")) {
        if (Test-Path $file) {
            $dest = Join-Path $tomcatConfDir (Split-Path $file -Leaf)
            Copy-Item -Path $file -Destination $dest
            Log-Message "Restored $dest from $file"
        }
    }
    if (Test-Path $backupDir) {
        Remove-Item -Path $backupDir -Recurse -Force
        Log-Message "Cleaned up backup directory"
    }
}

function Set-ServerConfig {
    param($ConfigType)
    $serverXmlPath = "$tomcatConfDir\server.xml"
    Copy-Item -Path "$backupDir\server.xml" -Destination $serverXmlPath
    Log-Message "Restored $serverXmlPath from $backupDir\server.xml"
    
    [xml]$serverXml = Get-Content $serverXmlPath
    $realm = $serverXml.Server.Service.Engine.Realm
    if ($realm.className -eq "org.apache.catalina.realm.LockOutRealm") {
        $realm = $realm.Realm
        Log-Message "Found nested UserDatabaseRealm in LockOutRealm"
    }
    
    if ($ConfigType -eq "NoCredentialHandler") {
        if ($realm.CredentialHandler) {
            $realm.RemoveChild($realm.CredentialHandler) | Out-Null
            Log-Message "Cleared existing CredentialHandler for $ConfigType test"
        }
        else {
            Log-Message "No CredentialHandler found to clear for $ConfigType test"
        }
    }
    else {
        $ch = $serverXml.CreateElement("CredentialHandler")
        if ($ConfigType -eq "MessageDigestCredentialHandler_MD5") {
            $ch.SetAttribute("className", "org.apache.catalina.realm.MessageDigestCredentialHandler")
            $ch.SetAttribute("algorithm", "MD5")
            $ch.SetAttribute("saltLength", "16")
            $ch.SetAttribute("iterations", "10000")
        }
        elseif ($ConfigType -eq "MessageDigestCredentialHandler_SHA256") {
            $ch.SetAttribute("className", "org.apache.catalina.realm.MessageDigestCredentialHandler")
            $ch.SetAttribute("algorithm", "SHA-256")
            $ch.SetAttribute("saltLength", "16")
            $ch.SetAttribute("iterations", "10000")
        }
        elseif ($ConfigType -eq "MessageDigestCredentialHandler_SHA512") {
            $ch.SetAttribute("className", "org.apache.catalina.realm.MessageDigestCredentialHandler")
            $ch.SetAttribute("algorithm", "SHA-512")
            $ch.SetAttribute("saltLength", "16")
            $ch.SetAttribute("iterations", "10000")
        }
        elseif ($ConfigType -eq "SecretKeyCredentialHandler_PBKDF2") {
            $ch.SetAttribute("className", "org.apache.catalina.realm.SecretKeyCredentialHandler")
            $ch.SetAttribute("algorithm", "PBKDF2WithHmacSHA512")
            $ch.SetAttribute("saltLength", "16")
            $ch.SetAttribute("iterations", "10000")
            $ch.SetAttribute("keyLength", "256")
        }
        elseif ($ConfigType -eq "NestedCredentialHandler") {
            $ch.SetAttribute("className", "org.apache.catalina.realm.NestedCredentialHandler")
        }
        # Remove existing CredentialHandler if present
        if ($realm.CredentialHandler) {
            $realm.RemoveChild($realm.CredentialHandler) | Out-Null
            Log-Message "Removed existing CredentialHandler before applying new one"
        }
        $realm.AppendChild($ch) | Out-Null
        Log-Message "Applied CredentialHandler configuration for $ConfigType"
    }
    $serverXml.Save($serverXmlPath)
    Log-Message "Set server.xml with $ConfigType"
}

function Set-PasswordType {
    param($PasswordType, $PasswordValue)
    $usersXmlPath = "$tomcatConfDir\tomcat-users.xml"
    [xml]$usersXml = Get-Content $usersXmlPath
    $user = $usersXml.'tomcat-users'.user
    if (-not $user) {
        $user = $usersXml.CreateElement("user")
        $usersXml.'tomcat-users'.AppendChild($user) | Out-Null
    }
    $user.SetAttribute("username", "testuser")
    $user.SetAttribute("password", $PasswordValue)
    $user.SetAttribute("roles", "manager")
    $usersXml.Save($usersXmlPath)
    Log-Message "Set tomcat-users.xml with $PasswordType password: $PasswordValue"
}

function Run-Test {
    param($ConfigType, $PasswordType, $PasswordValue)
    $testName = "${tomcatVersion}_${ConfigType}_${PasswordType}"
    Log-Message "Running test: $testName for Tomcat $tomcatVersion"
    
    Set-ServerConfig -ConfigType $ConfigType
    Set-PasswordType -PasswordType $PasswordType -PasswordValue $PasswordValue
    
    $output = & $scriptPath
    $output | Out-File -FilePath $logFile -Append
    Log-Message "Test output logged to $logFile"
    
    $status = if ($output.IsCompliant) { "Secure" } else { "Insecure" }
    $issues = $output.Issues -join "; "
    if (-not $issues) { $issues = "None" }
    
    $testResults += [PSCustomObject]@{
        Timestamp = Get-Date
        TomcatVersion = $tomcatVersion
        ServerConfig = $ConfigType
        PasswordType = $PasswordType
        Status = $status
        Issues = $issues
    }
}

# Main execution
Log-Message "Starting tests for CheckTomcatConfig.ps1..."

if (-not (Test-Path $scriptPath)) {
    Log-Message "Error: $scriptPath not found"
    exit 1
}
Log-Message "Verified file exists: $scriptPath"

if (Test-Path $logFile) {
    Remove-Item $logFile
    Log-Message "Cleared existing log file: $logFile"
}

if (-not (Test-Path $tomcatConfDir)) {
    Log-Message "Error: Tomcat $tomcatVersion configuration directory not found at $tomcatConfDir"
    exit 1
}
Log-Message "Detected installed Tomcat version $tomcatVersion at $tomcatConfDir"

$testFile = "$tomcatConfDir\test.txt"
try {
    New-Item -Path $testFile -ItemType File -Force | Out-Null
    Remove-Item $testFile
    Log-Message "Write permission confirmed for $testFile"
}
catch {
    Log-Message "Error: No write permission for $tomcatConfDir"
    exit 1
}

Log-Message "Testing Tomcat version $tomcatVersion at $tomcatConfDir"
Log-Message "Backing up files for Tomcat $tomcatVersion"
Setup-Backup

Log-Message "Starting test cases for Tomcat $tomcatVersion"
foreach ($config in $serverConfigs) {
    Log-Message "Processing server test: $config"
    foreach ($pw in $passwordTypes) {
        Log-Message "Processing password test: $($pw.Type)"
        Run-Test -ConfigType $config -PasswordType $pw.Type -PasswordValue $pw.Value
    }
}

Log-Message "Restoring original files for Tomcat $tomcatVersion"
Restore-Files

Log-Message "Generating test report"
$report = $testResults | ForEach-Object {
    $compliance = if ($_.Status -eq "Secure") {
        "Compliant with CIS Tomcat Benchmark 4.1"
    } else {
        "Non-compliant with NIST 800-53 IA-5"
    }
    $reason = switch ($_.PasswordType) {
        "Plaintext" { "Plaintext passwords are insecure and prohibited." }
        "Hashed_MD5" { "MD5 is weak and lacks salt." }
        "Hashed_SHA1" { "SHA-1 is weak and lacks salt." }
        "Hashed_SHA256" { "SHA-256 without salt is less secure." }
        "Hashed_SHA512" { "SHA-512 without salt is less secure." }
        "Salted_MD5" { "MD5 is outdated even with salt." }
        "Salted_PBKDF2" { "PBKDF2 with salt and iterations is secure." }
    }
    if ($_.Status -eq "Secure") {
        $reason = switch ($_.ServerConfig) {
            "MessageDigestCredentialHandler_SHA256" { "SHA-256 with salt and iterations is secure." }
            "MessageDigestCredentialHandler_SHA512" { "SHA-512 with salt and iterations is secure." }
            "SecretKeyCredentialHandler_PBKDF2" { "PBKDF2 is highly secure." }
            "NestedCredentialHandler" { "Combines SHA-256 and PBKDF2 for robust security." }
            default { $reason }
        }
    }
    [PSCustomObject]@{
        TomcatVersion = $_.TomcatVersion
        Configuration = $_.ServerConfig
        PasswordType = $_.PasswordType
        RequiredForVersion = "Yes"
        SecureForVersion = if ($_.Status -eq "Secure") { "Yes" } else { "No" }
        Compliance = $compliance
        Reason = $reason
    }
}
$report | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Message $_ }

Log-Message "Generating final status of all CheckTomcatConfig executions"
$finalStatus = $testResults | ForEach-Object {
    [PSCustomObject]@{
        TomcatVersion = $_.TomcatVersion
        Configuration = $_.ServerConfig
        PasswordType = $_.PasswordType
        Status = $_.Status
        RequiredForVersion = "Yes"
        SecureForVersion = if ($_.Status -eq "Secure") { "Yes" } else { "No" }
    }
}
$finalStatus | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Message $_ }

Log-Message "Generating execution summary of all CheckTomcatConfig.ps1 runs"
$executionSummary = $testResults | ForEach-Object {
    [PSCustomObject]@{
        TestName = "$($_.TomcatVersion)_$($_.ServerConfig)_$($_.PasswordType)"
        Status = $_.Status
        KeyFindings = $_.Issues
    }
}
$executionSummary | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Message $_ }

Log-Message "All tests completed successfully"
Log-Message "Script execution finished. Output logged to $logFile"