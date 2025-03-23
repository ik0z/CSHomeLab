In this part we touched on the topic of WAZUH LOGS + AV 


blog : 
https://wazuh.com/blog/using-wazuh-to-monitor-sysmon-events/


https://www.kaspersky.com/small-to-medium-business-security/downloads

#### Please always follow best practices and settings 


scripts to check the recording of events: 

Enable events logging 
```
# Run this as Administrator

$subcategories = @(
    # Logon/Logoff
    "Logon",
    "Logoff",
    "Special Logon",
    "Other Logon/Logoff Events",
    "Network Policy Server",
    "User / Device Claims",
    "Group Membership",

    # Account Logon
    "Credential Validation",
    "Kerberos Authentication Service",
    "Kerberos Service Ticket Operations",
    "Other Account Logon Events",

    # Object Access
    "File System",
    "Registry",
    "Kernel Object",
    "SAM",
    "Certification Services",
    "Application Generated",
    "Handle Manipulation",
    "Other Object Access Events",
    "Detailed File Share",
    "Removable Storage",
    "Central Policy Staging",

    # Process Tracking
    "Process Creation",
    "Process Termination",
    "DPAPI Activity",
    "RPC Events",
    "Plug and Play Events",
    "Token Right Adjusted Events",

    # Privilege Use
    "Sensitive Privilege Use",
    "Non Sensitive Privilege Use",
    "Other Privilege Use Events",

    # Policy Change
    "Audit Policy Change",
    "Authentication Policy Change",
    "Authorization Policy Change",
    "MPSSVC Rule-Level Policy Change",
    "Filtering Platform Policy Change",
    "Other Policy Change Events",

    # System Events
    "Security State Change",
    "Security System Extension",
    "System Integrity",
    "IPsec Driver",
    "Other System Events",

    # Account Management
    "User Account Management",
    "Computer Account Management",
    "Security Group Management",
    "Distribution Group Management",
    "Application Group Management",
    "Other Account Management Events",

    # Logon/Logoff Extended
    "Logoff",
    "Logon",
    "Account Lockout",

    # DS Access (for AD environments)
    "Directory Service Access",
    "Directory Service Changes",
    "Directory Service Replication",
    "Detailed Directory Service Replication"
)

foreach ($subcategory in $subcategories) {
    Write-Host "Enabling auditing for: $subcategory"
    auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable | Out-Null
}

Write-Host "`n All sensitive audit policies have been enabled." -ForegroundColor Green


```



Test events 
```
# ===============================
# PowerShell Script: Generate Security Events for SIEM/Wazuh testing
# Author: ENG. Khaled
# ===============================

Write-Host "Generating fake security events for testing..." -ForegroundColor Cyan

# 1. Simulate a process creation (4688)
Start-Process -FilePath "notepad.exe"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo Test"

# 2. Simulate file access (4663)
$testFile = "$env:ProgramData\test-log.txt"
"Test Log Access" | Out-File $testFile
Get-Content $testFile | Out-Null

# 3. Simulate failed logon (4625) - Invalid credentials (This will show in event viewer under Security)
$domain = $env:USERDOMAIN
$wrongUser = "FakeUser"
$wrongPassword = ConvertTo-SecureString "WrongPassword123!" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("$domain\$wrongUser", $wrongPassword)

try {
    $null = New-PSSession -ComputerName localhost -Credential $creds -ErrorAction Stop
} catch {
    Write-Host "Simulated failed logon attempt (4625)" -ForegroundColor Yellow
}

# 4. Simulate registry access/change (4657)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "CleanShutdown" -Value 0

# 5. Simulate privilege use attempt (4672/4673/4674)
whoami /priv

# Done
Write-Host " Fake events generated. Check your SIEM/Wazuh logs." -ForegroundColor Green

```


test event 2 
```
# =====================[ EVENT GENERATOR SCRIPT ]=====================
Write-Host "Starting test event generation..." -ForegroundColor Cyan

# 1. Create a new local user
$user = "testuser"
$pass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
New-LocalUser -Name $user -Password $pass -FullName "Test User" -Description "For SIEM test" -ErrorAction SilentlyContinue
Write-Host "[+] User $user created."

# 2. Add user to Administrators (Group Management)
Add-LocalGroupMember -Group "Administrators" -Member $user -ErrorAction SilentlyContinue
Write-Host "[+] Added $user to Administrators group."

# 3. Simulate logon/logoff (Logon Event)
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "Write-Host 'Simulated session'" -WindowStyle Hidden
Write-Host "[+] Simulated user session via PowerShell."

# 4. Create new service (Event ID 7045)
sc.exe create TempTestService binPath= "cmd.exe /c timeout 10"
Write-Host "[+] Dummy service created."

# 5. File access and delete (Event 4663 / 4660)
$tempFile = "$env:ProgramData\testfile.txt"
Set-Content -Path $tempFile -Value "This is a test file for Wazuh."
Remove-Item -Path $tempFile -Force
Write-Host "[+] File created and deleted: $tempFile"

# 6. Start a suspicious process (Event 4688)
Start-Process -FilePath "notepad.exe"
Start-Sleep -Seconds 2
Get-Process notepad | Stop-Process
Write-Host "[+] notepad.exe started and killed."

# =====================[ CLEANUP AFTER 5 MINS ]=====================
Write-Host "[*] Sleeping for 5 minutes before cleanup..." -ForegroundColor Yellow
Start-Sleep -Seconds 300

# Cleanup: remove user, group membership, service, etc.
Write-Host "[*] Starting cleanup..." -ForegroundColor Magenta

# Delete user
Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
Write-Host "[+] Deleted user $user"

# Delete service
sc.exe delete TempTestService > $null
Write-Host "[+] Deleted dummy service."

Write-Host "All cleanup completed. Done!" -ForegroundColor Green


```
