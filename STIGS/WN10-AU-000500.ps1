 <#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : John Lunnon
    LinkedIn        : linkedin.com/in/johnlunnon/
    GitHub          : https://github.com/JohnLunnon-cyber
    Date Created    : 2025-01-03
    Last Modified   : 2025-01-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# YOUR CODE GOES HERE






# Ensure the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    exit
}

# Define the registry path
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Define the registry value name and data
$registryValueName = "MaxSize"
$registryValueData = 0x8000  # 32,768 in decimal

# Check if the registry path exists, create it if necessary
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry value as a DWORD
Set-ItemProperty -Path $registryPath -Name $registryValueName -Value $registryValueData -Type DWord

# Confirm the change
Write-Output "Registry key updated: $registryPath\$registryValueName = $registryValueData"
 
