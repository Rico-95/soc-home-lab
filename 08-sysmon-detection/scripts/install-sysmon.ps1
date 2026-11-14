# install-sysmon.ps1
# Installs Microsoft Sysinternals Sysmon with the SwiftOnSecurity baseline configuration.
# Run in an elevated PowerShell session on the Windows endpoint.

mkdir C:\Tools\Sysmon -Force | Out-Null
Set-Location C:\Tools\Sysmon

Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath . -Force
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml

.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml

# Verify the service is running
Get-Service Sysmon64
