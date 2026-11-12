# parse-logon-failures.ps1
# Turns raw Windows Security events into readable tables for triage.
# Run in an elevated PowerShell session. Adjust -Hours to widen the window.

param([int]$Hours = 3)

function Get-EventFields($evt) {
    $d = @{}
    ([xml]$evt.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    return $d
}

$start = (Get-Date).AddHours(-$Hours)

# On a workstation: failed logons (4625)
# Status 0xC000006D + SubStatus 0xC000006A = wrong password
# SubStatus 0xC0000064 = user name does not exist
# SubStatus 0xC0000234 = account locked out
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$start} -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Get-EventFields $_
    [pscustomobject]@{ Time=$_.TimeCreated; User=$d.TargetUserName; Domain=$d.TargetDomainName; LogonType=$d.LogonType; Status=$d.Status; SubStatus=$d.SubStatus }
} | Format-Table -AutoSize

# On a domain controller: Kerberos pre-authentication failures (4771)
# Status 0x18 = wrong password, 0x12 = account disabled, expired or locked out
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4771; StartTime=$start} -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Get-EventFields $_
    [pscustomobject]@{ Time=$_.TimeCreated; User=$d.TargetUserName; Status=$d.Status; ClientIP=$d.IpAddress }
} | Format-Table -AutoSize

# On a domain controller: account lockouts (4740)
# In this event's raw data, the field named TargetDomainName holds the Caller Computer Name
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=$start} -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Get-EventFields $_
    [pscustomobject]@{ Time=$_.TimeCreated; LockedAccount=$d.TargetUserName; CallerComputer=$d.TargetDomainName }
} | Format-Table -AutoSize
