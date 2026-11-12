# create-lab-users.ps1
# Builds the lab.local OU structure, users and groups on DC01.
# Run in an elevated PowerShell session on the domain controller.
# The password is prompted for and never stored in this script.

New-ADOrganizationalUnit -Name "Lab-Users" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Lab-Computers" -Path "DC=lab,DC=local"

$pw = Read-Host -AsSecureString "Password for lab users"

New-ADUser -Name "John Smith" -SamAccountName j.smith -UserPrincipalName j.smith@lab.local -Path "OU=Lab-Users,DC=lab,DC=local" -AccountPassword $pw -Enabled $true
New-ADUser -Name "HR User" -SamAccountName hr.user -UserPrincipalName hr.user@lab.local -Path "OU=Lab-Users,DC=lab,DC=local" -AccountPassword $pw -Enabled $true
New-ADUser -Name "IT Admin" -SamAccountName it.admin -UserPrincipalName it.admin@lab.local -Path "OU=Lab-Users,DC=lab,DC=local" -AccountPassword $pw -Enabled $true

New-ADGroup -Name "HR" -GroupScope Global -GroupCategory Security -Path "OU=Lab-Users,DC=lab,DC=local"
New-ADGroup -Name "IT" -GroupScope Global -GroupCategory Security -Path "OU=Lab-Users,DC=lab,DC=local"

# Least privilege: only it.admin gets administrative rights
Add-ADGroupMember -Identity "HR" -Members hr.user
Add-ADGroupMember -Identity "IT" -Members it.admin
Add-ADGroupMember -Identity "Domain Admins" -Members it.admin

# Verify
Get-ADUser -Filter * -SearchBase "OU=Lab-Users,DC=lab,DC=local" | Select-Object Name, SamAccountName, Enabled
