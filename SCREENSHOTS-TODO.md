# Screenshot checklist (delete this file once done)

Save each screenshot under exactly this name, in the folder shown. The write-ups already link to these names, so an image with any other name won't show.

Before saving each one, check:
- It's cropped to the VM or browser window, with no desktop icons or personal files visible.
- No passwords, no Nessus activation code, and your email address is blurred.

| Folder | File name | What it shows |
| --- | --- | --- |
| 01-lab-build/screenshots | `01-ad-users.png` | Active Directory Users and Computers, Lab-Users OU |
| 01-lab-build/screenshots | `04-client-whoami.png` | CLIENT01 command prompt: `whoami` returns `lab\j.smith` |
| 02-vulnerability-management/screenshots | `07-uncredentialed-hosts.png` | Uncredentialed scan, Hosts tab (both hosts, Info only) |
| 02-vulnerability-management/screenshots | `07-credentialed-before.png` | Credentialed scan before patching (24 critical, 47 high) |
| 02-vulnerability-management/screenshots | `08-remediations.png` | Remediations tab (5 actions) |
| 02-vulnerability-management/screenshots | `09-update-history.png` | DC01 Windows Update history |
| 02-vulnerability-management/screenshots | `09-winver-after.png` | `winver` showing build 20348.5761 |
| 02-vulnerability-management/screenshots | `10-credentialed-after.png` | DC01 re-scan: 1 high, rest info |
| 02-vulnerability-management/screenshots | `11-credentialed-final.png` | Final scan after the registry fix: Info only |
| 03-malware-detection-eicar/screenshots | `12-protection-history.png` | Windows Security, Protection history entry |
| 03-malware-detection-eicar/screenshots | `12-event-1116.png` | Event Viewer, Event 1116 |
| 03-malware-detection-eicar/screenshots | `12-event-1117.png` | Event Viewer, Event 1117 |
| 04-email-header-analysis/screenshots | `13-header-summary.png` | Gmail "Show original" summary (SPF/DKIM/DMARC). Blur the To: address |
| 05-brute-force-lockout/screenshots | `14-lockout-policy.png` | `Get-ADDefaultDomainPasswordPolicy` output |
| 05-brute-force-lockout/screenshots | `15-account-locked.png` | `Get-ADUser j.smith` showing LockedOut True |
| 05-brute-force-lockout/screenshots | `16-event-4740.png` | Event Viewer on DC01, Event 4740 |
| 05-brute-force-lockout/screenshots | `17-client-4625-table.png` | The 4625 PowerShell table on CLIENT01 |
| 05-brute-force-lockout/screenshots | `18-dc-4771-table.png` | The 4771 PowerShell table on DC01 |
