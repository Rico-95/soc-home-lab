# Screenshot guide (delete this file once every image is uploaded)

The write-ups already link to these exact file names, so a screenshot saved under any other name won't appear.

## Rules for every screenshot
- **Capture one window, not the whole screen.** Press `Win + Shift + S` and choose **Window mode**, or capture a rectangle around the content. Leave out the taskbar, the desktop and other apps.
- **Browser screenshots (Nessus, GitHub, Gmail):** crop below the address bar, so no tabs, bookmarks or extensions show.
- **Never show:** passwords, the Nessus activation code, your personal email address, desktop files or icons, or other browser tabs.
- **Make the key detail obvious.** Draw a red box around the one or two things the image proves, such as `0xC000006A` or `Caller Computer Name: CLIENT01`. The Snipping Tool editor can do this.
- **Keep it readable.** Maximise the window first, and make sure the text is legible at normal size. Zoom in (Ctrl +) on dense pages.
- **Save as PNG**, using the exact file name below.
- **After uploading,** open the lab's README on GitHub and check that every image shows.

## Nessus tip: earlier results are still there
You re-ran the credentialed scan, but every earlier run is kept. Open the scan → **History** tab → click a run to view it exactly as it was:
- **5 Nov, ~11:24** = before patching (24 critical, 47 high)
- **5 Nov, ~18:27** = after patching (1 high)
- **12 Nov, ~20:02** = final (informational only)

## Shot list

| Folder | File name | What must be visible | Hide or blur |
| --- | --- | --- | --- |
| 01-lab-build/screenshots | `01-ad-users.png` | Active Directory Users and Computers: `lab.local` expanded, **Lab-Users** selected, showing HR, HR User, IT, IT Admin, John Smith | — |
| 01-lab-build/screenshots | `04-client-whoami.png` | Terminal on CLIENT01: `whoami` → `lab\j.smith` (add `hostname` → CLIENT01 if you can) | — |
| 02-vulnerability-management/screenshots | `07-uncredentialed-hosts.png` | Uncredentialed scan, **Hosts** tab: both IPs, Auth column, blue (info-only) bars, Scan Details panel | Feed-error banner if showing |
| 02-vulnerability-management/screenshots | `07-credentialed-before.png` | Credentialed scan, **5 Nov 11:24 run** (from History): DC01 **Auth: Pass** with the red 24 / 47 bar | — |
| 02-vulnerability-management/screenshots | `08-remediations.png` | Same run, **Remediations** tab: the five actions with their vulnerability counts | — |
| 02-vulnerability-management/screenshots | `09-update-history.png` | DC01 → Settings → Windows Update → **View update history**: KB5122882 and KB5128928 "Successfully installed" | — |
| 02-vulnerability-management/screenshots | `09-winver-after.png` | `winver` dialog: **OS Build 20348.5761** | — |
| 02-vulnerability-management/screenshots | `10-credentialed-after.png` | **5 Nov 18:27 run**, DC01 vulnerabilities: the single **HIGH** WinVerifyTrust row at the top | — |
| 02-vulnerability-management/screenshots | `11-credentialed-final.png` | **12 Nov run**, DC01 vulnerabilities: every row INFO, Auth: Pass, all-blue donut | Feed-error banner |
| 03-malware-detection-eicar/screenshots | `12-protection-history.png` | Windows Security → Protection history, entry **expanded**: Severe, Virus, the file path | — |
| 03-malware-detection-eicar/screenshots | `12-event-1116.png` | Event Viewer, Defender Operational log, **1116** selected: `Virus:DOS/EICAR_Test_File`, logged time, CLIENT01.lab.local | — |
| 03-malware-detection-eicar/screenshots | `12-event-1117.png` | Same log, **1117** selected: "applied the remediation action", logged time | — |
| 04-email-header-analysis/screenshots | `13-header-summary.png` | Gmail **Show original** summary table: From, Subject, SPF, DKIM, DMARC | **To:** address (your Gmail) |
| 05-brute-force-lockout/screenshots | `14-lockout-policy.png` | PowerShell: `Get-ADDefaultDomainPasswordPolicy` → threshold 5, duration and window 15 minutes | — |
| 05-brute-force-lockout/screenshots | `15-account-locked.png` | PowerShell: `Get-ADUser j.smith` → **LockedOut True**, BadLogonCount | — |
| 05-brute-force-lockout/screenshots | `16-event-4740.png` | DC01 Event Viewer, Security log filtered to **4740**: Account Name j.smith, **Caller Computer Name CLIENT01** | — |
| 05-brute-force-lockout/screenshots | `17-client-4625-table.png` | The PowerShell **4625 table** on CLIENT01 (five rows, `0xc000006a`) | — |
| 05-brute-force-lockout/screenshots | `18-dc-4771-table.png` | The PowerShell **4771 table** on DC01 (`0x18` rows, the final `0x12`, ClientIP `::ffff:10.0.2.4`) | — |
| 06-phishing-analysis/screenshots | `19-phishing-headers.png` | The sample's raw text on GitHub: **From, Reply-To, Return-Path, Authentication-Results** | — |
| 06-phishing-analysis/screenshots | `20-phishing-mailto.png` | The raw text around **mailto:** — the "Report The User" link to the Gmail address | — |

## If a screenshot can't be recreated
- **`15-account-locked.png`:** the account is unlocked now. Either lock it again (five wrong passwords as `lab\j.smith`, screenshot, then `Unlock-ADAccount j.smith`), or delete that image line from lab 05's README.
- **The 4625 and 4771 tables:** re-run the commands, widening the window to cover 12 Nov if needed. For example, replace `(Get-Date).AddHours(-3)` with `(Get-Date).AddDays(-2)`.
