# 10 · Microsoft 365, Entra ID and MFA with Conditional Access

**Goal:** run the identity side of a Microsoft 365 organisation the way a deskside or service desk engineer does (create accounts, assign licences, reset passwords), then make sure every user is protected by multi-factor authentication (MFA) and prove it from the sign-in logs.

**Result:** a Microsoft 365 Business Premium tenant with separate admin and user accounts. I found that a new user could sign in **with a password alone**. I wrote a Conditional Access policy to require MFA, and **rolling it out in report-only mode first caught a configuration mistake that would have left it enforcing nothing.** After the fix, the sign-in logs show my policy enforcing MFA. Part 2 (Intune device management) is next.

## Setup
- **Microsoft 365 Business Premium** (30-day trial), tenant `RicosLab.onmicrosoft.com`. Business Premium includes **Entra ID P1**, which is what enables Conditional Access.
- **Admin and user accounts kept separate:**

| Account | Role | Licence | Why |
| --- | --- | --- | --- |
| `admin@` | Global Administrator | **None** | No mailbox or apps means less to attack; MFA set up from the first sign-in |
| `j.smith@` | User | Business Premium | Standard user (mirrors my on-premises lab domain) |
| `hr.user@` | User | Business Premium | Second user for licence and email tests |

- Users created in the admin centre (not the setup wizard), each with **"require password change at first sign-in"**.
- **Password reset:** reset j.smith's password as admin with a forced change, then confirmed the user could sign in with the new one.
- **Display bug spotted:** the organisation name `Rico's Lab` showed in the admin centre header as `Rico&#x27;s Lab`, with the apostrophe's HTML code visible. The text had been escaped twice. Escaping output is how web apps defend against cross-site scripting (XSS); here it was applied once too often. I renamed the organisation to avoid it.

## Finding: a new user could sign in without MFA
j.smith's first sign-in, after the forced password change:

| Sign-in log field | Value |
| --- | --- |
| Time | 17 Nov, 17:37 |
| Authentication requirement | **Single-factor authentication** |
| Status | Success |

Security defaults were enabled at the time, but they give new users a **grace period before MFA registration is enforced**, so a password alone was enough. For a deskside team, that is a window in which a stolen or guessed password gives full access.

## The fix: Conditional Access policy CA001, rolled out safely
**CA001 – Require MFA for all users:** Users = All users; Target resources = All resources; Grant = Require multifactor authentication.

I created it in **report-only** mode, which logs what the policy *would* do without enforcing it. Security defaults were turned off, since they can't run alongside Conditional Access.

**Report-only caught a mistake.** On j.smith's next sign-in, CA001 reported **"Not applied"**. The policy details showed why: the sign-in to *Microsoft Graph* was **"Not matched – Not included"**, because the policy's **target resources were set to None**. It covered all users but no resources, so it could never apply. Had I switched it straight to On, it would have looked active while enforcing nothing. I set target resources to **All resources** and the next sign-in reported **Report-only: Success**. Only then did I switch CA001 **On**.

## What was actually enforcing MFA in the meantime
With security defaults off and CA001 only in report-only, j.smith was still being asked for a code, so something else was enforcing MFA. The **Conditional Access** tab of the sign-in named it: a **Microsoft-managed policy**, *"Multifactor authentication for all users"*. Microsoft had created four managed policies in the tenant at **17:59**, two minutes after CA001, all switched On:
- Multifactor authentication for all users
- Multifactor authentication for admins
- Multifactor authentication for Azure Management
- **Block legacy authentication.** Older mail protocols such as POP and IMAP can't do MFA, so attackers use them to get around it.

I kept Microsoft's policies and switched mine on as well. Overlapping policies are fine, and Microsoft can change the policies it manages. A policy I own and have tested is a control I can explain and maintain.

## Reading the sign-in logs correctly
One sign-in creates several log entries, and not all of them prove MFA was used:

| Time | Log detail | What it actually means |
| --- | --- | --- |
| 17:37 | Single-factor authentication | The gap: password only |
| 18:03 | "MFA requirement skipped during registration" | The user was *setting up* MFA; no second factor was used yet |
| 18:09 | "MFA requirement satisfied by claim in the token" | Reused proof from the earlier session; no fresh check |
| 19:28 | Password ✓ + **OATH verification code** ✓, "MFA completed" | **A real MFA sign-in.** Status shows "Interrupted" only because of the "Stay signed in?" prompt |
| 21:47 | **CA001: Success** + Microsoft "MFA for all users": Success | **My policy enforcing MFA** |

To get a true test I closed every private browser window before signing in again, so no saved session could carry an earlier MFA result.

## Security notes
- **The MFA setup QR code is never published.** It contains the secret that generates the user's codes; anyone with a screenshot of it could generate valid codes for that account.
- **Break-glass account:** in production, one emergency admin account would be excluded from Conditional Access and monitored closely, so a misconfigured policy can't lock every administrator out. Not built in this lab; my admin account had MFA registered before any policy was enforced.
- **Trial hygiene:** the trial is set to be cancelled before it starts charging.

## What I learned
- **Report-only first, every time.** A policy can be On and still apply to nothing; report-only shows that before it matters.
- **Sign-in logs need careful reading.** "Multifactor authentication required" doesn't mean a code was entered: check the Authentication Details and the Conditional Access tabs.
- **Know what is enforcing your controls.** The tenant had protections I didn't create; the logs showed which policy actually did the work.

## Evidence
![Users and licences](screenshots/41-users-licences.png)
![Password reset](screenshots/42-password-reset.png)
![Single-factor sign-in](screenshots/43-single-factor-signin.png)
![MFA registration](screenshots/44-mfa-registration.png)
![CA001 not matched](screenshots/45a-ca001-not-matched.png)
![CA001 with no target resources](screenshots/45b-ca001-no-target-resources.png)
![MFA completed](screenshots/46a-mfa-completed.png)
![CA001 report-only success](screenshots/46b-ca001-report-only-success.png)
![Conditional Access policies](screenshots/47-ca-policies.png)
![CA001 enforced](screenshots/48-ca001-enforced.png)
