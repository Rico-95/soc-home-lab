"""
wazuh_alert_to_jira.py
Turn a Wazuh alert (JSON) into a Jira Service Management incident ticket.

- Maps the Wazuh rule level to a ticket priority.
- Pulls the fields an analyst needs first: host, user, rule, MITRE technique, command line.
- Dry run by default: prints the ticket it WOULD create. Add --send to create it.

Credentials come from environment variables, never from this file:
  JIRA_URL        e.g. https://your-site.atlassian.net
  JIRA_EMAIL      the email address of your Atlassian account
  JIRA_API_TOKEN  create at https://id.atlassian.com/manage-profile/security/api-tokens
  JIRA_PROJECT    project key, e.g. SOC
  JIRA_ISSUETYPE  issue type name in that project, e.g. "[System] Incident"

Usage:
  python wazuh_alert_to_jira.py alert.json            # dry run
  python wazuh_alert_to_jira.py alert.json --send     # create the ticket
"""
import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request


def priority_for(level: int) -> str:
    """Wazuh levels run 0-15. Map them onto Jira's default priority names."""
    if level >= 12:
        return "High"      # high-confidence detection: respond fast
    if level >= 7:
        return "Medium"
    return "Low"


def clean(value: str) -> str:
    """Wazuh stores Windows paths with doubled backslashes and escaped quotes; undo that for display."""
    return str(value).replace("\\\\", "\\").replace('\\"', '"')


def event_fields(alert: dict) -> dict:
    """Read process details from a raw Wazuh alert (data.win.eventdata) or a trimmed copy (sysmon)."""
    ev = alert.get("data", {}).get("win", {}).get("eventdata") or alert.get("sysmon") or {}
    system = alert.get("data", {}).get("win", {}).get("system", {})
    return {
        "user": clean(ev.get("user", "unknown")),
        "computer": system.get("computer") or ev.get("computer") or alert.get("agent", {}).get("name", "unknown"),
        "command_line": clean(ev.get("commandLine", "n/a")),
        "parent": clean(ev.get("parentImage", "n/a")),
        "logon_id": ev.get("logonId", "n/a"),
    }


def build_ticket(alert: dict, project: str, issuetype: str) -> dict:
    rule = alert["rule"]
    level = int(rule["level"])
    mitre = ", ".join(rule.get("mitre", {}).get("id", [])) or "none"
    ev = event_fields(alert)
    summary = f"[Wazuh L{level}] {rule['description']} on {alert.get('agent', {}).get('name', '?')}"
    description = "\n".join([
        f"Alert time: {alert.get('timestamp', 'n/a')}",
        f"Rule: {rule['id']} (level {level})",
        f"MITRE ATT&CK: {mitre}",
        "",
        # {noformat} stops Jira treating backslashes in paths as formatting (\\ = line break in Jira markup).
        "{noformat}",
        f"Host:           {ev['computer']}",
        f"User:           {ev['user']}",
        f"Logon ID:       {ev['logon_id']}",
        f"Parent process: {ev['parent']}",
        f"Command line:   {ev['command_line']}",
        "{noformat}",
        "",
        "Triage checklist:",
        "1. Is the user and host expected to do this?",
        "2. Decode or inspect the command; what did it do?",
        "3. Search for other alerts from the same logon ID.",
        "4. Contain (isolate host / disable account) if malicious; record actions here.",
    ])
    return {"fields": {
        "project": {"key": project},
        "issuetype": {"name": issuetype},
        "summary": summary[:250],
        "description": description,
        "priority": {"name": priority_for(level)},
        "labels": ["wazuh", f"rule-{rule['id']}"],
    }}


def send(ticket: dict) -> None:
    url = os.environ["JIRA_URL"].rstrip("/") + "/rest/api/2/issue"
    token = base64.b64encode(f"{os.environ['JIRA_EMAIL']}:{os.environ['JIRA_API_TOKEN']}".encode()).decode()
    req = urllib.request.Request(url, data=json.dumps(ticket).encode(), method="POST", headers={
        "Authorization": f"Basic {token}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            print("Created:", json.loads(resp.read())["key"])
    except urllib.error.HTTPError as e:
        # Jira explains what it rejected in the response body; show that instead of a traceback.
        print(f"Jira refused the ticket (HTTP {e.code}):", file=sys.stderr)
        print(e.read().decode(errors="replace"), file=sys.stderr)
        sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("alert", help="path to a Wazuh alert JSON file")
    ap.add_argument("--send", action="store_true", help="create the ticket (default is a dry run)")
    args = ap.parse_args()

    with open(args.alert, encoding="utf-8-sig") as f:
        alert = json.load(f)
    # The Wazuh dashboard's JSON tab wraps the alert in "_source"; unwrap it.
    alert = alert.get("_source", alert)
    ticket = build_ticket(alert, os.environ.get("JIRA_PROJECT", "SOC"),
                          os.environ.get("JIRA_ISSUETYPE", "[System] Incident"))
    if not args.send:
        print(json.dumps(ticket, indent=2))
        print("\nDry run only. Re-run with --send to create the ticket.", file=sys.stderr)
        return
    send(ticket)


if __name__ == "__main__":
    main()
