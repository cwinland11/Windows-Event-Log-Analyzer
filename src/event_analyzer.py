
# Windows Event Log Analyzer
# Identifies Windows events relevant to forensic investigations.

IMPORTANT_EVENTS = {
    4624: ("Successful Login", "Authentication"),
    4625: ("Failed Login", "Authentication"),
    4634: ("Account Logoff", "Authentication"),
    4720: ("User Account Created", "Account Management"),
    4726: ("User Account Deleted", "Account Management"),
    4732: ("Member Added to Local Group", "Account Management"),
    4740: ("Account Locked Out", "Account Management"),
    1102: ("Security Audit Log Cleared", "Audit Activity"),
    6005: ("Event Log Service Started", "System Activity"),
    6006: ("Event Log Service Stopped", "System Activity"),
    7045: ("New Service Installed", "System Activity")
}


def analyze_events(events):
    findings = []

    for event in events:
        event_id = event.get("event_id")

        if event_id not in IMPORTANT_EVENTS:
            continue

        description, category = IMPORTANT_EVENTS[event_id]
        details = event.get("details", {})

        username = (
            details.get("TargetUserName")
            or details.get("SubjectUserName")
            or details.get("AccountName")
            or "N/A"
        )

        findings.append({
            "event_id": event_id,
            "description": description,
            "category": category,
            "timestamp": event.get("timestamp", ""),
            "computer": event.get("computer", ""),
            "username": username,
            "provider": event.get("provider", ""),
            "details": details
        })

    return findings

def filter_events(findings, event_id=None, username=None,
                  start_date=None, end_date=None, keyword=None):
    filtered = []

    for event in findings:
        if event_id is not None and event["event_id"] != event_id:
            continue

        if username and username.lower() not in event["username"].lower():
            continue

        timestamp = event.get("timestamp", "")
        event_date = timestamp[:10]

        if start_date and event_date < start_date:
            continue

        if end_date and event_date > end_date:
            continue

        if keyword:
            searchable = " ".join([
                event.get("description", ""),
                event.get("category", ""),
                event.get("computer", ""),
                event.get("provider", ""),
                str(event.get("details", {}))
            ]).lower()

            if keyword.lower() not in searchable:
                continue

        filtered.append(event)

    return filtered
