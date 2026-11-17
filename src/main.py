from report_generator import generate_report
from collections import Counter
from cache_manager import load_events
from event_analyzer import analyze_events, filter_events


def main():
    print("=" * 55)
    print("WINDOWS EVENT LOG ANALYZER")
    print("=" * 55)

    log_files = [
        "samples/security.evtx",
        "samples/system.evtx"
    ]

    all_events = []

    for file_path in log_files:
        print(f"\nReading: {file_path}")

        try:
            events = load_events(file_path)
            all_events.extend(events)
            print(f"Successfully parsed {len(events)} events.")

        except Exception as error:
            print(f"Error reading {file_path}: {error}")

    print("\nAnalyzing security and system events...")

    findings = analyze_events(all_events)

    print("\n" + "=" * 55)
    print("FORENSIC ANALYSIS SUMMARY")
    print("=" * 55)

    print(f"Total events analyzed: {len(all_events)}")
    print(f"Relevant events identified: {len(findings)}")

    category_counts = Counter(
        finding["category"] for finding in findings
    )

    print("\nEvents by Category:")
    for category, count in category_counts.items():
        print(f"  {category}: {count}")

    event_counts = Counter(
        finding["event_id"] for finding in findings
    )

    print("\nEvents by Event ID:")
    for event_id, count in sorted(event_counts.items()):
        print(f"  Event ID {event_id}: {count}")

    print("\nMost Recent Relevant Events:")

    recent_findings = sorted(
        findings,
        key=lambda event: event["timestamp"],
        reverse=True
    )

    for event in recent_findings[:10]:
        print("-" * 55)
        print(f"Event ID: {event['event_id']}")
        print(f"Description: {event['description']}")
        print(f"Timestamp: {event['timestamp']}")
        print(f"Username: {event['username']}")
        print(f"Computer: {event['computer']}")

    print("\n" + "=" * 55)
    print("FILTER TEST: FAILED LOGIN ATTEMPTS")
    print("=" * 55)

    failed_logins = filter_events(findings, event_id=4625)

    print(f"Failed login events found: {len(failed_logins)}")

    for event in failed_logins:
        print("-" * 55)
        print(f"Timestamp: {event['timestamp']}")
        print(f"Username: {event['username']}")
        print(f"Computer: {event['computer']}")
        print(f"Details: {event['details']}")
    report_path = generate_report(all_events, findings)
    print(f"\nHTML forensic report generated: {report_path}")
    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()
