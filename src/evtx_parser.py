
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from pathlib import Path

NAMESPACE = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_evtx(file_path):
    events = []
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())

                system = root.find("e:System", NAMESPACE)
                if system is None:
                    continue

                event_id = system.find("e:EventID", NAMESPACE)
                timestamp = system.find("e:TimeCreated", NAMESPACE)
                computer = system.find("e:Computer", NAMESPACE)
                provider = system.find("e:Provider", NAMESPACE)

                details = {}
                event_data = root.find("e:EventData", NAMESPACE)

                if event_data is not None:
                    for index, data in enumerate(
                        event_data.findall("e:Data", NAMESPACE)
                    ):
                        name = data.get("Name") or f"Data_{index}"
                        details[name] = data.text or ""

                events.append({
                    "event_id": int(event_id.text) if event_id is not None else None,
                    "timestamp": timestamp.get("SystemTime", "") if timestamp is not None else "",
                    "computer": computer.text if computer is not None else "",
                    "provider": provider.get("Name", "") if provider is not None else "",
                    "details": details
                })

            except (ET.ParseError, ValueError, TypeError) as error:
                print(f"Warning: Skipped invalid record: {error}")

    return events
