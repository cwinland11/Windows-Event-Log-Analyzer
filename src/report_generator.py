
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import json
import html


def generate_report(events, findings, output_path="reports/forensic_report.html"):
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    event_counts = Counter(
        event["event_id"] for event in findings
    )

    groups = {}

    for event in findings:
        event_id = str(event["event_id"])

        if event_id not in groups:
            groups[event_id] = {
                "event_id": event["event_id"],
                "description": event["description"],
                "category": event["category"],
                "records": []
            }

        groups[event_id]["records"].append({
            "timestamp": event.get("timestamp", ""),
            "username": event.get("username", ""),
            "computer": event.get("computer", ""),
            "provider": event.get("provider", ""),
            "details": event.get("details", {})
        })

    for group in groups.values():
        group["records"].sort(
            key=lambda record: record["timestamp"],
            reverse=True
        )

    report_data = {
        "total_events": len(events),
        "relevant_events": len(findings),
        "successful_logins": event_counts.get(4624, 0),
        "failed_logins": event_counts.get(4625, 0),
        "generated_at": generated_at,
        "groups": sorted(
            groups.values(),
            key=lambda group: group["event_id"]
        )
    }

    # Escape characters that could prematurely close the script tag.
    data_json = json.dumps(report_data, ensure_ascii=True)
    data_json = data_json.replace("<", "\\u003c")
    data_json = data_json.replace(">", "\\u003e")
    data_json = data_json.replace("&", "\\u0026")

    template = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows Event Log Analyzer</title>
<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    background: #f3f5f9;
    color: #243044;
    font-family: Arial, sans-serif;
}

.container {
    max-width: 1250px;
    margin: auto;
    padding: 28px;
}

header {
    background: #172b4d;
    color: white;
    border-radius: 12px;
    padding: 30px;
}

header h1 { margin: 0 0 8px; }
header p { color: #d1deee; margin: 6px 0; }

.cards {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin: 22px 0;
}

.card, .panel {
    background: white;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0 2px 8px #0000000b;
}

.card .label {
    font-size: 13px;
    color: #65748a;
}

.card .number {
    font-size: 30px;
    font-weight: bold;
    color: #1769aa;
    margin-top: 10px;
}

h2 { margin-top: 0; }

.controls {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 18px;
}

input, select, button {
    padding: 11px;
    border: 1px solid #cbd5e1;
    border-radius: 7px;
    font: inherit;
}

input { flex: 1; min-width: 200px; }
select { min-width: 180px; }

button {
    cursor: pointer;
    background: #172b4d;
    color: white;
    border: none;
}

button:hover { background: #294a77; }
button:disabled { opacity: .45; cursor: default; }

.event-group {
    border: 1px solid #dce3ec;
    border-radius: 9px;
    margin-bottom: 10px;
    overflow: hidden;
}

.group-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 17px;
    background: #f8fafc;
    cursor: pointer;
}

.group-header:hover { background: #edf3fa; }

.group-title { font-weight: bold; }

.group-category {
    font-size: 12px;
    color: #64748b;
    margin-top: 5px;
}

.group-count {
    background: #e3ebf7;
    border-radius: 20px;
    padding: 7px 12px;
    font-weight: bold;
    white-space: nowrap;
}

.group-content {
    padding: 15px;
    border-top: 1px solid #e2e8f0;
}

.hidden { display: none; }

.table-wrap { overflow-x: auto; }

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 11px;
    text-align: left;
    border-bottom: 1px solid #e2e8f0;
    font-size: 13px;
    overflow-wrap: anywhere;
}

th { background: #edf2f8; }
tr:hover { background: #f8fafc; }

.pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
    margin-top: 15px;
}

.details {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 250px;
    overflow-y: auto;
    background: #f1f5f9;
    padding: 12px;
    border-radius: 6px;
    font-size: 12px;
}

.note {
    color: #64748b;
    font-size: 13px;
    line-height: 1.6;
}

@media (max-width: 750px) {
    .cards { grid-template-columns: repeat(2, 1fr); }
    .container { padding: 12px; }
}
</style>
</head>
<body>
<div class="container">

<header>
<h1>Windows Event Log Analyzer</h1>
<p>Interactive Digital Forensic Investigation Report</p>
<p id="generatedAt"></p>
</header>

<div class="cards">
<div class="card">
<div class="label">Total Events</div>
<div class="number" id="totalEvents"></div>
</div>
<div class="card">
<div class="label">Relevant Events</div>
<div class="number" id="relevantEvents"></div>
</div>
<div class="card">
<div class="label">Successful Logons</div>
<div class="number" id="successfulLogins"></div>
</div>
<div class="card">
<div class="label">Failed Logons</div>
<div class="number" id="failedLogins"></div>
</div>
</div>

<div class="panel">
<h2>Event Explorer</h2>
<p class="note">
Select an Event ID to inspect individual records.
Search by Event ID, description, username, or computer.
Only selected forensic event types are included.
</p>

<div class="controls">
<input id="searchInput" type="search"
       placeholder="Search events, usernames, computers...">

<select id="categoryFilter">
<option value="all">All Categories</option>
<option value="Authentication">Authentication</option>
<option value="Account Management">Account Management</option>
<option value="Audit Activity">Audit Activity</option>
<option value="System Activity">System Activity</option>
</select>
</div>

<p class="note" id="resultCount"></p>
<div id="eventGroups"></div>
</div>

<p class="note">
Forensic note: Identified events are not automatically evidence
of malicious activity. Review event context before drawing conclusions.
All timestamps are displayed as recorded in the source logs.
</p>

</div>

<script id="reportData" type="application/json">__REPORT_DATA__</script>
<script>
const report = JSON.parse(
    document.getElementById("reportData").textContent
);

const pageSize = 25;
const pages = {};
const expanded = new Set();

function formatNumber(value) {
    return Number(value).toLocaleString();
}

function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) {
        node.textContent = String(text);
    }
    if (className) node.className = className;
    return node;
}

function initializeSummary() {
    document.getElementById("totalEvents").textContent =
        formatNumber(report.total_events);
    document.getElementById("relevantEvents").textContent =
        formatNumber(report.relevant_events);
    document.getElementById("successfulLogins").textContent =
        formatNumber(report.successful_logins);
    document.getElementById("failedLogins").textContent =
        formatNumber(report.failed_logins);
    document.getElementById("generatedAt").textContent =
        "Generated: " + report.generated_at;
}

function matchesRecord(record, query) {
    const searchable = [
        record.timestamp,
        record.username,
        record.computer,
        record.provider,
        JSON.stringify(record.details)
    ].join(" ").toLowerCase();

    return searchable.includes(query);
}

function getMatchingRecords(group, query) {
    if (!query) return group.records;

    const groupText = [
        group.event_id,
        group.description,
        group.category
    ].join(" ").toLowerCase();

    if (groupText.includes(query)) return group.records;

    return group.records.filter(record =>
        matchesRecord(record, query)
    );
}

function renderTable(container, group, records) {
    const pageCount = Math.max(
        1, Math.ceil(records.length / pageSize)
    );

    const page = Math.min(
        Math.max(1, pages[group.event_id] || 1),
        pageCount
    );
    pages[group.event_id] = page;

    const start = (page - 1) * pageSize;
    const visible = records.slice(start, start + pageSize);

    const wrap = element("div", null, "table-wrap");
    const table = element("table");
    const thead = element("thead");
    const headerRow = element("tr");

    ["Timestamp", "Username", "Computer", "Details"].forEach(name => {
        headerRow.appendChild(element("th", name));
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = element("tbody");

    visible.forEach(record => {
        const row = element("tr");

        row.appendChild(element("td", record.timestamp));
        row.appendChild(element("td", record.username));
        row.appendChild(element("td", record.computer));

        const detailCell = element("td");
        const detailToggle = element("details");
        const summary = element("summary", "View details");
        const pre = element(
            "pre",
            JSON.stringify(record.details, null, 2),
            "details"
        );

        detailToggle.appendChild(summary);
        detailToggle.appendChild(pre);
        detailCell.appendChild(detailToggle);
        row.appendChild(detailCell);
        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    wrap.appendChild(table);
    container.appendChild(wrap);

    const navigation = element("div", null, "pagination");

    const previous = element("button", "Previous");
    previous.disabled = page <= 1;
    previous.addEventListener("click", () => {
        pages[group.event_id] = page - 1;
        renderGroups();
    });

    const next = element("button", "Next");
    next.disabled = page >= pageCount;
    next.addEventListener("click", () => {
        pages[group.event_id] = page + 1;
        renderGroups();
    });

    navigation.appendChild(previous);
    navigation.appendChild(
        element("span", `Page ${page} of ${pageCount}`)
    );
    navigation.appendChild(next);
    container.appendChild(navigation);
}

function renderGroups() {
    const query = document.getElementById(
        "searchInput"
    ).value.trim().toLowerCase();

    const category = document.getElementById(
        "categoryFilter"
    ).value;

    const container = document.getElementById("eventGroups");
    container.replaceChildren();

    let visibleGroups = 0;
    let visibleRecords = 0;

    report.groups.forEach(group => {
        if (category !== "all" && group.category !== category) {
            return;
        }

        const records = getMatchingRecords(group, query);
        if (records.length === 0) return;

        visibleGroups++;
        visibleRecords += records.length;

        const groupBox = element("div", null, "event-group");
        const header = element("div", null, "group-header");

        const left = element("div");
        left.appendChild(
            element("div",
                `${group.event_id} — ${group.description}`,
                "group-title")
        );
        left.appendChild(
            element("div", group.category, "group-category")
        );

        header.appendChild(left);
        header.appendChild(
            element("span", formatNumber(records.length), "group-count")
        );

        const content = element("div", null, "group-content");

        const isExpanded = expanded.has(group.event_id);
        if (!isExpanded) content.classList.add("hidden");

        header.setAttribute("role", "button");
        header.setAttribute("tabindex", "0");
        header.setAttribute("aria-expanded", String(isExpanded));

        function toggle() {
            if (expanded.has(group.event_id)) {
                expanded.delete(group.event_id);
            } else {
                expanded.add(group.event_id);
            }
            renderGroups();
        }

        header.addEventListener("click", toggle);
        header.addEventListener("keydown", event => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                toggle();
            }
        });

        if (isExpanded) {
            renderTable(content, group, records);
        }

        groupBox.appendChild(header);
        groupBox.appendChild(content);
        container.appendChild(groupBox);
    });

    document.getElementById("resultCount").textContent =
        `${visibleGroups} event groups, ` +
        `${formatNumber(visibleRecords)} matching records`;

    if (visibleGroups === 0) {
        container.appendChild(
            element("p", "No matching events found.", "note")
        );
    }
}

document.getElementById("searchInput").addEventListener(
    "input", () => {
        Object.keys(pages).forEach(key => pages[key] = 1);
        renderGroups();
    }
);

document.getElementById("categoryFilter").addEventListener(
    "change", renderGroups
);

initializeSummary();
renderGroups();
</script>
</body>
</html>"""

    final_html = template.replace("__REPORT_DATA__", data_json)
    output.write_text(final_html, encoding="utf-8")

    return output
