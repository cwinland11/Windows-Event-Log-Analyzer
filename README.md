# Windows Event Log Analyzer
A Python-based digital forensics tool that reads Windows Event Log files (`.evtx`),
identifies important security and system events, and generates an interactive HTML report.
This project is designed to make Windows event log analysis easier. Instead of manually searching through thousands 
of entries in Windows Event Viewer, users can run this program to identify relevant activity and review the results in a browser.
The program works entirely on your computer. No internet connection is required to analyze logs after the initial setup.

## Requirements
Before using the program, you will need:

- A Windows 10 or Windows 11 computer
- Python 3.10 or newer
- An internet connection for downloading and installing the program
- Windows PowerShell
- Windows Event Log files (`.evtx`)

Git is recommended for downloading the project, but it is not required.

**Note:** The instructions below use Windows 11 and PowerShell.

## Step 1: Install Python

Python is the programming language used to run this application.
After installing Python, open PowerShell.
Enter the following command:
```powershell
python --version
```
You should see something similar to:
```text
Python 3.13.17
```
The exact version may be different.
Next, verify that Python's package manager, pip, is installed:
```powershell
python -m pip --version
```
If both commands display version information, Python is ready.
If Windows cannot find Python, restart PowerShell and try again. You may need to reinstall Python or configure its PATH setting.

## Step 2: Download the Project
There are two ways to download the Windows Event Log Analyzer.
### Option A: Download ZIP (Recommended for Beginners)

This method does not require Git.
1. Open the project's GitHub repository:

   https://github.com/cwinland11/Windows-Event-Log-Analyzer

2. Click the green **Code** button.
3. Select **Download ZIP**.
4. Wait for the download to finish.
5. Open your Downloads folder.
6. Right-click the downloaded ZIP file.
7. Select **Extract All**.
8. Extract the files to your Desktop.

The extracted folder will usually be named:

```text
Windows-Event-Log-Analyzer-main
```

### Option B: Download Using Git

If Git is installed, open PowerShell and enter:
```powershell
cd "$HOME\Desktop"
```
Download the repository:
```powershell
git clone https://github.com/cwinland11/Windows-Event-Log-Analyzer.git
```
Enter the project folder:
```powershell
cd "$HOME\Desktop\Windows-Event-Log-Analyzer"
```

## Step 3: Open the Project in PowerShell

If you downloaded the ZIP file, enter:

cd "$HOME\Desktop\Windows-Event-Log-Analyzer-main"

If you used Git, enter:

cd "$HOME\Desktop\Windows-Event-Log-Analyzer"

You can verify that you are in the correct folder by running:

dir

You should see files and folders similar to:
```text
Windows-Event-Log-Analyzer/
|
|-- src/
|   |-- main.py
|   |-- evtx_parser.py
|   |-- event_analyzer.py
|   |-- report_generator.py
|   |-- cache_manager.py
|
|-- samples/
|-- reports/
|-- tests/
|-- README.md
|-- requirements.txt
|-- .gitignore
```

The `src` folder contains the Python source code.
The `samples` folder is where you will place the Windows Event Log files.
The `reports` folder is where the generated report will be saved.

## Step 4: Create a Python Virtual Environment

A virtual environment keeps the project's Python packages separate from other programs on your computer.
While inside the project folder, enter:
```powershell
python -m venv .venv
```

This creates a new folder named `.venv`.

Next, activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

If activation succeeds, your PowerShell prompt should begin with:

```text
(.venv)
```

For example:

```text
(.venv) PS C:\Users\YourName\Desktop\Windows-Event-Log-Analyzer>
```

### If PowerShell Blocks Activation
Some Windows computers prevent PowerShell scripts from running by default.
If you receive an execution policy error, enter:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

If prompted, enter:

```text
Y
```

Then activate the virtual environment again:

```powershell
.\.venv\Scripts\Activate.ps1
```

This execution policy change applies only to the current PowerShell session.

## Step 5: Install the Required Python Packages

With the virtual environment activated, enter:

```powershell
python -m pip install -r requirements.txt
```

This installs the dependencies required by the program, including `python-evtx`, which allows Python to read Windows Event Log files.
Wait until the installation finishes.
You can verify that the package is installed by entering:

```powershell
python -m pip show python-evtx
```

If the command displays package information, the dependency is installed.

## Step 6: Collect Windows Event Logs

The program needs Windows Event Log files to analyze.
Windows records information about logins, security activity, installed services, system startups, shutdowns, and other events.
For this project, the program expects two files:

- `security.evtx`
- `system.evtx`

These files must be placed in the project's `samples` folder.
### Export the Security Log
Open a **new PowerShell window as Administrator**.
Navigate to your project folder.
If you downloaded the ZIP:

```powershell
cd "$HOME\Desktop\Windows-Event-Log-Analyzer-main"
```

If you cloned the repository using Git:

```powershell
cd "$HOME\Desktop\Windows-Event-Log-Analyzer"
```

Create the samples folder if it does not already exist:

```powershell
New-Item -ItemType Directory -Force -Path ".\samples"
```

Export the Windows Security Event Log:

```powershell
wevtutil epl Security ".\samples\security.evtx"
```

### Export the System Log

In the same administrator PowerShell window, enter:

```powershell
wevtutil epl System ".\samples\system.evtx"
```

Both commands may take some time, depending on how many events are stored on your computer.

### Verify the Files

Enter:

```powershell
dir .\samples
```

You should see:

```text
security.evtx
system.evtx
```

**Important:** Windows Security logs can contain usernames, computer names, and other potentially sensitive information.
Only analyze logs from systems you own or are authorized to investigate. Do not publicly upload your personal event logs.

## Step 7: Run the Windows Event Log Analyzer

Return to your original PowerShell window.
Make sure you are inside the project folder and that the Python virtual environment is activated.
If necessary, activate it again:

```powershell
.\.venv\Scripts\Activate.ps1
```

Now run the program:

```powershell
python .\src\main.py
```

The program will:

1. Read `security.evtx` and `system.evtx` from the `samples` folder.
2. Parse the Windows event records.
3. Identify important security and system events.
4. Display a summary in PowerShell.
5. Generate an interactive HTML report.
6. Save parsed data to a local cache to speed up future runs.

The first analysis may take several minutes if your Windows logs contain thousands of records.

This is normal.

After the first successful run, repeated analyses of unchanged files should be much faster because the program can reuse cached data.

## Step 8: Open the HTML Report

After the analysis finishes, the program creates a report named:

```text
forensic_report.html
```

The report is stored inside the `reports` folder.

To open it automatically in your default web browser, enter:

```powershell
Start-Process ".\reports\forensic_report.html"
```

You can also open File Explorer, navigate to the project's `reports` folder, and double-click `forensic_report.html`.
The report does not require a web server or an internet connection.
The interactive HTML report provides several ways to review Windows event data.
- An Event ID such as `4625`
- A Windows username such as `Guest`
- A computer name
- A keyword contained in event details

| Event ID | Description |
|---|---|
| 4624 | Successful account logon |
| 4625 | Failed account logon |
| 4634 | Account logoff |
| 4720 | User account created |
| 4726 | User account deleted |
| 4732 | Member added to a security-enabled local group |
| 4740 | User account locked out |
| 1102 | Security audit log cleared |
| 6005 | Windows Event Log service started |
| 6006 | Windows Event Log service stopped |
| 7045 | New service installed |

These events can help investigators understand login activity, account changes, and important system events.
**Note:** An event appearing in the report does not automatically mean a security incident occurred. Events must be interpreted in context.


### Source Files

**main.py**
The main entry point of the program. Coordinates log loading, analysis, console output, and report generation.

**evtx_parser.py**
Reads Windows `.evtx` files and extracts event information into Python data structures.

**event_analyzer.py**
Identifies important Event IDs, organizes findings, and provides filtering functionality.

**report_generator.py**
Creates the interactive HTML report, including event groups, searching, filtering, and pagination.

**cache_manager.py**
Stores previously parsed events locally so unchanged log files do not need to be processed again.

### Other Folders
**samples/**
Stores the Windows Event Log files used during analysis.

**reports/**
Contains the generated HTML report.

**tests/**
Reserved for testing and future development.

## Current Limitations

- The program is currently designed around Windows Security and System `.evtx` files.
- The default workflow expects the filenames `security.evtx` and `system.evtx` in the `samples` directory.
- Only selected Event IDs are classified as important.
- The tool does not automatically determine whether an event is malicious.
- The HTML report is generated locally rather than hosted online.
- Large event logs may require significant processing time during the initial analysis.

## Security and Privacy

Windows Event Logs may contain sensitive system information.

For that reason:

- Event logs should only be collected from systems you own or are authorized to analyze.
- Exported `.evtx` files should not be uploaded to public repositories.
- Generated reports should be reviewed before sharing.
- Cached data should be handled with the same care as the original logs.
- The tool should be used to support an investigation, not as a replacement for professional forensic analysis.

The repository's `.gitignore` is intended to exclude local event log files, generated reports, caches, and Python virtual environments from version control.

## Purpose

This project was developed as an educational digital forensics and cybersecurity tool.
Its purpose is to demonstrate how Python can automate the collection, parsing, filtering, and presentation of Windows event data.
The project combines Windows event log analysis, Python programming, file processing, performance optimization, and interactive reporting into a single application.

## Disclaimer

This software is intended for educational use and authorized digital forensic analysis.

It does not guarantee detection of security incidents, and its results should be verified against the original event records when conducting an investigation.
