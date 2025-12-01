# File Integrity Monitoring System (FIM)

A lightweight File Integrity Monitoring tool written in Python. It helps detect added, removed, or modified files under a given directory and can optionally send email alerts and export reports.

## Features
- Initialize a baseline file (SHA256 hashes)
- Scan and report differences (added/removed/modified)
- Monitor continuously with a configurable interval
- Export reports to JSON or CSV
- Optional email alerts via SMTP (user must provide credentials)
- Simple logging to `fim.log`

## Requirements
- Python 3.7+
- No external Python packages required (uses standard library)
- Optional: SMTP credentials for email notifications

## Installation
1. Download or clone the repository
```bash
git clone https://github.com/yourusername/file-integrity-monitor.git
cd file-integrity-monitor
```

2. Make the main script executable (optional)
```bash
chmod +x fim.py
```

## Usage

### Initialize baseline
```bash
python3 fim.py init /path/to/monitor --db baseline.json
```
This creates a `baseline.json` file containing SHA256 hashes of all files in the path.

### Scan once and show report
```bash
python3 fim.py scan /path/to/monitor --db baseline.json --export report.json
```
This compares current state with baseline and optionally exports report to `report.json` or `report.csv`.

### Monitor continuously
```bash
python3 fim.py monitor /path/to/monitor --db baseline.json --interval 120 --notify --smtp smtp.json
```
This runs periodic checks (default 60s). If changes are detected, it exports a timestamped report file and (optionally) sends an email using SMTP config in `smtp.json`.

### SMTP configuration (smtp.json)
If you want email alerts, create a JSON file with the following fields:
```json
{
  "host": "smtp.example.com",
  "port": 465,
  "username": "user@example.com",
  "password": "yourpassword",
  "to": "notifyme@example.com"
}
```
> Keep this file secure and do not commit credentials to public repos.

## Logs
The script writes logs to `fim.log` in the current directory.

## Disclaimer
Use this tool only on systems and networks you own or have explicit permission to test. The author is not responsible for misuse.

## Contributing
Contributions welcome. Open issues or create pull requests.
