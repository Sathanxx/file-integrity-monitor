#!/usr/bin/env python3
"""
File Integrity Monitoring System (FIM)
Features:
- Initialize baseline hash database for a path
- Scan and report changes (modified, added, removed)
- Monitor mode: run periodically and log alerts
- Export reports to JSON/CSV
- Optional email alerts (SMTP config required)
"""

import os
import sys
import time
import json
import hashlib
import argparse
import logging
import smtplib
import ssl
from datetime import datetime
from typing import Dict, Tuple, List

LOG_FILE = "fim.log"
DEFAULT_DB = "baseline.json"
VERSION = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def build_baseline(target_path: str) -> Dict[str, str]:
    baseline = {}
    for root, dirs, files in os.walk(target_path):
        for fname in files:
            full = os.path.join(root, fname)
            try:
                baseline[full] = sha256_of_file(full)
            except (PermissionError, FileNotFoundError) as e:
                logging.warning(f"Skipping {full}: {e}")
    return baseline

def save_baseline(baseline: Dict[str, str], filename: str) -> None:
    with open(filename, "w") as f:
        json.dump(baseline, f, indent=2)
    logging.info(f"Baseline saved to {filename} (entries: {len(baseline)})")

def load_baseline(filename: str) -> Dict[str, str]:
    with open(filename, "r") as f:
        return json.load(f)

def compare_baselines(old: Dict[str, str], new: Dict[str, str]) -> Dict[str, List[str]]:
    old_keys = set(old.keys())
    new_keys = set(new.keys())
    added = sorted(list(new_keys - old_keys))
    removed = sorted(list(old_keys - new_keys))
    modified = []
    for k in old_keys & new_keys:
        if old[k] != new[k]:
            modified.append(k)
    return {"added": added, "removed": removed, "modified": sorted(modified)}

def send_email_alert(smtp_cfg: dict, subject: str, body: str) -> bool:
    try:
        port = smtp_cfg.get("port", 465)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_cfg["host"], port, context=context) as server:
            server.login(smtp_cfg["username"], smtp_cfg["password"])
            message = f"""From: {smtp_cfg['username']}
To: {smtp_cfg['to']}
Subject: {subject}

{body}
"""
            server.sendmail(smtp_cfg["username"], smtp_cfg["to"].split(","), message)
        logging.info("Email alert sent.")
        return True
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        return False

def export_report(changes: dict, filename: str) -> None:
    if filename.endswith(".json"):
        with open(filename, "w") as f:
            json.dump(changes, f, indent=2)
    elif filename.endswith(".csv"):
        import csv
        rows = []
        for typ in ("added","removed","modified"):
            for p in changes.get(typ, []):
                rows.append([typ, p])
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["change_type","path"])
            writer.writerows(rows)
    else:
        with open(filename, "w") as f:
            f.write(json.dumps(changes, indent=2))
    logging.info(f"Exported report to {filename}")

def human_report(changes: dict) -> str:
    lines = []
    total = sum(len(v) for v in changes.values())
    lines.append(f"FIM Report - {datetime.utcnow().isoformat()}Z - Total changes: {total}")
    for typ in ("added","removed","modified"):
        lines.append(f"\n{typ.upper()} ({len(changes.get(typ, []))}):")
        for p in changes.get(typ, []):
            lines.append(f"  - {p}")
    return "\n".join(lines)

def do_init(args):
    target = args.path
    baseline = build_baseline(target)
    dbfile = args.db or DEFAULT_DB
    save_baseline(baseline, dbfile)
    print(f"Initialized baseline at {dbfile} for path: {target}")

def do_scan(args):
    dbfile = args.db or DEFAULT_DB
    if not os.path.exists(dbfile):
        logging.error(f"Baseline file {dbfile} not found. Create it with --init") 
        sys.exit(1)
    old = load_baseline(dbfile)
    new = build_baseline(args.path)
    changes = compare_baselines(old, new)
    report = human_report(changes)
    print(report)
    if args.export:
        export_report(changes, args.export)
    if args.notify and args.smtp:
        send_email_alert(args.smtp, "FIM Alert - Scan Results", report)

def do_monitor(args):
    dbfile = args.db or DEFAULT_DB
    interval = args.interval
    smtp_cfg = args.smtp
    if not os.path.exists(dbfile):
        logging.error(f"Baseline file {dbfile} not found. Create it with --init") 
        sys.exit(1)
    baseline = load_baseline(dbfile)
    logging.info(f"Starting monitor on {args.path} (interval={interval}s)" )
    try:
        while True:
            new = build_baseline(args.path)
            changes = compare_baselines(baseline, new)
            total = sum(len(v) for v in changes.values())
            if total > 0:
                report = human_report(changes)
                logging.warning(report)
                timestamped = f"fim_report_{int(time.time())}.json"
                export_report(changes, timestamped)
                # send email if configured
                if args.notify and smtp_cfg:
                    send_email_alert(smtp_cfg, "FIM Alert - Monitor", report)
                # update baseline to new snapshot so future alerts are incremental
                baseline = new
                save_baseline(baseline, dbfile)
            else:
                logging.info("No changes detected.")
            time.sleep(interval)
    except KeyboardInterrupt:
        logging.info("Monitor stopped by user.")
        print("Monitor stopped.")

def parse_smtp_from_file(path: str) -> dict:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load SMTP config: {e}")
        return {}

def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitoring System (FIM)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize baseline for a target path")
    p_init.add_argument("path", help="Target path to scan", type=str)
    p_init.add_argument("--db", help="Baseline DB file", type=str)

    p_scan = sub.add_parser("scan", help="Compare current state against baseline")
    p_scan.add_argument("path", help="Target path to scan", type=str)
    p_scan.add_argument("--db", help="Baseline DB file", type=str)
    p_scan.add_argument("--export", help="Export report filename (json/csv)", type=str)
    p_scan.add_argument("--notify", help="Send email notification on changes", action="store_true")
    p_scan.add_argument("--smtp", help="Path to smtp.json config file", type=str)

    p_mon = sub.add_parser("monitor", help="Monitor target path continuously")
    p_mon.add_argument("path", help="Target path to monitor", type=str)
    p_mon.add_argument("--db", help="Baseline DB file", type=str)
    p_mon.add_argument("--interval", help="Interval seconds between checks", type=int, default=60)
    p_mon.add_argument("--notify", help="Send email notification on changes", action="store_true")
    p_mon.add_argument("--smtp", help="Path to smtp.json config file", type=str)

    p_ver = sub.add_parser("version", help="Show version")

    args = parser.parse_args()

    # if smtp path provided, load config
    if hasattr(args, "smtp") and args.smtp:
        smtp_cfg = parse_smtp_from_file(args.smtp)
        args.smtp = smtp_cfg
    else:
        args.smtp = None

    if args.command == "init":
        do_init(args)
    elif args.command == "scan":
        do_scan(args)
    elif args.command == "monitor":
        do_monitor(args)
    elif args.command == "version":
        print(VERSION)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
