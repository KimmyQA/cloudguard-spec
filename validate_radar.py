import json
import os
from datetime import datetime, timezone, timedelta

def load_and_validate_feed(filepath):
    if not os.path.exists(filepath):
        print(f"❌ Error: File {filepath} not found.")
        return None
        
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        print("✅ Success: JSON syntax is valid.")
        return data
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON syntax. Details: {e}")
        return None

def check_sla_deadlines(data):
    print("\n--- Running CloudRadar SLA Analysis ---")
    now = datetime.now(timezone.utc)
    critical_breaches = 0

    vulns = data.get("active_vulnerabilities", [])
    for v in vulns:
        rem_status = v["remediation"]["status"]
        if rem_status == "RESOLVED":
            continue
            
        deadline_str = v["remediation"]["sla_deadline"]
        deadline = datetime.fromisoformat(deadline_str.replace("Z", "+00:00"))
        
        time_left = deadline - now
        
        print(f"Analyzing {v['vuln_id']} ({v['severity']}) - Status: {rem_status}")
        
        if time_left <= timedelta(hours=24):
            print(f"  ⚠️ ALERT: SLA expiring soon! Time left: {time_left}")
            if v["severity"] in ["CRITICAL", "HIGH"]:
                critical_breaches += 1
        else:
            print(f"  Status: OK. Time left: {time_left.days} days")

    print("\n--- Summary ---")
    if critical_breaches > 0:
        print(f"🚨 Action Required: {critical_breaches} critical/high ticket(s) require immediate remediation!")
    else:
        print("🟢 All outstanding SLAs are within safe operational margins.")

if __name__ == "__main__":
    feed_file = "vulnerability-feed.json"
    feed_data = load_and_validate_feed(feed_file)
    if feed_data:
        check_sla_deadlines(feed_data)
