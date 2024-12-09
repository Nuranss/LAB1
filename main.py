import re
import json
import csv
from collections import defaultdict


log_file = "server_logs.txt"
with open(log_file, "r") as file:
    logs = file.readlines()


log_pattern = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>[^\]]+)\] \"(?P<method>\w+) (?P<path>[^\"]+) HTTP/[0-9\.]+\" (?P<status>\d+) (?P<size>\d+)")


ip_attempts = defaultdict(int)
log_entries = []


for log in logs:
    match = log_pattern.search(log)
    if match:
        ip = match.group("ip")
        date = match.group("date")
        method = match.group("method")
        status = match.group("status")
        
        log_entries.append({"ip": ip, "date": date, "method": method, "status": status})
        
        
        if status == "401":
            ip_attempts[ip] += 1


failed_logins = {ip: count for ip, count in ip_attempts.items() if count > 5}


with open("failed_logins.json", "w") as json_file:
    json.dump(failed_logins, json_file, indent=4)


with open("log_analysis.txt", "w") as txt_file:
    for ip, count in ip_attempts.items():
        txt_file.write(f"{ip}: {count} failed attempts\n")


with open("log_analysis.csv", "w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
    for entry in log_entries:
        ip = entry["ip"]
        csv_writer.writerow([
            entry["ip"],
            entry["date"],
            entry["method"],
            ip_attempts.get(ip, 0) if entry["status"] == "401" else 0
        ])


threat_ips = ["10.0.0.15", "192.168.1.11"]
threat_data = {ip: "Threat Detected" for ip in threat_ips}

with open("threat_ips.json", "w") as json_file:
    json.dump(threat_data, json_file, indent=4)


combined_data = {
    "failed_logins": failed_logins,
    "threat_data": threat_data
}

with open("combined_security_data.json", "w") as json_file:
    json.dump(combined_data, json_file, indent=4)

print("Log analysis completed. Files generated:")
print("- failed_logins.json")
print("- threat_ips.json")
print("- combined_security_data.json")
print("- log_analysis.txt")
print("- log_analysis.csv")