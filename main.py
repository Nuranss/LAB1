import re
import json
import csv
from collections import defaultdict

# Step 1: Read the log file
log_file = "server_logs.txt"
with open(log_file, "r") as file:
    logs = file.readlines()

# Regex to extract IP, date, and HTTP method
log_pattern = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>[^\]]+)\] \"(?P<method>\w+) (?P<path>[^\"]+) HTTP/[0-9\.]+\" (?P<status>\d+) (?P<size>\d+)")

# Data structures to store extracted information
ip_attempts = defaultdict(int)
log_entries = []

# Step 2: Parse logs and count failed login attempts
for log in logs:
    match = log_pattern.search(log)
    if match:
        ip = match.group("ip")
        date = match.group("date")
        method = match.group("method")
        status = match.group("status")
        
        log_entries.append({"ip": ip, "date": date, "method": method, "status": status})
        
        # Count failed login attempts (HTTP status 401)
        if status == "401":
            ip_attempts[ip] += 1

# Step 3: Identify IPs with more than 5 failed login attempts
failed_logins = {ip: count for ip, count in ip_attempts.items() if count > 5}

# Write failed_logins.json
with open("failed_logins.json", "w") as json_file:
    json.dump(failed_logins, json_file, indent=4)

# Step 4: Save IP and failed attempts count to a text file
with open("log_analysis.txt", "w") as txt_file:
    for ip, count in ip_attempts.items():
        txt_file.write(f"{ip}: {count} failed attempts\n")

# Step 5: Write log data to a CSV file
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

# Step 6: Combine with threat intelligence (mock threat data for example)
threat_ips = ["10.0.0.15", "192.168.1.11"]
threat_data = {ip: "Threat Detected" for ip in threat_ips}

with open("threat_ips.json", "w") as json_file:
    json.dump(threat_data, json_file, indent=4)

# Step 7: Combine failed logins and threat data into one JSON file
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