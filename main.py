import re
import json
import csv
from collections import Counter

def read_logs(file_path):
    """Read logs from the specified file."""
    with open(file_path, 'r') as file:
        return file.readlines()

def extract_log_data(logs):
    """Extract IP addresses, dates, HTTP methods, and status codes from logs."""
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    date_pattern = r'\[(.*?)\]'
    method_pattern = r'\"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)'

    ip_counts = Counter()
    extracted_data = []

    for log in logs:
        ip = re.search(ip_pattern, log).group(1)
        date = re.search(date_pattern, log).group(1)
        method = re.search(method_pattern, log).group(1)
        status_code = log.split('" ')[1].split(' ')[0]

        if status_code == "401":  # Failed login attempts
            ip_counts[ip] += 1

        extracted_data.append({
            "ip": ip,
            "date": date,
            "method": method,
            "status_code": status_code
        })

    return ip_counts, extracted_data

def write_json(file_path, data):
    """Write data to a JSON file."""
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def write_text(file_path, ip_counts):
    """Write IP counts to a text file."""
    with open(file_path, 'w') as file:
        for ip, count in ip_counts.items():
            file.write(f"{ip}: {count} failed attempts\n")

def write_csv(file_path, extracted_data, ip_counts):
    """Write extracted data to a CSV file."""
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
        for data in extracted_data:
            writer.writerow([
                data["ip"], data["date"], data["method"],
                ip_counts[data["ip"]] if data["status_code"] == "401" else 0
            ])

def main():
    # File paths
    log_file = "server_logs.txt"
    failed_logins_json = "failed_logins.json"
    threat_ips_json = "threat_ips.json"
    combined_security_data_json = "combined_security_data.json"
    log_analysis_txt = "log_analysis.txt"
    log_analysis_csv = "log_analysis.csv"

    # Step 1: Read and analyze logs
    logs = read_logs(log_file)
    ip_counts, extracted_data = extract_log_data(logs)

    # Step 2: Identify failed logins and write to JSON
    failed_logins = {ip: count for ip, count in ip_counts.items() if count > 3}
    write_json(failed_logins_json, failed_logins)

    # Step 3: Match threat intelligence and write to JSON
    threat_intel = ["192.168.1.11", "10.0.0.15"]
    threat_matches = [ip for ip in threat_intel if ip in ip_counts]
    write_json(threat_ips_json, threat_matches)

    # Step 4: Combine data and write to JSON
    combined_data = {
        "failed_logins": failed_logins,
        "threat_matches": threat_matches
    }
    write_json(combined_security_data_json, combined_data)

    # Step 5: Write log analysis to text file
    write_text(log_analysis_txt, ip_counts)

    # Step 6: Write log analysis to CSV file
    write_csv(log_analysis_csv, extracted_data, ip_counts)

if __name__ == "__main__":
    main()
