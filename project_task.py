import re
import csv
from collections import defaultdict

# Configuration for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10  # Default threshold for failed login attempts

def parse_log_file(log_file_path):
    """Parses the log file and extracts information."""
    ip_request_count = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_logins = defaultdict(int)

    ip_regex = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    endpoint_regex = re.compile(r'\"(?:GET|POST|PUT|DELETE|HEAD) (.*?) HTTP/')

    with open(log_file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = ip_regex.search(line)
            if ip_match:
                ip = ip_match.group()
                ip_request_count[ip] += 1

            # Extract endpoint
            endpoint_match = endpoint_regex.search(line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access_count[endpoint] += 1

            # Detect failed login attempts (status code 401 or "Invalid credentials")
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_request_count, endpoint_access_count, failed_logins

def save_to_csv(file_name, ip_requests, endpoint_data, suspicious_data):
    """Saves data to a CSV file."""
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Save requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_requests)
        writer.writerow([])  # Add an empty row for separation

        # Save most accessed endpoint
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerows([endpoint_data])
        writer.writerow([])

        # Save suspicious activity
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        writer.writerows(suspicious_data)

def main(log_file_path):
    ip_request_count, endpoint_access_count, failed_logins = parse_log_file(log_file_path)

    # Process requests per IP
    requests_per_ip = sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)
    print("Requests per IP Address:")
    print("IP Address           Request Count")
    for ip, count in requests_per_ip:
        print(f"{ip:<20}{count}")

    # Find the most accessed endpoint
    most_accessed_endpoint = max(endpoint_access_count.items(), key=lambda x: x[1])
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Detect suspicious activity
    suspicious_activity = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]
    suspicious_activity.sort(key=lambda x: x[1], reverse=True)
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity:
        print(f"{ip:<20}{count}")

    # Save results to CSV
    save_to_csv(
        'log_analysis_results.csv',
        requests_per_ip,
        (most_accessed_endpoint[0], most_accessed_endpoint[1]),
        suspicious_activity
    )
    print("\nResults saved to 'log_analysis_results.csv'.")

if __name__ == "__main__":
    log_file_path = input("Enter the path to the log file: ")
    main(log_file_path)
