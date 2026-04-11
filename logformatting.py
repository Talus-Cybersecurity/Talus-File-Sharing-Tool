import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "logs", "serverLogs.json")

def read_logs():
    if not os.path.exists(LOG_PATH):
        return []

    with open(LOG_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []
        
def format_log_entry(entry):
    timestamp = entry.get("timestamp_utc", "N/A")
    event = entry.get("event_type", "N/A")
    result = entry.get("result", "N/A")
    client = entry.get("client_id", "unknown")
    role = entry.get("role", "unknown")
    file_id = entry.get("file_id", "-")
    message = entry.get("message", "")

    return (
        f"[{timestamp}] "
        f"{result.upper()} | {event} | "
        f"client={client} | role={role} | file={file_id} | {message}"
    )

def get_readable_logs():
    logs = read_logs()
    return [format_log_entry(entry) for entry in logs]

READABLE_PATH = os.path.join(BASE_DIR, "logs", "readableLogs.txt")

def generate_readable_log_file():
    lines = get_readable_logs()

    with open(READABLE_PATH, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")