import uuid
from datetime import datetime, timezone
import os
import json
import shutil

def build_log_entry(event_type, result, message, **kwargs):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "result": result,
        "message": message,

        # Common optional fields
        "client_id": kwargs.get("client_id"),
        "role": kwargs.get("role"),
        "ip": kwargs.get("ip"),
        "auth_method": kwargs.get("auth_method"),
        "file_id": kwargs.get("file_id"),
        "failure_reason": kwargs.get("failure_reason"),
        "access_count_after": kwargs.get("access_count_after")
    }

def log_sender_event(event_type, result, message, **kwargs):
    return build_log_entry(
        event_type=event_type,
        result=result,
        message=message,
        role="sender",
        **kwargs
    )

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "logs", "serverLogs.json")
BACKUP_DIR = os.path.join(BASE_DIR, "logs", "backups")

def ensure_log_file():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            json.dump([], f)

def read_logs():
    ensure_log_file()
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except:
            return []
        
def write_logs(logs):
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

def write_log(entry):
    logs = read_logs()
    logs.append(entry)
    write_logs(logs)

    check_log_size()


def check_log_size(max_size_bytes=1_000_000):  # ~1MB
    if os.path.exists(LOG_PATH):
        size = os.path.getsize(LOG_PATH)
        if size > max_size_bytes:
            warning_entry = build_log_entry(
                event_type="log_size_warning",
                result="warning",
                message=f"Log file exceeded {max_size_bytes} bytes"
            )
            logs = read_logs()
            logs.append(warning_entry)
            write_logs(logs)


def backup_logs():
    os.makedirs(BACKUP_DIR, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"serverLogs_{timestamp}.json")

    shutil.copy(LOG_PATH, backup_path)

    backup_entry = build_log_entry(
        event_type="log_backup_created",
        result="success",
        message=f"Backup created: {backup_path}"
    )

    logs = read_logs()
    logs.append(backup_entry)
    write_logs(logs)