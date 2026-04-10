import uuid
from datetime import datetime, timezone

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