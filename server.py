import asyncio
import logging
import os
import base64
import json
import websockets
from websockets.server import WebSocketServerProtocol
from email_service import generate_verification_code, send_verification_email
from datetime import timedelta

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from typing import Any, Dict, Optional

import secrets
import ssl
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import psycopg2
from loghelper import build_log_entry, log_sender_event, write_log, handle_get_logs
from logformatting import get_readable_logs
from backend.schema import Schema
from backend.database import Database
from Cryptography import hash_password, verify_password

import re

HOST = "0.0.0.0"
PORT = 8765
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
SERVER_PRIVATE_KEY_FILE = "server_private.pem"
SERVER_PUBLIC_KEY_FILE = "server_public.pem"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

@dataclass
class ClientSession:
    websocket: WebSocketServerProtocol
    client_id: str
    role: str  # "sender" or "receiver"
    public_key_pem: Optional[str] = None
    connected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class FilePackage:
    package_id: str
    sender_id: str
    receiver_id: str
    encrypted_file_b64: str
    encrypted_requirements_b64: Optional[str] = None
    encrypted_file_key_b64: Optional[str] = None
    parsed_requirements: Optional[Dict[str, Any]] = None
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[str] = None
    uploaded_at: Any = field(default_factory=lambda: datetime.now(timezone.utc))
    delivered: bool = False
    accepted: bool = False
    view_count: int = 0


connected_clients: Dict[str, ClientSession] = {}
public_keys: Dict[str, str] = {}
sender_session_keys: Dict[str, bytes] = {}
receiver_session_keys: Dict[str, bytes] = {}
packages: Dict[str, FilePackage] = {}
_pending_registrations: Dict[str, dict] = {}  # username -> pending reg data + verification code

async def handle_get_logs(ws, data):
    client_id = data.get("client_id")

    # VERY SIMPLE admin check (adjust if you have roles stored elsewhere)
    session = connected_clients.get(client_id)

    if not session or session.role != "admin":
        await send_json(ws, {
            "type": "error",
            "message": "Unauthorized: Admin access required"
        })
        return

    logs = get_readable_logs()

    await send_json(ws, {
        "type": "logs_response",
        "logs": logs
    })

def generate_rsa_keypair_if_missing() -> None:
    private_path = Path(SERVER_PRIVATE_KEY_FILE)
    public_path = Path(SERVER_PUBLIC_KEY_FILE)

    if private_path.exists() and public_path.exists():
        logging.info("Server RSA keypair already exists.")
        return

    logging.info("Generating server RSA keypair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    logging.info("Server RSA keypair generated.")


def load_server_private_key():
    return serialization.load_pem_private_key(
        Path(SERVER_PRIVATE_KEY_FILE).read_bytes(),
        password=None
    )

def load_server_public_key_pem() -> str:
    return Path(SERVER_PUBLIC_KEY_FILE).read_text(encoding="utf-8")

def rsa_encrypt_with_public_key(public_key_pem: str, plaintext: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt_with_server_private_key(ciphertext: bytes) -> bytes:
    private_key = load_server_private_key()
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
# User account registration logic starts here
# ws = who to respond to
# data = data sent from client 
db = Database()
async def handle_create_account(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    user_id       = str(uuid.uuid4())
    username      = data["username"]
    email         = data["email"]
    password      = data["password_hash"]   # client sends SHA-256 hash; server bcrypts it
    tag_id        = data["tag_id"]
    public_key_spki  = data.get("public_key_spki")
    public_key_pem   = spki_b64_to_pem(public_key_spki) if public_key_spki else None
    encrypted_private_key = data.get("encrypted_private_key")
    pbkdf2_salt      = data.get("pbkdf2_salt")
    aes_iv           = data.get("aes_iv")

    if not username or len(username) < 3 or len(username) > 36:
        await send_json(ws, {"type": "error",
            "message": "Username must be between 3 and 36 characters."})
        return

    if not password or len(password) != 64 or not re.fullmatch(r"[0-9a-f]{64}", password):
        await send_json(ws, {"type": "error",
            "message": "Invalid password format."})
        return

    new_hash_pw = hash_password(password)
    if new_hash_pw is None:
        write_log(build_log_entry(event_type="register_failure", result="failure",
            message="Password hashing failed", client_id=user_id, role="unknown"))
        await send_json(ws, {"type": "error", "message": "Password hashing failed"})
        return

    # Reject if username already exists in DB or has a pending registration
    if db.check_if_user_exists(username) or username in _pending_registrations:
        write_log(build_log_entry(event_type="register_failure", result="failure",
            message="Username or email already taken", client_id=user_id,
            role="unknown", failure_reason="duplicate_user"))
        await send_json(ws, {"type": "error", "message": "Username or email is already taken."})
        return

    # Hold registration data in memory — only write to DB after email is verified
    code = generate_verification_code()
    _pending_registrations[username] = {
        "user_id": user_id,
        "email": email,
        "password": new_hash_pw,
        "tag_id": tag_id,
        "public_key_pem": public_key_pem,
        "encrypted_private_key": encrypted_private_key,
        "pbkdf2_salt": pbkdf2_salt,
        "aes_iv": aes_iv,
        "code": code,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
    }

    sent = send_verification_email(email, code)
    if not sent:
        logging.warning("Failed to send verification email to %s", email)

    await send_json(ws, {"type": "create_account_ack", "user_id": user_id})

async def handle_verify_email(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    username = (data.get("username") or "").strip()
    code     = (data.get("code") or "").strip()

    if not username or not code:
        await send_json(ws, {"type": "error", "message": "username and code are required."})
        return

    pending = _pending_registrations.get(username)
    if not pending:
        await send_json(ws, {"type": "error", "message": "Invalid or expired verification code."})
        return

    if datetime.now(timezone.utc) > pending["expires_at"]:
        del _pending_registrations[username]
        await send_json(ws, {"type": "error",
            "message": "Verification code has expired. Please register again."})
        return

    if pending["code"] != code:
        await send_json(ws, {"type": "error", "message": "Invalid or expired verification code."})
        return

    # Code is valid — commit the user to the database now
    try:
        db.insert_user(
            pending["user_id"], username, pending["email"], pending["password"],
            pending["tag_id"], pending["public_key_pem"], pending["encrypted_private_key"],
            pending["pbkdf2_salt"], pending["aes_iv"]
        )
        db.verify_user(pending["user_id"])
        if pending["public_key_pem"]:
            public_keys[pending["user_id"]] = pending["public_key_pem"]
    except psycopg2.IntegrityError:
        await send_json(ws, {"type": "error", "message": "Username or email is already taken."})
        return
    finally:
        _pending_registrations.pop(username, None)

    logging.info("Account created and email verified for username=%s", username)
    write_log(build_log_entry(event_type="register_success", result="success",
        message="User account created", client_id=pending["user_id"], role="user"))
    await send_json(ws, {"type": "verify_email_ack", "message": "Email verified. You can now log in."})

async def handle_resend_verification(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    username = (data.get("username") or "").strip()
    if not username:
        await send_json(ws, {"type": "error", "message": "username is required."})
        return

    pending = _pending_registrations.get(username)
    if not pending:
        await send_json(ws, {"type": "error", "message": "No pending registration found."})
        return

    code = generate_verification_code()
    pending["code"] = code
    pending["expires_at"] = datetime.now(timezone.utc) + timedelta(minutes=10)

    sent = send_verification_email(pending["email"], code)
    if not sent:
        await send_json(ws, {"type": "error", "message": "Failed to send email. Please try again."})
        return

    await send_json(ws, {"type": "resend_verification_ack"})

async def handle_check_user(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    username = (data.get("username") or "").strip()
    tag_id   = (data.get("tag_id") or "").strip()
    if not username or not tag_id:
        await send_json(ws, {"type": "check_user_ack", "exists": False})
        return
    exists = db.check_user_by_tag(username, tag_id)
    await send_json(ws, {"type": "check_user_ack", "exists": exists})

async def handle_login(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    username = data["username"]
    password = data["password_hash"]   # client sends SHA-256 hash; server verifies with bcrypt
    user_matches = False

    # Check username if it matches one in the database
    if db.get_username(username) and username == db.get_username(username)[0]:
            user_matches = True
    else:
        await send_json(ws, {
            "type":"error",
            "message":"User does not exist"
        })
        logging.info("Client entered a username that does not exist")
        entry = build_log_entry(
            event_type="login_failure",
            result="failure",
            message="User does not exist",
            client_id=username,
            role="user"
        )
        write_log(entry)
        return

    user_id = db.get_user_id(username)  
    
    # Check if user is verified
    if not db.is_user_verified(username):
        await send_json(ws, {"type": "error",
            "message": "Please verify your email before logging in."})
        return
        
    # Get database password using the username
    get_db_hash = db.get_password(username)

    # If the grabbed database password matches the password typed in through login, set to True
    pw_matches = verify_password(password, get_db_hash)
    
    if pw_matches is False or get_db_hash is None:
        await send_json(ws, {
            "type": "error",
            "message" : "Incorrect password. Please retry."
        })
        logging.info("Incorrect password")
        entry = build_log_entry(
            event_type="login_failure",
            result="failure",
            message="Incorrect password",
            client_id=username,
            role="user",
            failure_reason="invalid_password"
        )
        write_log(entry)
        return
    
    try:
        if user_matches and pw_matches is True:
            entry = build_log_entry(
                event_type="login_success",
                result="success",
                message="User logged in",
                client_id=user_id,
                role="user"
            )
            write_log(entry)

            user_public_key = db.get_public_key(username)
            encrypted_private_key, pbkdf2_salt, aes_iv = db.get_key_bundle(username)
            if user_public_key:
                public_keys[user_id] = user_public_key

            await send_json(ws, {
                "type": "login_ack",
                "username": username,
                "user_id": user_id,
                "public_key_pem": user_public_key,
                "encrypted_private_key": encrypted_private_key,
                "pbkdf2_salt": pbkdf2_salt,
                "aes_iv": aes_iv
            })
        else:
            await send_json(ws, {
                "type": "error",
                "message": "Wrong password! Or smth when wrong idk"
            })

    except psycopg2.IntegrityError:
        await send_json(ws, {
            "type": "error",
            "message": "Server failed to check "
        })
        return
        

def generate_symmetric_key() -> bytes:
    return os.urandom(32)

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, plaintext, None)

def aes_gcm_decrypt(key: bytes, data: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)

def spki_b64_to_pem(spki_b64: str) -> str:
    der = base64.b64decode(spki_b64)
    pem_body = base64.encodebytes(der).decode("utf-8")
    return f"-----BEGIN PUBLIC KEY-----\n{pem_body}-----END PUBLIC KEY-----\n"


async def send_json(ws: WebSocketServerProtocol, message: Dict[str, Any]) -> None:
    await ws.send(json.dumps(message))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_packet(raw: str) -> tuple[str, Dict[str, Any]]: # validates envelope and returns packets as a tuple
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Packet must be a JSON object.")
    msg_type = data.get("type")
    if not msg_type or not isinstance(msg_type, str):
        raise ValueError("Packet missing required string field 'type'.")
    if "payload" in data:
        payload = data["payload"]
        if not isinstance(payload, dict):
            raise ValueError("Field 'payload' must be a JSON object.")
    else:
        payload = {k: v for k, v in data.items() if k != "type"}
    return msg_type, payload


def encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def decode_b64(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


#Message hander
async def handle_register(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    client_id = data["client_id"]
    role = data["role"]  # sender / receiver
    public_key_pem = data.get("public_key_pem")
    
    connected_clients[client_id] = ClientSession(
        websocket=ws,
        client_id=client_id,
        role=role,
        public_key_pem=public_key_pem
    )
    if public_key_pem:
        public_keys[client_id] = public_key_pem

    logging.info("Registered client_id=%s role=%s", client_id, role)

    await send_json(ws, {
        "type": "register_ack",
        "client_id": client_id,
        "role": role,
        "server_time": now_iso()
    })


async def handle_get_server_public_key(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    await send_json(ws, {
        "type": "server_public_key",
        "public_key_pem": load_server_public_key_pem()
    })


async def handle_publish_public_key(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    client_id = data["client_id"]
    public_key_pem = data["public_key_pem"]

    public_keys[client_id] = public_key_pem

    if client_id in connected_clients:
        connected_clients[client_id].public_key_pem = public_key_pem

    await send_json(ws, {
        "type": "publish_public_key_ack",
        "client_id": client_id
    })


async def handle_request_peer_public_key(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    peer_id = data["peer_id"]
    pem = public_keys.get(peer_id) or db.get_public_key(peer_id)

    if not pem:
        await send_json(ws, {
            "type": "error",
            "message": f"No public key found for peer '{peer_id}'"
        })
        return

    public_keys[peer_id] = pem  # cache it for future requests
    await send_json(ws, {
        "type": "peer_public_key",
        "peer_id": peer_id,
        "public_key_pem": pem
    })


async def handle_create_session_key(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    client_id = data["client_id"]

    if client_id not in public_keys:
        await send_json(ws, {
            "type": "error",
            "message": f"No public key registered for '{client_id}'"
        })
        return

    symmetric_key = generate_symmetric_key()
    encrypted_key = rsa_encrypt_with_public_key(public_keys[client_id], symmetric_key)

    role = connected_clients[client_id].role if client_id in connected_clients else "unknown"

    if role == "sender":
        sender_session_keys[client_id] = symmetric_key
    elif role == "receiver":
        receiver_session_keys[client_id] = symmetric_key

    await send_json(ws, {
        "type": "session_key_created",
        "client_id": client_id,
        "encrypted_session_key_b64": encode_b64(encrypted_key)
    })

async def handle_get_incoming_transfers(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    client_id = data.get("client_id", "")
    transfers = []

    for pkg in packages.values():
        pkg_receiver = pkg.receiver_id.split('#')[0] if '#' in pkg.receiver_id else pkg.receiver_id
        if pkg_receiver != client_id:
            continue

        try:
            uploaded = pkg.uploaded_at
            if isinstance(uploaded, str):
                uploaded = datetime.fromisoformat(uploaded)
            if uploaded.tzinfo is None:
                uploaded = uploaded.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - uploaded
            minutes = int(delta.total_seconds() / 60)
            if minutes < 1:
                time_str = "just now"
            elif minutes < 60:
                time_str = f"{minutes} min ago"
            else:
                time_str = f"{minutes // 60} hr ago"
        except Exception:
            time_str = "recently"

        requirements = pkg.parsed_requirements or {}
        max_views = requirements.get("max_views")
        view_count = pkg.view_count
        if pkg.delivered:
            status = "declined"
        elif pkg.accepted:
            status = "accepted"
        elif max_views is not None:
            try:
                status = "expired" if view_count >= int(max_views) else "pending"
            except (TypeError, ValueError):
                status = "pending"
        else:
            status = "pending"
        transfers.append({
            "id": pkg.package_id,
            "sender": pkg.sender_id,
            "initials": pkg.sender_id[:2].upper(),
            "tag": "",
            "time": time_str,
            "status": status,
            "verified": True,
            "passwordRequired": bool(requirements.get("password")),
            "passwordVerified": False,
            "timeRestricted": False,
            "withinAllowedWindow": True,
            "files": [{"name": pkg.file_name or "transfer", "size": pkg.file_size or "unknown", "type": (pkg.file_type or "").split("/")[-1].upper() or "FILE"}],
            "options": [],
            "maxViews": max_views,
            "viewCount": view_count
        })

    await send_json(ws, {"type": "incoming_transfers_list", "transfers": transfers})


# TALUS-195 - Identify if incoming message is Sender File post, store files, and database requirements
def is_sender_file_post(data: dict) -> tuple[bool, str | None]:
    for field in ("encrypted_file_b64", "encrypted_requirements_b64"):
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            return False, f"Missing or empty required field: '{field}'"
    for field in ("sender_id", "receiver_id"):
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            return False, f"Missing or empty required field: '{field}'"
    session = connected_clients.get(data["sender_id"])
    if session is None:
        return False, f"sender_id '{data['sender_id']}' is not a connected client"
    if session.role != "sender":
        return False, f"client '{data['sender_id']}' is role '{session.role}', expected 'sender'"
    return True, None


async def handle_upload_package(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    valid, reason = is_sender_file_post(data)
    if not valid:
        entry = log_sender_event(
            event_type="file_upload",
            result="failure",
            message="Invalid sender file upload",
            client_id=data.get("sender_id"),
            failure_reason=reason
        )
        write_log(entry)
        logging.warning("Rejected sender file post: %s", reason)
        await send_json(ws, {"type": "error", "message": reason})
        return
 
    sender_id                  = data["sender_id"]
    receiver_id                = data["receiver_id"]
    encrypted_file_b64         = data["encrypted_file_b64"]
    encrypted_requirements_b64 = data["encrypted_requirements_b64"]
    file_name = data.get("file_name") or "unknown"
    file_type = data.get("file_type") or "application/octet-stream"
    file_size = data.get("file_size") or str(len(encrypted_file_b64)) + " bytes (enc)"
    upload_time = datetime.now(timezone.utc)
 
    try:
        requirements = json.loads(
            rsa_decrypt_with_server_private_key(
                decode_b64(encrypted_requirements_b64)
            ).decode("utf-8")
        )
    except Exception:
        entry = log_sender_event(
            event_type="file_upload",
            result="failure",
            message="Failed to decrypt requirements",
            client_id=sender_id,
            file_id="unknown"
        )
        write_log(entry)
        logging.exception("Failed to decrypt requirements")
        await send_json(ws, {"type": "error", "message": "Could not decrypt requirements."})
        return
 
    package_id = str(uuid.uuid4())
    policy_id  = str(uuid.uuid4())
 
    packages[package_id] = FilePackage(
        package_id=package_id,
        sender_id=sender_id,
        receiver_id=receiver_id,
        encrypted_file_b64=encrypted_file_b64,
        encrypted_requirements_b64=encrypted_requirements_b64,
        encrypted_file_key_b64=data.get("encrypted_file_key_b64"),
        parsed_requirements=requirements,
        file_name=file_name,
        file_type=file_type,
        file_size=file_size,
        uploaded_at=upload_time
    )
 
    sender_user_id = db.get_user_id(sender_id) or sender_id
    try:
        db.insert_file(
            file_id=package_id,
            log_id=None,
            owner_id=sender_user_id,
            file_type=file_type,
            upload_timestamp=upload_time,
            file_size=file_size,
            file_name=file_name,
            file_path=encrypted_file_b64
        )
    except Exception:
        logging.exception("insert_file failed for package_id=%s", package_id)

    receiver_user_id = db.get_user_id(receiver_id.split('#')[0]) or receiver_id
    try:
        db.insert_file_policy(
            policy_id=policy_id,
            receiver_id=receiver_user_id,
            file_id=package_id,
            ip_address=requirements.get("ip_address"),
            access_count=requirements.get("access_count"),
            active_permissions=True,
            device_verification=requirements.get("device_verification"),
            location=requirements.get("location"),
            account_info=None,
            watermark=requirements.get("watermark"),
            data_range=None,
            time=upload_time,
            biometrics=requirements.get("biometrics")
        )
    except Exception:
        logging.exception("insert_file_policy failed for package_id=%s", package_id)
 
    logging.info("Stored package_id=%s sender=%s receiver=%s", package_id, sender_id, receiver_id)
    entry = log_sender_event(
        event_type="file_upload",
        result="success",
        message="Sender uploaded package",
        client_id=sender_id,
        file_id=package_id
    )
    write_log(entry)
    await send_json(ws, {"type": "upload_package_ack", "package_id": package_id})

    # Push notification to receiver if they're connected
    receiver_username = receiver_id.split('#')[0] if '#' in receiver_id else receiver_id
    receiver_session = connected_clients.get(receiver_username)
    if receiver_session:
        transfer_obj = {
            "id": package_id,
            "sender": sender_id,
            "initials": sender_id[:2].upper(),
            "tag": "",
            "time": "just now",
            "status": "pending",
            "verified": True,
            "passwordRequired": bool(requirements.get("password")),
            "passwordVerified": False,
            "timeRestricted": False,
            "withinAllowedWindow": True,
            "files": [{"name": file_name or "transfer", "size": file_size or "unknown", "type": (file_type or "").split("/")[-1].upper() or "FILE"}],
            "options": [],
            "maxViews": requirements.get("max_views"),
            "viewCount": 0
        }
        await send_json(receiver_session.websocket, {"type": "incoming_transfer", "transfer": transfer_obj})

def validate_receiver_against_requirements(
    receiver_metadata: Dict[str, Any],
    requirements: Dict[str, Any],
    ws_ip: str = None
) -> tuple[bool, str | None]:
    for field_name, expected_value in requirements.items():
 
        # TALUS-231 time-of-day: use server clock
        if field_name == "hour_range":
            server_hour = datetime.now(timezone.utc).hour
            if isinstance(expected_value, dict):
                min_hour = expected_value.get("min", 0)
                max_hour = expected_value.get("max", 23)
                if not (min_hour <= server_hour <= max_hour):
                    return False, f"Access denied: outside allowed time window ({min_hour}:00–{max_hour}:00 UTC, current hour is {server_hour}:00 UTC)"
            continue
        if field_name == "password" and expected_value:
            required_hash = requirements.get("password_hash")
            provided_hash = receiver_metadata.get("password_hash")
            if not provided_hash or provided_hash != required_hash:
                return False, "incorrect_password"
            continue
        if field_name == "password_hash":
            continue
 
        # TALUS-232 IP address: use WebSocket connection IP
        if field_name == "ip_address":
            if expected_value is not None and ws_ip is not None:
                if ws_ip != expected_value:
                    return False, "Access denied: your IP address is not permitted"
            continue
 
        # All other fields are sender-side policy flags (limited_access, max_views,
        # track_views, watermark, device_cert, ip_filter, time_of_day, etc.).
        # They are enforced elsewhere (view count, DB checks) — skip here.
        continue

    return True, None

# TALUS-194: Detect if incoming is file access request
def is_file_access_request(data: dict) -> tuple[bool, str | None]:
    for field in ("receiver_id", "package_id", "encrypted_receiver_metadata_b64"):
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            return False, f"Missing or empty required field: '{field}'"
    package = packages.get(data["package_id"])
    if package is None:
        return False, f"Unknown package_id: '{data['package_id']}'"
    pkg_receiver = package.receiver_id.split('#')[0] if '#' in package.receiver_id else package.receiver_id
    if pkg_receiver != data["receiver_id"]:
        return False, f"receiver_id '{data['receiver_id']}' is not authorized for this package"
    return True, None
    
async def handle_log_transfer_view(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    await send_json(ws, {"type": "log_transfer_view_ack"})


async def handle_transfer_response(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    package_id = data.get("transfer_id")
    decision   = data.get("decision")
    if package_id and package_id in packages:
        if decision == "declined":
            packages[package_id].delivered = True
        elif decision == "accepted":
            packages[package_id].accepted = True
    await send_json(ws, {"type": "transfer_response_ack"})

async def handle_delete_transfer(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    package_id = data.get("package_id")
    if not package_id:
        await send_json(ws, {"type": "error", "message": "Missing package_id."})
        return

    packages.pop(package_id, None)

    try:
        db.delete_file_policy(package_id)
        db.delete_file(package_id)
    except Exception:
        logging.exception("Failed to delete package_id=%s from DB", package_id)

    logging.info("Deleted package_id=%s", package_id)
    await send_json(ws, {"type": "delete_transfer_ack", "package_id": package_id})


async def handle_verify_file_password(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    receiver_id = data.get("receiver_id", "")
    package_id  = data.get("package_id", "")

    package = packages.get(package_id)
    if not package:
        await send_json(ws, {"type": "verify_file_password_ack", "valid": False})
        return

    requirements = package.parsed_requirements or {}
    if not requirements.get("password"):
        await send_json(ws, {"type": "verify_file_password_ack", "valid": True})
        return

    session_key = receiver_session_keys.get(receiver_id)
    if not session_key:
        await send_json(ws, {"type": "error", "message": "No session key found."})
        return

    try:
        receiver_metadata = json.loads(
            aes_gcm_decrypt(session_key, decode_b64(data["encrypted_receiver_metadata_b64"])).decode("utf-8")
        )
    except Exception:
        await send_json(ws, {"type": "verify_file_password_ack", "valid": False})
        return

    required_hash = requirements.get("password_hash", "")
    provided_hash = receiver_metadata.get("password_hash", "")
    valid = bool(provided_hash and provided_hash == required_hash)
    await send_json(ws, {"type": "verify_file_password_ack", "valid": valid})

async def handle_request_file_access(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    valid, reason = is_file_access_request(data)
    if not valid:
        logging.warning("Rejected file access request: %s", reason)
        await send_json(ws, {"type": "error", "message": reason})
        return
 
    receiver_id = data["receiver_id"]
    package_id  = data["package_id"]
    package = packages[package_id]  # guaranteed to exist after gate
 
    if receiver_id not in receiver_session_keys:
        await send_json(ws, {"type": "error", "message": "No server-receiver session key found"})
        return
 
    session_key = receiver_session_keys[receiver_id]
 
    try:
        receiver_metadata = json.loads(
            aes_gcm_decrypt(session_key, decode_b64(data["encrypted_receiver_metadata_b64"])).decode("utf-8")
        )
    except Exception:
        logging.exception("Failed to decrypt receiver metadata")
        await send_json(ws, {"type": "error", "message": "Could not decrypt receiver metadata."})
        return
 
    requirements = package.parsed_requirements or {}
    max_views = requirements.get("max_views")
    if max_views is not None:
        try:
            if package.view_count >= int(max_views):
                logging.info("Access denied for package_id=%s: max_views (%s) reached", package_id, max_views)
                error_payload = {"status": "denied", "failed_field": "max_views", "message": "Access limit reached."}
                await send_json(ws, {
                    "type": "authorization_denied",
                    "encrypted_error_b64": encode_b64(aes_gcm_encrypt(session_key, json.dumps(error_payload).encode()))
                })
                return
        except (TypeError, ValueError):
            pass

    # TALUS-233 Check access count from AccessLog
    if "access_count" in requirements and requirements["access_count"] is not None:
        current_count = db.get_access_count(package_id)
        if current_count >= requirements["access_count"]:
            await send_json(ws, {
                "type": "authorization_denied",
                "encrypted_error_b64": encode_b64(aes_gcm_encrypt(
                    session_key,
                    json.dumps({
                        "status": "denied",
                        "failed_field": "access_count",
                        "message": f"Access denied: file has reached its maximum view limit ({requirements['access_count']} views)"
                    }).encode("utf-8")
                ))
            })
            return

    # TALUS-232 - Get IP from websocket
    ws_ip = ws.remote_address[0] if ws.remote_address else None

    # TALUS-231, 232, 234
    allowed, failed_field = validate_receiver_against_requirements(
        receiver_metadata,
        requirements,
        ws_ip=ws_ip
    )

    access_status = "granted" if allowed else f"denied:{failed_field}"

    log_detail = json.dumps({
        "sender_id":    package.sender_id,
        "receiver_id":  receiver_id,
        "file_name":    package.file_name,
        "file_size":    package.file_size,
        "file_type":    package.file_type,
        "send_options": package.parsed_requirements or {},
        "access_status": access_status,
        "timestamp":    datetime.now(timezone.utc).isoformat()
    })
    try:
        db.insert_access_log(
            log_id=str(uuid.uuid4()),
            user_id=db.get_user_id(receiver_id) or receiver_id,
            file_id=package_id,
            access_attempts=1,
            timestamps=datetime.now(timezone.utc),
            ip_address=ws_ip,
            access_status=log_detail
        )
    except Exception:
        logging.exception("insert_access_log failed for package_id=%s", package_id)
 
    logging.info(
        "Access request package_id=%s receiver_id=%s allowed=%s",
        package_id, receiver_id, allowed
    )
 
    if allowed:
        await send_json(ws, {
            "type": "authorized_file_delivery",
            "package_id": package_id,
            "encrypted_file_b64": package.encrypted_file_b64,
            "encrypted_file_key_b64": package.encrypted_file_key_b64
        })
        package.view_count += 1
    else:
        # TALUS-234 — human-readable denial reason
        error_payload = {
            "status": "denied",
            "failed_field": failed_field,
            "message": failed_field  # already a human-readable string from validate_receiver_against_requirements
        }
        encrypted_error = aes_gcm_encrypt(session_key, json.dumps(error_payload).encode("utf-8"))
        await send_json(ws, {
            "type": "authorization_denied",
            "encrypted_error_b64": encode_b64(encrypted_error)
        })
 
async def client_handler(ws: WebSocketServerProtocol) -> None:
    logging.info("Client connected")

    try:
        async for message in ws:
            await handle_message(ws, message)

    except websockets.ConnectionClosed:
        logging.info("Client disconnected")

    finally:
        # Clean up disconnected sessions
        disconnected_ids = [
            client_id
            for client_id, session in connected_clients.items()
            if session.websocket == ws
        ]
        for client_id in disconnected_ids:
            connected_clients.pop(client_id, None)
            logging.info("Cleaned session for client_id=%s", client_id)

async def handle_message(ws: WebSocketServerProtocol, raw_message: str) -> None:
    try:
        msg_type, data = parse_packet(raw_message)

        if msg_type == "register":
            await handle_register(ws, data)
        elif msg_type == "get_server_public_key":
            await handle_get_server_public_key(ws, data)
        elif msg_type == "publish_public_key":
            await handle_publish_public_key(ws, data)
        elif msg_type == "request_peer_public_key":
            await handle_request_peer_public_key(ws, data)
        elif msg_type == "create_session_key":
            await handle_create_session_key(ws, data)
        elif msg_type == "get_incoming_transfers":
            await handle_get_incoming_transfers(ws, data)
        elif msg_type == "upload_package":
            await handle_upload_package(ws, data)
        elif msg_type == "log_transfer_view":
            await handle_log_transfer_view(ws, data)
        elif msg_type == "transfer_response":
            await handle_transfer_response(ws, data)
        elif msg_type == "delete_transfer":
            await handle_delete_transfer(ws, data)
        elif msg_type == "request_file_access":
            await handle_request_file_access(ws, data)
        elif msg_type == "verify_file_password":
            await handle_verify_file_password(ws, data)
        elif msg_type == "check_user":
            await handle_check_user(ws, data)
        elif msg_type == "create_account":
            await handle_create_account(ws, data)
        elif msg_type == "login":
            await handle_login(ws, data)
        elif msg_type == "verify_email":
            await handle_verify_email(ws, data)
        elif msg_type == "resend_verification":
            await handle_resend_verification(ws, data)
        elif msg_type == "session_clear":
            pass
        elif msg_type == "get_logs":
            await handle_get_logs(ws, data)
        else:
            await send_json(ws, {
                "type": "error",
                "message": f"Unknown message type '{msg_type}'"
            })


    except ValueError as ve:
        await send_json(ws, {"type": "error", "message": str(ve)})
    except Exception as exc:
        logging.exception("Message handling failed")
        try:
            await send_json(ws, {"type": "error", "message": str(exc)})
        except Exception:
            pass

def build_ssl_context() -> ssl.SSLContext:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)
    return ssl_context

async def main() -> None:
    schema = Schema()
    schema.run()

    generate_rsa_keypair_if_missing()

    ssl_context = build_ssl_context()

    async with websockets.serve(
        client_handler,
        HOST,
        PORT,
        ssl=ssl_context
    ):
        logging.info("Secure websocket server running on wss://%s:%s", HOST, PORT)
        await asyncio.Future()
if __name__ == "__main__":
    asyncio.run(main())
