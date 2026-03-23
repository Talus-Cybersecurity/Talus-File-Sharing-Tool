import asyncio
import logging
import os
import base64
import json
import websockets
from websockets.server import WebSocketServerProtocol

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from typing import Any, Dict, Optional

import secrets
import ssl
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.fernet import Fernet

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
    parsed_requirements: Optional[Dict[str, Any]] = None
    uploaded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    delivered: bool = False


connected_clients: Dict[str, ClientSession] = {}
public_keys: Dict[str, str] = {}
sender_session_keys: Dict[str, bytes] = {}
receiver_session_keys: Dict[str, bytes] = {}
packages: Dict[str, FilePackage] = {}


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

def generate_symmetric_key() -> bytes:
    return Fernet.generate_key()


def fernet_encrypt(key: bytes, plaintext: bytes) -> bytes:
    return Fernet(key).encrypt(plaintext)


def fernet_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return Fernet(key).decrypt(ciphertext)

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

async def handle_upload_package(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    sender_id = data["sender_id"]
    receiver_id = data["receiver_id"]
    encrypted_file_b64 = data["encrypted_file_b64"]
    encrypted_requirements_b64 = data["encrypted_requirements_b64"]

    # Requirements are encrypted for the server per assignment design.
    decrypted_requirements = rsa_decrypt_with_server_private_key(
        decode_b64(encrypted_requirements_b64)
    )

    requirements = json.loads(decrypted_requirements.decode("utf-8"))

    package_id = str(uuid.uuid4())
    packages[package_id] = FilePackage(
        package_id=package_id,
        sender_id=sender_id,
        receiver_id=receiver_id,
        encrypted_file_b64=encrypted_file_b64,
        encrypted_requirements_b64=encrypted_requirements_b64,
        parsed_requirements=requirements
    )

    logging.info(
        "Stored package_id=%s sender=%s receiver=%s",
        package_id, sender_id, receiver_id
    )

    await send_json(ws, {
        "type": "upload_package_ack",
        "package_id": package_id
    })



def validate_receiver_against_requirements(
    receiver_metadata: Dict[str, Any],
    requirements: Dict[str, Any]
) -> tuple[bool, Optional[str]]:
    for field_name, expected_value in requirements.items():
        if field_name not in receiver_metadata:
            return False, field_name

        actual_value = receiver_metadata[field_name]

        if isinstance(expected_value, dict):
            # Example structure:
            # "hour_range": {"min": 8, "max": 17}
            if "min" in expected_value and actual_value < expected_value["min"]:
                return False, field_name
            if "max" in expected_value and actual_value > expected_value["max"]:
                return False, field_name
        else:
            if actual_value != expected_value:
                return False, field_name

    return True, None

async def handle_request_file_access(ws: WebSocketServerProtocol, data: Dict[str, Any]) -> None:
    receiver_id = data["receiver_id"]
    package_id = data["package_id"]
    encrypted_receiver_metadata_b64 = data["encrypted_receiver_metadata_b64"]

    package = packages.get(package_id)
    if not package:
        await send_json(ws, {
            "type": "error",
            "message": f"Unknown package '{package_id}'"
        })
        return

    if package.receiver_id != receiver_id:
        await send_json(ws, {
            "type": "error",
            "message": "Receiver is not authorized for this package"
        })
        return

    if receiver_id not in receiver_session_keys:
        await send_json(ws, {
            "type": "error",
            "message": "No server-receiver session key found"
        })
        return

    session_key = receiver_session_keys[receiver_id]

    receiver_metadata = json.loads(
        fernet_decrypt(session_key, decode_b64(encrypted_receiver_metadata_b64)).decode("utf-8")
    )

    allowed, failed_field = validate_receiver_against_requirements(
        receiver_metadata,
        package.parsed_requirements or {}
    )

    logging.info(
        "Access request package_id=%s receiver_id=%s allowed=%s failed_field=%s",
        package_id, receiver_id, allowed, failed_field
    )

    if allowed:
        await send_json(ws, {
            "type": "authorized_file_delivery",
            "package_id": package_id,
            "encrypted_file_b64": package.encrypted_file_b64
        })
        package.delivered = True
    else:
        error_payload = {
            "status": "denied",
            "failed_field": failed_field,
            "message": "Receiver metadata did not satisfy sender requirements."
        }

        encrypted_error = fernet_encrypt(
            session_key,
            json.dumps(error_payload).encode("utf-8")
        )

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
        data = parse_json(raw_message)
        msg_type = data.get("type")

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
        elif msg_type == "upload_package":
            await handle_upload_package(ws, data)
        elif msg_type == "request_file_access":
            await handle_request_file_access(ws, data)
        else:
            await send_json(ws, {
                "type": "error",
                "message": f"Unknown message type '{msg_type}'"
            })

    except Exception as exc:
        logging.exception("Message handling failed")
        await send_json(ws, {
            "type": "error",
            "message": str(exc)
        })

async def main() -> None:
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