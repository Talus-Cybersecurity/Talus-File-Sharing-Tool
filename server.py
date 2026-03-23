import asyncios
import logging
import os
import base64
import json
import websockets
from websockets.server import WebSocketServerProtocol



HOST = "0.0.0.0"
PORT = 8765


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


    if __name__ == "__main__":
    asyncio.run(main())