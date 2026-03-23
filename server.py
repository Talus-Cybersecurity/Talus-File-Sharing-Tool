import asyncios

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
        #public_keys[client_id] = public_key_pem

    #logging.info("Registered client_id=%s role=%s", client_id, role)

    await send_json(ws, {
        "type": "register_ack",
        "client_id": client_id,
        "role": role,
        "server_time": now_iso()
    })


    if __name__ == "__main__":
    asyncio.run(main())