import asyncio
import websockets
import json
import ssl

async def test_create_account():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    ws = await websockets.connect("wss://localhost:8765", ssl=ssl_context)
    
    await ws.send(json.dumps({
        "type": "create_account",
        "username": "michelle",
        "email": "michelle@email.com",
        "password": "talus2026",
        "tag_id": "4821"
    }))

    response = await ws.recv()
    print("Server response:", response)
    
    await ws.close()

asyncio.run(test_create_account())