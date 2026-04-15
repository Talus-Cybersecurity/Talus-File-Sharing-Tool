import asyncio
#import ssl
import json
import base64

import websockets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

def encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def decode_b64(data: str) -> bytes:
    return base64.b64decode(data.encode())

def make_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, private_pem, public_pem

async def main():
    #ssl_context = ssl._create_unverified_context()

    sender_private, _, sender_public = make_rsa_keypair()

    async with websockets.connect("ws://localhost:8765") as ws:
        await ws.send(json.dumps({
            "type": "register",
            "client_id": "sender1",
            "role": "sender",
            "public_key_pem": sender_public
        }))
        print(await ws.recv())

        await ws.send(json.dumps({
            "type": "get_server_public_key"
        }))
        server_pub_msg = json.loads(await ws.recv())
        print(server_pub_msg)

        server_public_key = serialization.load_pem_public_key(
            server_pub_msg["public_key_pem"].encode()
        )

        requirements = {
            "os": "Windows",
            "ram_gb": {"min": 16, "max": 64}
        }

        encrypted_requirements = server_public_key.encrypt(
            json.dumps(requirements).encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        fake_file_key = Fernet.generate_key()
        fake_file_cipher = Fernet(fake_file_key).encrypt(b"secret file contents")

        await ws.send(json.dumps({
            "type": "upload_package",
            "sender_id": "sender1",
            "receiver_id": "receiver1",
            "encrypted_file_b64": encode_b64(fake_file_cipher),
            "encrypted_requirements_b64": encode_b64(encrypted_requirements)
        }))
        print(await ws.recv())

asyncio.run(main())