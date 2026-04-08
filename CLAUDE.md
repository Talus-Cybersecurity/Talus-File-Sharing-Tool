# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Talus is a context-aware, policy-driven file sharing system using a **secure middle-man architecture**. The server enforces access policies without ever seeing plaintext files or decryption keys (zero-knowledge). AES-256 encrypts files client-side; RSA-2048 handles key exchange; Argon2id hashes passwords.

## Setup & Running

**Install dependencies:**
```bash
pip install pycryptodome argon2-cffi websockets psycopg2-binary python-dotenv cryptography
```

**Database:** Requires a local PostgreSQL instance. Create a `.env` file:
```
DB_HOST = localhost
DB_NAME = talus_db
DB_USER = <user>
DB_PASSWORD = <password>
DB_PORT = 5432
```

**Start the server:**
```bash
python server.py
```
Listens on `wss://0.0.0.0:8765`. On first run, generates an RSA keypair (`server_private.pem`, `server_public.pem`) and initializes the database schema.

**Run tests:**
```bash
python test.py
```
`test.py` is a WebSocket client that exercises the account creation handshake.

## Architecture

### Communication Protocol
All communication is over secure WebSocket (WSS). Messages are JSON with a `type` field and `payload`. Key message types:

| Type | Direction | Purpose |
|------|-----------|---------|
| `create_account` | Client→Server | Register new user |
| `register` | Client→Server | Authenticate existing user |
| `get_server_public_key` | Client→Server | Fetch server's RSA public key |
| `publish_public_key` | Client→Server | Client uploads its RSA public key |
| `create_session_key` | Client→Server | Establish encrypted session key |
| `upload_package` | Sender→Server | Upload encrypted file + access policy |
| `request_file_access` | Receiver→Server | Request decryption key for a file |
| `authorized_file_delivery` | Server→Receiver | Deliver decryption key if policy passes |

### Key Components

**`server.py`** — Async WebSocket server (asyncio + websockets). Maintains in-memory state:
- `connected_clients` — maps websocket → `ClientSession`
- `public_keys` — maps client_id → RSA public key
- `sender_session_keys` / `receiver_session_keys` — per-client AES session keys
- `packages` — in-flight file packages awaiting delivery

**`Cryptography.py`** — Crypto utilities: AES-256-CBC encrypt/decrypt, RSA-2048 OAEP encrypt/decrypt, Argon2id password hashing/verification.

**`backend/schema.py`** — Connects to PostgreSQL and creates tables: `User`, `File`, `AccessLog`, `FilePolicy`.

**`backend/database.py`** — `Database` class wrapping psycopg2 for parameterized query execution.

**`Frontend.html`** — Single-file SPA with Send/Receive tabs. Connects to the WSS server directly from the browser.

### Access Policy Enforcement
When a receiver requests a file, `server.py` checks `FilePolicy` against: IP address, device certification, time-of-day restrictions, and authentication status. Only if all conditions pass does the server release the AES session key to the receiver.

### SSL Certificates
`cert.pem` and `key.pem` are the TLS cert/key for the WebSocket server. `server_private.pem` / `server_public.pem` are the server's RSA keypair for key exchange (separate from TLS).
