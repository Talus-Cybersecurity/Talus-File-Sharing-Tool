from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import base64
from Crypto.Util.Padding import unpad

def generate_talus_keys(private_key_path, public_key_path):
    """
    Generates a 2048-bit RSA key pair for the Talus tool.
    Saves them to the specified PEM files.
    """
    try:
        # 1. Generate the RSA key (2048-bit)
        key = RSA.generate(2048)

        # 2. Export the Private Key
        # We use PKCS#8 for the private key
        private_key = key.export_key()
        with open(private_key_path, "wb") as f:
            f.write(private_key)

        # 3. Export the Public Key
        public_key = key.publickey().export_key()
        with open(public_key_path, "wb") as f:
            f.write(public_key)

        print(f"Success! Keys saved to {private_key_path} and {public_key_path}")
        
    except Exception as e:
        print(f"An error occurred during key generation: {e}")

def generateSymmetricKey(key_size=32,symmetric_key_path="key.bin"):
    """
    Generating a symmetric key using a key size of 32 bytes
    for AES-256
    """
    try:
        # 1. Generate key using get_random_bytes import
        symmetric_key = get_random_bytes(key_size)    

        # 2. Checks if current key has same key size of 32 bytes
        if symmetric_key and len(symmetric_key) == key_size:                            

            # Write into a key.bin file to export the key into
            with open(symmetric_key_path, "wb") as f:
                f.write(symmetric_key)
            
            print(f"Symmetric key has been generated and saved to {symmetric_key_path}")
            return symmetric_key
           
        
        else:
            print("Symmetric key generation has failed")
            return None
        
    except Exception as e:
        print(f"An error has occurred: {e}")
        return None


def encrypt(message: str, key: bytes) -> dict:
    """
    Encrypts a string message using AES-256-CBC.
    
    Args:
        message: The plaintext string to encrypt.
        key: A 32-byte AES-256 key (e.g., from generateSymmetricKey()).
    
    Returns:
        A dict with 'iv' and 'ciphertext', both base64-encoded strings.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key)}")

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return {
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }


def decrypt(encrypted_payload: dict, key: bytes) -> str:
    """
    Decrypts an AES-256-CBC encrypted payload.
    
    Args:
        encrypted_payload: A dict with 'iv' and 'ciphertext' (base64-encoded strings),
                           as returned by the encrypt() helper.
        key: The same 32-byte AES-256 key used during encryption.
    
    Returns:
        The decrypted plaintext string.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes for AES-256, got {len(key)}")

    if "iv" not in encrypted_payload or "ciphertext" not in encrypted_payload:
        raise ValueError("encrypted_payload must contain 'iv' and 'ciphertext' keys")

    iv = base64.b64decode(encrypted_payload["iv"])
    ciphertext = base64.b64decode(encrypted_payload["ciphertext"])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext.decode('utf-8')

# Testing Section
# key = generateSymmetricKey()  # your existing helper

# payload = encrypt("Hello, Talus!", key)
# # payload -> {"iv": "...", "ciphertext": "..."}

# message = decrypt(payload, key)
# # message -> "Hello, Talus!"


from Crypto.Cipher import PKCS1_OAEP

def encrypt_key_with_rsa(symmetric_key: bytes, public_key_path: str) -> bytes:
    """
    Encrypts a symmetric key using a recipient's RSA public key.
    
    Args:
        symmetric_key: The raw AES key bytes to encrypt.
        public_key_path: Path to the recipient's public key PEM file.
    
    Returns:
        The encrypted key as bytes.
    """
    try:
        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher_rsa.encrypt(symmetric_key)

        return encrypted_key

    except Exception as e:
        print(f"An error occurred during RSA key encryption: {e}")
        return None
    

def decrypt_key_with_rsa(encrypted_key: bytes, private_key_path: str) -> bytes:
    """
    Decrypts an RSA-encrypted symmetric key using a private key.
    
    Args:
        encrypted_key: The encrypted AES key bytes.
        private_key_path: Path to the recipient's private key PEM file.
    
    Returns:
        The decrypted symmetric key as bytes.
    """
    try:
        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(private_key)
        symmetric_key = cipher_rsa.decrypt(encrypted_key)

        return symmetric_key

    except Exception as e:
        print(f"An error occurred during RSA key decryption: {e}")
        return None
    

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Argon2id config — these match OWASP recommended settings
ph = PasswordHasher(
    time_cost=2,        # number of iterations
    memory_cost=65536,  # 64MB in kibibytes
    parallelism=2,      # parallel threads
    hash_len=32,
    salt_len=16
)

def hash_password(password: str) -> str:
    """
    Hashes a password using Argon2id with a random salt.
    
    Args:
        password: The plaintext password string to hash.
    
    Returns:
        The full Argon2id hash string (includes salt and params),
        ready to store directly in the database.
    """
    try:
        hashed = ph.hash(password)
        return hashed

    except Exception as e:
        print(f"An error occurred during password hashing: {e}")
        return None

print("\n")
print(hash_password("hello"))
