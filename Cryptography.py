from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import base64

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