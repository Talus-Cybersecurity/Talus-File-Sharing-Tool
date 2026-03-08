from Crypto.PublicKey import RSA

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