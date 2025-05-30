import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

# Constants
SALT_SIZE = 16 # Size of random salt (in bytes)
NONCE_SIZE = 12  # Size of nonce for AES-GCM
ITERATIONS = 600000 # PBKDF2 iterations (NIST recommended)
CHUNK_SIZE = 1024 * 1024  # Process files in 1MB chunks

class FileEncryptor:
    @staticmethod
    def _derive_key(password: bytes, salt: bytes) -> bytes:
        """Derive a secure encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # 256-bit key
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password)

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, password: str) -> None:
        """Encrypt a file using AES-GCM 256-bit encryption"""
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        key = FileEncryptor._derive_key(password.encode('utf-8'), salt)

        aesgcm = AESGCM(key)

        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write salt and nonce to output file
            outfile.write(salt)
            outfile.write(nonce)

            # Process file in chunks
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    break
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                outfile.write(encrypted_chunk)

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, password: str) -> bool:
        """Decrypt a file with authentication check"""
        try:
            with open(input_path, 'rb') as infile:
                # Read salt and nonce from input file
                salt = infile.read(SALT_SIZE)
                nonce = infile.read(NONCE_SIZE)
                key = FileEncryptor._derive_key(password.encode('utf-8'), salt)

                aesgcm = AESGCM(key)

                with open(output_path, 'wb') as outfile:
                    # Process file in chunks
                    while True:
                        chunk = infile.read(CHUNK_SIZE + 16)  # GCM adds 16 bytes tag
                        if not chunk:
                            break
                        decrypted_chunk = aesgcm.decrypt(nonce, chunk, None)
                        outfile.write(decrypted_chunk)
            return True
        except Exception as e:
            # Authentication failed or other error
            if os.path.exists(output_path):
                os.remove(output_path)  # Cleanup partial output
            raise e

# Add this to make the class available when importing
__all__ = ['FileEncryptor']