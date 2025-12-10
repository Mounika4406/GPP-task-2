import base64
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key():
    """
    Load RSA private key from student_private.pem
    """
    with open("student_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256)
    Returns 64-character hex string.
    """

    # 1. Base64 decode the encrypted seed string
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # 2. RSA/OAEP decrypt with SHA-256
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Decode bytes to UTF-8 string
    hex_seed = plaintext_bytes.decode("utf-8").strip()

    # 4. Validate: must be 64-character hex string
    if len(hex_seed) != 64:
        raise ValueError(f"Decrypted seed must be 64 chars, got {len(hex_seed)}")

    allowed = set("0123456789abcdef")
    if not all(c in allowed for c in hex_seed):
        raise ValueError("Decrypted seed is not valid lowercase hex")

    # 5. Return hex seed
    return hex_seed


def main():
    # Read encrypted seed
    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed_b64 = f.read().strip()

    private_key = load_private_key()
    hex_seed = decrypt_seed(encrypted_seed_b64, private_key)

    print("✅ Decrypted hex seed:", hex_seed)

    # Store at data/seed.txt (in container this will be /data/seed.txt)
    os.makedirs("data", exist_ok=True)
    with open(os.path.join("data", "seed.txt"), "w") as f:
        f.write(hex_seed)

    print("✅ Seed written to data/seed.txt")


if __name__ == "__main__":
    main()
