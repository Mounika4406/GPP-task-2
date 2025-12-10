import os
import base64
from typing import Optional
from subprocess import run, PIPE

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature

# --- Configuration Paths and Placeholders ---
PRIVATE_KEY_PATH = "student_private.pem"

# NOTE: REPLACE THIS ENTIRE STRING WITH THE ACTUAL CONTENT of the instructor_public.pem FILE
# This public key is used for the FINAL encryption step.
INSTRUCTOR_PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAq4QI08D4DNCsJ25uF5eP
tFDGsZMFu6VE79v70vF2xWWgKagN1cKeq9Ty7viOn9bEbi7efo3juWvr8t3fCjyK
7Ab2X3FBSAGtOrGH6EjbNGpsssfMMnpj1rcOdXfXCavdC/cOXuQck+TmZ143CwtY
VyvjaNRjT08028PdW02CC1WYEznWzwSC1MUj873HeYA/7cVg82ViWTy4/DYmL3I6
+kcIgnnnzF4X7yXsuFg8n4dj1J5x9FO/lQZSBYtk7K+rmw7O705x+uGq2Ftd/uHn
wvKzjQ6rqcjFgyDjv4FvwtEPzbkD3C95KijUA8GMu02xGIxegmUp8TRfwbHhC0RN
K0PzC+EDB+MADyceoOHsRq4tQmp8Y85b3qfkF8/JdpWLP8QTa3Qin3EbWjVHPgy3
zzICe0vCiXbuZLCJ22nxZtHDDRAvfWlZ1DT+guGcyyGK4gxL44+5S9DFLJQbk4qz
mBjv1thRrUmG5MwrosqpD7cYaBlRyHKuvq2jaNDEyJd65HeSL9rDZHCzPL4a+Ejz
RSvPmS9Vmel3mNRE9JZiuaSOggYEDVy6dVURO0ZOWpfMwxfkxdrX/iNzmTldQww4
pxCFXJOflmdSlfNsnOcfVYHgSZyePqOdq8zmZ6GZAIKMTsrn/k/of2aQtgWGUQWA
Azya3uyI1IPHsBL4yKqYK7Z/dHPdwAapGoZGN2XZafY0ihezXpm/fvD7JqlRbC2V
co9bZeJLuU85EnGabjD857dWiDz4QnIFT8yAZj10BPX2Xb52hZdBZtdOBe1Klm6b
iF79Ho38IYavyshAUHYmS3d/137XUknsFN2BogWnPSrrLM9PsuiEvC6uR7N6ywuV
P7Me81GpUgViNHsVOQ0hRD3m/ZqTA5rgRqRN6FITMSihYSGx7DZzFrhFwThQiTf0
U2bzTuDsOgYXy8Nj/fMvoxd5JzrxDDmFB1+Nt82sFoGQ2/Bj7Lvh2efoESFcr5ji
eYApZPIgen3wMU+ms19jOuarR/hID7pLs3hGbHqRgis0vVISrK9K7oFcHjgnBN7X
m54cF6AaFv5/U4sKSQ+MoEMDGolfjDiWiDnCdPbmcmfeFs2cQY9otNCsh1oM8q1l
GnPx4cGkHNf9LgKBcS0HBp0pWfMK1P+QydPkBSU03MMQv5KbfCInHAcvg+IAVe9P
LRq3XufZiLqU/FnNKmDSJmnkm2lEvM9eqJSp7aJvyfQFkiRoLbKRBcGBOrlKxFVq
HkaZqZe72r+D15SFM5o1wOyc+xvq6TLW3kaSE/XlGBY1fPP2T8dAjLZRz3jhzkFM
d8KiQ4BRU9F/QNCok7s+em1eX4rlrMjlYOvx3PjPsNYECdFJl9F8klPwRt7vXrI9
vQIDAQAB
-----END PUBLIC KEY-----
""" # Placeholder value. You MUST replace this with the instructor's key.

# --- Helper Functions ---

def load_private_key(filepath: str = PRIVATE_KEY_PATH) -> Optional[rsa.RSAPrivateKey]:
    """Loads the student's RSA private key from the PEM file."""
    if not os.path.exists(filepath):
        print(f"Error: Private key file not found at {filepath}")
        return None
        
    try:
        with open(filepath, "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None, # Key was generated without a password
            )
        return private_key
    except Exception as e:
        print(f"Error loading student private key: {e}")
        return None

def load_instructor_public_key(pem_content: str) -> Optional[rsa.RSAPublicKey]:
    """Loads the instructor's RSA public key from the PEM content string."""
    try:
        public_key = serialization.load_pem_public_key(pem_content.encode('utf-8'))
        return public_key
    except Exception as e:
        print(f"Error loading instructor public key from placeholder content: {e}")
        return None
    
def get_commit_hash() -> Optional[str]:
    """Runs 'git log -1 --format=%H' to get the latest commit hash."""
    try:
        # Run the git command
        result = run(['git', 'log', '-1', '--format=%H'], capture_output=True, text=True, check=True)
        commit_hash = result.stdout.strip()
        
        if len(commit_hash) == 40 and all(c in '0123456789abcdef' for c in commit_hash):
            print(f"Successfully retrieved commit hash: {commit_hash}")
            return commit_hash
        else:
            print(f"Error: Commit hash format invalid or repository empty. Output: {commit_hash}")
            return None
            
    except Exception as e:
        print(f"Error executing git command. Did you commit all files? Error: {e}")
        return None

def sign_message(message: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256 (Required for the signature).
    """
    # 1. Encode commit hash as ASCII/UTF-8 bytes (CRITICAL: signing the string value)
    message_bytes = message.encode('utf-8')
    
    # 2. Sign using RSA-PSS with SHA-256
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH # Salt Length: Maximum
        ),
        hashes.SHA256()
    )
    
    return signature

def encrypt_with_public_key(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt data (the signature bytes) using RSA/OAEP with public key (Required for encryption).
    """
    # 1. Encrypt signature bytes using RSA/OAEP with SHA-256
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return ciphertext

# --- Main Proof Generation Logic ---

def generate_commit_proof():
    """Performs all steps: get hash, sign, encrypt, and base64 encode."""
    
    # 1. Get current commit hash (Requires files to be committed)
    commit_hash = get_commit_hash()
    if not commit_hash:
        return

    # 2. Load student private key
    private_key = load_private_key()
    if not private_key:
        return

    # 3. Sign commit hash with student private key
    print(f"\nSigning commit hash with {PRIVATE_KEY_PATH}...")
    signature = sign_message(commit_hash, private_key)
    print(f"Signature generated ({len(signature)} bytes).")

    # 4. Load instructor public key
    public_key = load_instructor_public_key(INSTRUCTOR_PUBLIC_KEY_PEM)
    if not public_key:
        print("\nFATAL ERROR: Instructor Public Key is likely the placeholder.")
        print("Please replace INSTRUCTOR_PUBLIC_KEY_PEM content in the script and try again.")
        return

    # 5. Encrypt signature with instructor public key
    print("\nEncrypting signature with Instructor's Public Key...")
    encrypted_signature = encrypt_with_public_key(signature, public_key)
    
    # 6. Base64 encode encrypted signature
    proof_base64 = base64.b64encode(encrypted_signature).decode('utf-8')

    # --- Output ---
    print("\n=============================================")
    print("        ✅ COMMIT PROOF GENERATED ✅        ")
    print("=============================================")
    print(f"Commit Hash: {commit_hash}")
    print("\nEncrypted Signature (Base64 Proof):")
    print(proof_base64)
    print("\n=============================================")
    print("Submit this Base64 string as your final proof.")


if __name__ == '__main__':
    # Initial setup check
    if INSTRUCTOR_PUBLIC_KEY_PEM.strip() == "":
        print("FATAL ERROR: Please paste the instructor's public key PEM content into the 'INSTRUCTOR_PUBLIC_KEY_PEM' variable inside generate_proof.py.")
    else:
        generate_commit_proof()