from pathlib import Path
from typing import Optional
import base64
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

import pyotp  # make sure this is in requirements.txt


app = FastAPI()

# Paths inside the container
PRIVATE_KEY_PATH = Path("/app/student_private.pem")
SEED_FILE_PATH = Path("/data/seed.txt")


# ---------- Helpers for RSA / seed ----------

def load_student_private_key():
    if not PRIVATE_KEY_PATH.exists():
        raise RuntimeError("Student private key not found at /app/student_private.pem")

    key_data = PRIVATE_KEY_PATH.read_bytes()
    private_key = serialization.load_pem_private_key(key_data, password=None)
    return private_key


def decrypt_seed_from_b64(b64_ciphertext: str) -> str:
    """
    Decrypt base64-encoded ciphertext using the student's private key.

    Returns: 64-character hex seed string.
    """
    try:
        ciphertext = base64.b64decode(b64_ciphertext)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 ciphertext: {e}")

    private_key = load_student_private_key()

    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")

    try:
        hex_seed = plaintext_bytes.decode("utf-8").strip()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decode plaintext as UTF-8: {e}")

    if len(hex_seed) != 64:
        raise HTTPException(status_code=400, detail="Decrypted seed is not a 64-character hex string")

    return hex_seed


def save_seed(hex_seed: str):
    SEED_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SEED_FILE_PATH.write_text(hex_seed)


def load_seed() -> str:
    if not SEED_FILE_PATH.exists():
        raise HTTPException(status_code=500, detail="Seed file not found at /data/seed.txt")

    return SEED_FILE_PATH.read_text().strip()


def make_totp_from_hex_seed(hex_seed: str) -> pyotp.TOTP:
    """
    Convert 64-char hex seed to base32 and create a pyotp.TOTP instance.
    We always use the same logic for generate and verify.
    """
    try:
        seed_bytes = bytes.fromhex(hex_seed)
    except ValueError:
        raise HTTPException(status_code=500, detail="Seed in /data/seed.txt is not valid hex")

    # Convert to base32; remove padding (=) to match typical TOTP secrets
    base32_secret = base64.b32encode(seed_bytes).decode("ascii").rstrip("=")

    # 6 digits, 30-second interval (default TOTP settings)
    return pyotp.TOTP(base32_secret, digits=6, interval=30)


# ---------- Request models ----------

class DecryptSeedRequest(BaseModel):
    encrypted_seed: Optional[str] = None
    ciphertext: Optional[str] = None  # evaluator might use this name


class VerifyRequest(BaseModel):
    code: str


# ---------- Health check ----------

@app.get("/")
def health_check():
    return {"status": "ok"}


# ---------- API endpoints ----------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: DecryptSeedRequest):
    """
    Called by evaluator.
    Decrypts the seed using student_private.pem and stores it in /data/seed.txt
    """
    b64_ciphertext = payload.encrypted_seed or payload.ciphertext
    if not b64_ciphertext:
        raise HTTPException(status_code=400, detail="Missing encrypted_seed/ciphertext field")

    hex_seed = decrypt_seed_from_b64(b64_ciphertext)

    # Persist for later use (and for the evaluator to check /data/seed.txt)
    save_seed(hex_seed)

    return {
        "status": "ok",
        "seed_preview": hex_seed[:8],
        "message": "Seed decrypted and stored at /data/seed.txt",
    }


@app.get("/generate-2fa")
def generate_2fa():
    """
    Generate current TOTP code from persisted seed.
    Returns the code and how many seconds it remains valid.
    """
    hex_seed = load_seed()

    totp = make_totp_from_hex_seed(hex_seed)
    try:
        code = totp.now()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating TOTP code: {e}")

    interval = totp.interval  # 30
    seconds_remaining = int(interval - (time.time() % interval))

    return {"code": code, "valid_for": seconds_remaining}


@app.post("/verify-2fa")
def verify_2fa(payload: VerifyRequest):
    """
    Verify a provided TOTP code against the same seed and parameters
    used by /generate-2fa.
    """
    hex_seed = load_seed()

    totp = make_totp_from_hex_seed(hex_seed)
    try:
        is_valid = totp.verify(payload.code, valid_window=1)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error verifying TOTP code: {e}")

    return {"valid": is_valid}
