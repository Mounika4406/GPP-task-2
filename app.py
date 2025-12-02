import base64
import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from totp_utils import generate_totp_code, verify_totp_code


app = FastAPI()

# In the container this will be /data/seed.txt (as per spec)
SEED_PATH = Path("/data/seed.txt")

# For local development, fall back to ./data/seed.txt
LOCAL_SEED_PATH = Path("data") / "seed.txt"


def get_seed_path() -> Path:
    """Use /data/seed.txt if it exists or is writable, otherwise use local data/seed.txt."""
    # If running in container, /data will exist/mounted
    if SEED_PATH.parent.exists():
        return SEED_PATH
    # Local dev fallback
    LOCAL_SEED_PATH.parent.mkdir(exist_ok=True)
    return LOCAL_SEED_PATH


def load_private_key():
    """Load RSA private key from student_private.pem."""
    with open("student_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP-SHA256.
    Returns 64-character hex string.
    """
    # 1. Base64 decode
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # 2. RSA/OAEP decrypt
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Decode to UTF-8
    hex_seed = plaintext_bytes.decode("utf-8").strip()

    # 4. Validate 64-char hex
    if len(hex_seed) != 64:
        raise ValueError(f"Decrypted seed must be 64 chars, got {len(hex_seed)}")

    allowed = set("0123456789abcdef")
    if not all(c in allowed for c in hex_seed):
        raise ValueError("Decrypted seed is not valid lowercase hex")

    return hex_seed


# ---------- Request/Response Models ----------

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class Verify2FARequest(BaseModel):
    code: str | None = None


# ---------- Endpoint 1: POST /decrypt-seed ----------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(body: DecryptSeedRequest):
    """
    1) Load private key
    2) Base64 decode encrypted_seed
    3) Decrypt using RSA/OAEP-SHA256
    4) Validate 64-char hex
    5) Save to /data/seed.txt (or local fallback)
    6) Return {"status": "ok"}
    """
    try:
        private_key = load_private_key()
        hex_seed = decrypt_seed(body.encrypted_seed, private_key)

        seed_path = get_seed_path()
        seed_path.write_text(hex_seed)

        return {"status": "ok"}
    except Exception as e:
        # Log error (for debugging), but don’t expose full details in production
        print("Decryption failed:", e)
        return JSONResponse(
            status_code=500,
            content={"error": "Decryption failed"},
        )


# ---------- Endpoint 2: GET /generate-2fa ----------

@app.get("/generate-2fa")
def generate_2fa():
    """
    1) Check if /data/seed.txt exists
    2) Read hex seed
    3) Generate TOTP code
    4) Calculate remaining seconds in current 30s period
    5) Return {"code": "123456", "valid_for": 30}
    """
    seed_path = get_seed_path()
    if not seed_path.exists():
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    try:
        hex_seed = seed_path.read_text().strip()
        code = generate_totp_code(hex_seed)

        # Period is 30 seconds; calculate remaining seconds in current period
        period = 30
        now = int(time.time())
        remaining = period - (now % period)

        return {
            "code": code,
            "valid_for": remaining,
        }
    except Exception as e:
        print("Error generating 2FA code:", e)
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )


# ---------- Endpoint 3: POST /verify-2fa ----------

@app.post("/verify-2fa")
def verify_2fa(body: Verify2FARequest):
    """
    1) Validate 'code' is provided
    2) Check if /data/seed.txt exists
    3) Read hex seed
    4) Verify TOTP code with ±1 period tolerance
    5) Return {"valid": true/false} or errors
    """
    if body.code is None or body.code == "":
        return JSONResponse(
            status_code=400,
            content={"error": "Missing code"},
        )

    seed_path = get_seed_path()
    if not seed_path.exists():
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    try:
        hex_seed = seed_path.read_text().strip()
        is_valid = verify_totp_code(hex_seed, body.code, valid_window=1)
        return {"valid": bool(is_valid)}
    except Exception as e:
        print("Error verifying 2FA code:", e)
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )
