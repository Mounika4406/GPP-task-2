import base64
import pyotp


def _hex_seed_to_base32(hex_seed: str) -> str:
    """
    Helper: convert 64-char hex seed to base32 string
    """
    # 1. Convert hex to bytes
    seed_bytes = bytes.fromhex(hex_seed)

    # 2. Convert bytes to base32 (returns bytes)
    base32_bytes = base64.b32encode(seed_bytes)

    # 3. Convert to string
    base32_str = base32_bytes.decode("utf-8")

    return base32_str


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed

    Args:
        hex_seed: 64-character hex string

    Returns:
        6-digit TOTP code as string
    """
    # Convert hex seed to base32
    base32_seed = _hex_seed_to_base32(hex_seed)

    # Create TOTP object (SHA-1, 30s period, 6 digits by default)
    totp = pyotp.TOTP(base32_seed)

    # Generate current code
    code = totp.now()

    # Ensure it's 6 characters, zero-padded if needed
    return code.zfill(6)


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance

    Args:
        hex_seed: 64-character hex string
        code: 6-digit code to verify
        valid_window: number of periods before/after to accept (default 1 = ±30s)

    Returns:
        True if code is valid, False otherwise
    """
    base32_seed = _hex_seed_to_base32(hex_seed)

    totp = pyotp.TOTP(base32_seed)

    # valid_window = 1 means current time slice ±1 → ±30 seconds
    return totp.verify(code, valid_window=valid_window)
