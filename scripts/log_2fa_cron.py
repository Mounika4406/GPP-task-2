#!/usr/bin/env python3

import os
import datetime
import pytz
from totp_utils import generate_totp_code

def main():
    seed_path = "/data/seed.txt"

    # 1. Read hex seed
    if not os.path.exists(seed_path):
        print("Seed file not found. Cannot generate 2FA code.")
        return

    try:
        with open(seed_path, "r") as f:
            hex_seed = f.read().strip()
    except Exception as e:
        print("Error reading seed:", e)
        return

    # 2. Generate TOTP
    try:
        code = generate_totp_code(hex_seed)
    except Exception as e:
        print("TOTP generation error:", e)
        return

    # 3. UTC timestamp
    timestamp = datetime.datetime.now(pytz.utc).strftime("%Y-%m-%d %H:%M:%S")

    # 4. Output
    print(f"{timestamp} - 2FA Code: {code}")

if __name__ == "__main__":
    main()
