from pathlib import Path
from totp_utils import generate_totp_code, verify_totp_code


def main():
    # Load hex seed from data/seed.txt
    seed_path = Path("data") / "seed.txt"
    hex_seed = seed_path.read_text().strip()

    # Generate current TOTP code
    code = generate_totp_code(hex_seed)
    print("Current TOTP code:", code)

    # Optional verification
    is_valid = verify_totp_code(hex_seed, code, valid_window=1)
    print("Verification of generated code:", is_valid)


if __name__ == "__main__":
    main()
