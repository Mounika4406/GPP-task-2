import requests


def request_seed(student_id: str, github_repo_url: str, api_url: str):
    # 1. Read student public key exactly as PEM (with real newlines)
    with open("student_public.pem", "r") as f:
        public_key_pem = f.read()

    # ✅ Do NOT replace newlines, send PEM as-is
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_pem,
    }

    headers = {"Content-Type": "application/json"}

    # 3. Send POST request (requests will handle JSON encoding correctly)
    response = requests.post(api_url, json=payload, headers=headers, timeout=30)

    print("----- RAW API RESPONSE -----")
    print(response.text)
    print("----------------------------")

    # 4. Parse JSON response
    try:
        data = response.json()
    except Exception:
        print("❌ API did not return JSON")
        return

    if "encrypted_seed" not in data:
        print("❌ Error from API:")
        print(data)
        return

    encrypted_seed = data["encrypted_seed"]

    # 5. Save encrypted seed to file
    with open("encrypted_seed.txt", "w") as f:
        f.write(encrypted_seed)

    print("✅ Encrypted seed saved to encrypted_seed.txt")


if __name__ == "__main__":
    API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
    STUDENT_ID = "23mh1a4406"
    GITHUB_REPO_URL = "https://github.com/Mounika4406/GPP-task-2.git"

    request_seed(STUDENT_ID, GITHUB_REPO_URL, API_URL)
