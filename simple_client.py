from dotenv import load_dotenv
import os
import httpx

# --- CONFIGURE THESE TWO VALUES ---
ACCOUNT_KEY = "I7k71md8l03w9"          # from test_token.py
FROM_ADDRESS = "justin.lavey@manitec.pw"  # your Mail360 mailbox
# ----------------------------------

BASE_URL = "https://mail360.zoho.com"

load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")


def get_access_token() -> str:
    url = f"{BASE_URL}/api/access-token"
    payload = {
        "refresh_token": REFRESH_TOKEN,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    resp = httpx.post(url, json=payload)
    if resp.status_code != 200:
        print("Error getting access token:", resp.text)
        raise SystemExit(1)
    data = resp.json()
    return data["data"]["access_token"]


def list_inbox(limit: int = 10):
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    # Use searchKey to target inbox. [web:4]
    params = {"searchKey": "in:inbox", "limit": limit}
    resp = httpx.get(url, headers=headers, params=params)
    if resp.status_code != 200:
        print("Error listing inbox:", resp.text)
        return

    data = resp.json()
    messages = data.get("data", [])
    if not messages:
        print("\nInbox is empty or no messages matched.\n")
        return

    print(f"\nLast {len(messages)} messages in INBOX:\n")
    for i, msg in enumerate(messages, start=1):
        subject = msg.get("subject") or "(No subject)"
        sender = msg.get("fromAddress") or msg.get("sender") or "Unknown"
        print(f"{i}. From: {sender}")
        print(f"   Subject: {subject}\n")


def send_email():
    to_addr = input("To: ").strip()
    subject = input("Subject: ").strip()
    print("Message (end with a blank line):")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    body = "\n".join(lines) or "(no content)"

    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    # Mail360 send payload. [web:4]
    payload = {
        "fromAddress": FROM_ADDRESS,
        "toAddress": to_addr,
        "subject": subject,
        "content": body,
        "mailFormat": "plaintext",
    }

    resp = httpx.post(url, headers=headers, json=payload)
    if resp.status_code in (200, 201, 202):
        print("\n✅ Email sent successfully.\n")
    else:
        print("\n❌ Error sending email:")
        print(resp.text, "\n")


def main():
    print("=== Mail360 Command-Line Client ===")
    print(f"Account: {FROM_ADDRESS}")
    while True:
        print("\nMenu:")
        print("  1) List last 10 inbox emails")
        print("  2) Send an email")
        print("  q) Quit")
        choice = input("Choose an option: ").strip().lower()

        if choice == "1":
            list_inbox()
        elif choice == "2":
            send_email()
        elif choice == "q":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
