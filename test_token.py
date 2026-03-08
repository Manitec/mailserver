from dotenv import load_dotenv
import os
import httpx
import json

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")
BASE_URL = "https://mail360.zoho.com"

print("✅ Loaded credentials OK")

# Get access token
token_url = f"{BASE_URL}/api/access-token"
payload = {
    "refresh_token": REFRESH_TOKEN,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET
}

with httpx.Client() as client:
    resp = client.post(token_url, json=payload)
    print(f"Token status: {resp.status_code}")
    
    if resp.status_code == 200:
        data = resp.json()
        access_token = data["data"]["access_token"]
        print(f"✅ Access token OK")
        
        # List accounts (with debug)
        accounts_url = f"{BASE_URL}/api/accounts"
        headers = {"Authorization": f"Zoho-oauthtoken {access_token}"}
        resp2 = client.get(accounts_url, headers=headers)
        print(f"Accounts status: {resp2.status_code}")
        
        if resp2.status_code == 200:
            accounts_data = resp2.json()
            print("\n=== RAW ACCOUNTS JSON ===")
            print(json.dumps(accounts_data, indent=2)[:1000] + "..." if len(json.dumps(accounts_data)) > 1000 else json.dumps(accounts_data, indent=2))
            
            accounts_list = accounts_data.get("data", [])
            print(f"\n✅ Found {len(accounts_list)} accounts")
            for i, acc in enumerate(accounts_list):
                print(f"\nAccount {i+1}:")
                print(f"  Keys available: {list(acc.keys())}")
                print(f"  Full account data: {json.dumps(acc, indent=2)}")
        else:
            print("❌ Accounts error:", resp2.text)
    else:
        print("❌ Token error:", resp.json())

input("\nPress Enter to exit...")
