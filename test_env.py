@echo
from dotenv import load_dotenv
import os

load_dotenv()  # looks for .env in current folder

print("CLIENT_ID:", os.getenv("CLIENT_ID"))
print("REFRESH_TOKEN:", os.getenv("REFRESH_TOKEN")[:10] + "..." if os.getenv("REFRESH_TOKEN") else "MISSING")

input("\nPress Enter to exit...")