import requests
import sys

BASE_URL = "http://localhost:8000"

def verify():
    # 1. Login
    print("Logging in as analyst...")
    try:
        resp = requests.post(f"{BASE_URL}/api/auth/login", data={"username": "analyst", "password": "analyst123"})
        if resp.status_code != 200:
            print("Failed to login. Ensure 'analyst' user exists. Try registering first via UI if needed.")
            # Try register if login failed
            requests.post(f"{BASE_URL}/api/auth/register", json={
                "email": "analyst@example.com", 
                "username": "analyst", 
                "password": "analyst123",
                "full_name": "Analyst User"
            })
            resp = requests.post(f"{BASE_URL}/api/auth/login", data={"username": "analyst", "password": "analyst123"})
            if resp.status_code != 200:
                print("FATAL: Could not login/register.")
                sys.exit(1)
                
        token = resp.json()["access_token"]
        print("Logged in. Token acquired.")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Loop requests
        print("Sending 55 requests (Limit is 50/60m)...")
        success_count = 0
        blocked_count = 0
        
        for i in range(1, 56):
            r = requests.post(f"{BASE_URL}/api/scans/", json={"content": "test", "source": "API"}, headers=headers)
            if r.status_code == 201:
                success_count += 1
                print(f"Req {i}: 201 Created")
            elif r.status_code == 429:
                blocked_count += 1
                print(f"Req {i}: 429 Too Many Requests (Blocked)")
            else:
                print(f"Req {i}: Unexpected status {r.status_code} - {r.text}")
                
        print(f"\nResult: {success_count} Successes, {blocked_count} Blocked")
        
        if success_count == 50 and blocked_count >= 1:
            print("VERIFICATION SUCCESS: Rate limit enforced correctly.")
            sys.exit(0)
        else:
            print("VERIFICATION FAILED: Did not match expected 50 success / 5+ blocked.")
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
