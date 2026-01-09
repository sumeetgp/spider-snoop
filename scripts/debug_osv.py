import requests
import json

def debug_osv():
    url = "https://api.osv.dev/v1/query"
    query = {
        "package": {"name": "Django", "ecosystem": "PyPI"},
        "version": "3.2.0"
    }
    
    print("Querying OSV (Single) for Django 3.2.0...")
    response = requests.post(url, json=query)
    
    if response.status_code == 200:
        data = response.json()
        # print(json.dumps(data, indent=2)) # Too big probably
        
        # Check structure
        vulns = data.get("vulns", [])
        print(f"Found {len(vulns)} vulns.")
        
        for vuln in vulns[:3]: # check first 3
             print(f"Checking Vuln: {vuln.get('id')}")
             if "affected" in vuln:
                 print("  Has 'affected' field matches")
                 for affected in vuln.get("affected", []):
                    for range_info in affected.get("ranges", []):
                        print(f"    Range Type: {range_info.get('type')}")
                        for event in range_info.get("events", []):
                            if "fixed" in event:
                                print(f"      -> FOUND FIXED: {event['fixed']}")
             else:
                 print("  NO 'affected' field found.")
    else:
        print(f"Error: {response.status_code} {response.text}")

if __name__ == "__main__":
    debug_osv()
