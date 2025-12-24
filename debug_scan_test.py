import asyncio
import sys
import os

# Mock settings
os.environ["OPENAI_API_KEY"] = "sk-mock"

# Add current dir to path
sys.path.append(os.getcwd())

from mcp_server import scan_dependencies, scan_dependency_manifest

content = """Django==3.2.5
requests==2.25.1
urllib3==1.26.5
Pillow==8.3.2
Werkzeug==2.0.0
"""

filename = "test_vuln.txt"
with open(filename, "w") as f:
    f.write(content)

async def main():
    print("--- 1. Testing OSV Scan (scan_dependencies) ---")
    osv_result = scan_dependencies(content, ecosystem="PyPI")
    print(osv_result[:1000])
    
    print("\n--- 2. Testing Trivy Scan (scan_dependency_manifest) ---")
    try:
        trivy_result = scan_dependency_manifest(os.path.abspath(filename))
        print(trivy_result[:1000])
    except Exception as e:
        print(f"Trivy Failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
