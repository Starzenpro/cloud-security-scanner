import requests
import time

API_URL = "http://localhost:8000"

def test_health():
    try:
        r = requests.get(f"{API_URL}/health")
        print(f"Health check: {r.json()}")
        return True
    except:
        print("API not running")
        return False

def test_aws_scan():
    payload = {"region": "us-east-1"}
    r = requests.post(f"{API_URL}/scan/aws", json=payload)
    if r.status_code == 200:
        print(f"AWS scan completed: {r.json()['total_findings']} findings")
    else:
        print(f"AWS scan failed: {r.text}")

def test_azure_scan():
    payload = {"subscription_id": "test-sub"}
    r = requests.post(f"{API_URL}/scan/azure", json=payload)
    if r.status_code == 200:
        print(f"Azure scan completed: {r.json()['total_findings']} findings")
    else:
        print(f"Azure scan failed: {r.text}")

if __name__ == "__main__":
    if test_health():
        test_aws_scan()
        test_azure_scan()
