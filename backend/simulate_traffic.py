
import random
import time
import requests

BACKEND = "http://127.0.0.1:8000"

PATHS = ["/", "/login", "/search", "/api/users", "/admin", "/download"]
METHODS = ["GET", "POST"]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert('xss')",
]
SQLI_PAYLOADS = [
    "1' OR 1=1 --",
    "' UNION SELECT username, password FROM users --",
    "admin' OR '1'='1",
]
RCE_PAYLOADS = [
    "__import__('os').system('whoami')",
    "system('rm -rf /')",
]
TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32",
]
CLEAN_PAYLOADS = [
    "page=1",
    "q=neo+secure",
    "id=42",
]

def random_event():
    kind = random.choices(
        ["CLEAN", "XSS", "SQLi", "RCE", "Traversal"],
        weights=[50, 20, 15, 5, 10],
    )[0]

    if kind == "XSS":
        payload = random.choice(XSS_PAYLOADS)
    elif kind == "SQLi":
        payload = random.choice(SQLI_PAYLOADS)
    elif kind == "RCE":
        payload = random.choice(RCE_PAYLOADS)
    elif kind == "Traversal":
        payload = random.choice(TRAVERSAL_PAYLOADS)
    else:
        payload = random.choice(CLEAN_PAYLOADS)

    return {
        "path": random.choice(PATHS),
        "method": random.choice(METHODS),
        "payload": payload,
        "source": f"10.0.0.{random.randint(1, 200)}",
    }

if __name__ == "__main__":
    print("Starting NeoSecure traffic simulator… Ctrl+C to stop.")
    while True:
        evt = random_event()
        try:
            r = requests.post(f"{BACKEND}/ingest", json=evt, timeout=3)
            print("Sent", evt["method"], evt["path"], "status", r.status_code)
        except Exception as e:
            print("Error:", e)
        time.sleep(1.0)
