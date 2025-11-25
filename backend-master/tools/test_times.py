import requests, json, sys

base = "http://127.0.0.1:8000"
username = "hello"
password = "123456"

try:
    login = requests.post(base + "/api/v1/auth/login", json={"username": username, "password": password}, timeout=10)
except Exception as e:
    print("LOGIN_REQUEST_FAILED:", e)
    sys.exit(2)

print("LOGIN_STATUS:", login.status_code)
try:
    lj = login.json()
    print(json.dumps(lj, ensure_ascii=False, indent=2))
except Exception:
    print(login.text)

if not (200 <= login.status_code < 300):
    sys.exit(1)

data = lj.get('data') if isinstance(lj, dict) else None
token = None
if isinstance(data, dict):
    token = data.get('accessToken') or data.get('access_token')

seafile_cached_val = None
if isinstance(data, dict):
    seafile_cached_val = data.get('seafileCached') or data.get('seafileCachedDetail')
print("seafileCached:", seafile_cached_val)

if not token:
    print("NO_ACCESS_TOKEN_RETURNED")
    sys.exit(1)

headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

try:
    t = requests.get(base + "/api/v1/crawler/category/12/times", headers=headers, timeout=10)
except Exception as e:
    print("TIMES_REQUEST_FAILED:", e)
    sys.exit(2)

print("TIMES_STATUS:", t.status_code)
try:
    print(json.dumps(t.json(), ensure_ascii=False, indent=2))
except Exception:
    print(t.text)
