import os
import sys
import json
import time
import requests

# Ensure PYTHONPATH includes project root if run directly
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.append(ROOT)

from ui.auth_db import AuthDatabase


def add_user(db_path: str, username: str, password: str) -> bool:
    auth = AuthDatabase(db_path=db_path)
    created = auth.create_user(username, password, role='user')
    return created


def call_analyze(session: requests.Session, endpoint: str, analysis_type: str, content: str, timeout: int = 15):
    url = endpoint.rstrip('/') + '/api/analyze'
    payload = {"type": analysis_type, "content": content}
    resp = session.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def main():
    endpoint = os.environ.get('FAIRY_ENDPOINT', 'http://127.0.0.1:8000')
    db_path = os.environ.get('FAIRY_AUTH_DB', os.path.join('data', 'auth.db'))

    print(f"Using AUTH DB: {db_path}")
    print(f"Analyzing via: {endpoint}")

    # 1) Add danger user
    created = add_user(db_path, 'danger', 'danger')
    print(json.dumps({"user_created": created}, ensure_ascii=False))

    # 2) Login with danger user to obtain session
    sess = requests.Session()
    login_url = endpoint.rstrip('/') + '/login'
    login_payload = {"username": "danger", "password": "danger"}
    login_resp = sess.post(login_url, json=login_payload, timeout=15)
    login_ok = False
    try:
        login_json = login_resp.json()
        login_ok = bool(login_json.get('success'))
    except Exception:
        login_ok = False
    print(json.dumps({"login_success": login_ok}, ensure_ascii=False))

    # 3) Prepare dangerous samples
    samples = {
        "url": "`http://198.51.100.23:8080/free-download.exe?update=1&ref=bit.ly`",
        "text": "【重要】您的银行账户已被冻结！请立即点击链接 `http://bit.ly/secure-verify` 输入验证码并下载安全更新工具，限时免费，否则账户将永久停用。",
        "ip": "45.77.123.11"
    }

    results = {}
    for t, c in samples.items():
        try:
            result = call_analyze(sess, endpoint, t, c, timeout=15)
            results[t] = result
        except Exception as e:
            results[t] = {"error": str(e)}
        time.sleep(0.2)

    print(json.dumps({"samples": samples, "results": results}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
