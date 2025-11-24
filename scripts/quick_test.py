import os
import requests


def run_tests(base_url: str = "http://127.0.0.1:8000"):
    session = requests.Session()

    print("[1] GET /login")
    r = session.get(f"{base_url}/login", timeout=5)
    print("status:", r.status_code)

    print("[2] POST /login")
    r = session.post(
        f"{base_url}/login",
        json={"username": "admin", "password": "admin123"},
        timeout=15,
    )
    print("status:", r.status_code)
    print("body:", r.text[:200])
    if r.status_code != 200 or "success" not in r.text:
        print("登录失败，退出测试")
        return

    print("[3] POST /api/analyze (url)")
    r = session.post(
        f"{base_url}/api/analyze",
        json={"type": "url", "content": "http://test.example.com/login.php?id=123&token=x"},
        timeout=15,
    )
    print("status:", r.status_code)
    print("json:", r.json())

    print("[4] POST /api/analyze (ip)")
    r = session.post(
        f"{base_url}/api/analyze",
        json={"type": "ip", "content": "8.8.8.8"},
        timeout=15,
    )
    print("status:", r.status_code)
    print("json:", r.json())

    print("[5] POST /api/analyze (text)")
    r = session.post(
        f"{base_url}/api/analyze",
        json={"type": "text", "content": "这是一段用于测试的文本，其中包含可疑词钓鱼和攻击"},
        timeout=15,
    )
    print("status:", r.status_code)
    print("json:", r.json())


if __name__ == "__main__":
    # 可选：启用离线登录以避免锁表影响测试
    if not os.environ.get("FAIRY_OFFLINE_LOGIN"):
        os.environ["FAIRY_OFFLINE_LOGIN"] = "1"
    run_tests()
