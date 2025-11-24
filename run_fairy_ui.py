import os
import sys
import threading
import time
import requests


def main():
    # 确保可以导入ui包
    base_dir = os.path.abspath(os.path.dirname(__file__))
    # 确保项目根与ui均可导入
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)
    ui_dir = os.path.join(base_dir, 'ui')
    if ui_dir not in sys.path:
        sys.path.insert(0, ui_dir)

    from ui.fairy_web import FairyWebInterface

    app = FairyWebInterface()
    host = os.environ.get('FAIRY_HOST', '127.0.0.1')
    try:
        port = int(os.environ.get('FAIRY_PORT', '8000'))
    except ValueError:
        port = 8000
    debug = os.environ.get('FAIRY_DEBUG', '').lower() in ('1', 'true', 'yes')

    run_smoke = os.environ.get('FAIRY_RUN_SMOKE', '').lower() in ('1', 'true', 'yes')
    if not run_smoke:
        app.run(host=host, port=port, debug=debug)
        return

    def _run_server():
        app.run(host=host, port=port, debug=debug)

    t = threading.Thread(target=_run_server, daemon=True)
    t.start()

    base = f"http://{host}:{port}"
    for _ in range(30):
        try:
            r = requests.get(base + "/api/status", timeout=1)
            if r.ok:
                break
        except Exception:
            time.sleep(0.5)

    samples = [
        { 'type': 'text', 'content': '您的银行账户已被冻结，请访问 secure-verify.io 或 bit.ly/abc123 验证' },
        { 'type': 'url',  'content': 'http://phishing-site.net/login' },
        { 'type': 'ip',   'content': '192.168.1.100' },
        { 'type': 'domain', 'content': 'phishing-site.net' },
    ]
    print("=== Fairy Smoke Tests ===")
    for s in samples:
        try:
            resp = requests.post(base + "/api/analyze", json=s, timeout=5)
            print(f"[{s['type']}] -> status={resp.status_code}")
            print(resp.text[:400])
        except Exception as e:
            print(f"[{s['type']}] error: {e}")
    print("=== Visit /smoke for interactive test ===")
    print(base + "/smoke")
    t.join()


if __name__ == '__main__':
    main()
