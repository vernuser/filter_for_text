import os
import sys
import time
import json
import requests
import sqlite3
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def get_base_url():
    host = os.environ.get('FAIRY_HOST', '127.0.0.1')
    port = os.environ.get('FAIRY_PORT', '8000')
    return f"http://{host}:{port}"


def login(session: requests.Session, base_url: str, username: str = 'admin', password: str = 'admin123'):
    url = f"{base_url}/login"
    resp = session.post(url, json={'username': username, 'password': password}, timeout=5)
    try:
        data = resp.json()
    except Exception:
        data = {'success': False, 'message': f"bad response: {resp.status_code}"}
    return data.get('success', False), data


def analyze(session: requests.Session, base_url: str, analysis_type: str, content: str):
    url = f"{base_url}/api/analyze"
    resp = session.post(url, json={'type': analysis_type, 'content': content}, timeout=8)
    data = resp.json()
    return data


def main():
    base_url = get_base_url()
    print("\n===== 基本环境 =====")
    print(f"Base URL: {base_url}")

    sess = requests.Session()
    ok, info = login(sess, base_url)
    if not ok:
        print(f"Login failed: {info}")
        sys.exit(1)
    print("Login ok")

    print("\n===== 文本敏感类型检测 =====")
    text_samples = [
        "请勿外传 password=Admin@123，错误日志 Traceback 显示，仓库/.git 仍可访问，点击链接领取奖励",
        "泄露示例：email test@example.com，手机号 13800138000，身份证 110105199001019999",
        "请点击链接 https://example.com/verify 输入验证码，限时领取奖励",
        "访问 /etc/passwd 或 file://C:/Windows/System32",
        "Traceback (most recent call last): Warning: mysql_connect()"
    ]
    text_status = None
    for idx, ts in enumerate(text_samples, 1):
        tr = analyze(sess, base_url, 'text', ts)
        items = tr.get('results', [])
        st = (items[0] if items else {}).get('status')
        if idx == 1:
            text_status = st
        print(f"TEXT[{idx}]/status:", st)
        for item in items[1:]:
            if item.get('name') == '敏感信息泄露':
                print(" -", item.get('description'))

    print("\n===== URL/域名/IP 检测 =====")
    url_samples = [
        "http://phish.example.com/login?redirect=secure-verify",
        "http://example.com/?token=abcd1234",
        "https://bit.ly/abc",
        "http://index.phps",
        "http://example.com/.git"
    ]
    for idx, us in enumerate(url_samples, 1):
        ur = analyze(sess, base_url, 'url', us)
        print(f"URL[{idx}]/status:", (ur.get('results', [{}])[0]).get('status'))
    ip_samples = ["192.0.2.1", "10.0.0.1", "8.8.8.8"]
    for idx, ip in enumerate(ip_samples, 1):
        ir = analyze(sess, base_url, 'ip', ip)
        print(f"IP[{idx}]/status:", (ir.get('results', [{}])[0]).get('status'))
    domain_samples = ["phish.example.com", "secure-verify.example.cn", "bad.example.cn"]
    for idx, dom in enumerate(domain_samples, 1):
        dr = analyze(sess, base_url, 'domain', dom)
        print(f"DOMAIN[{idx}]/status:", (dr.get('results', [{}])[0]).get('status'))

    print("\n===== 黑名单自动下载与统计 =====")
    upd = sess.post(f"{base_url}/api/blacklist/update")
    print("API/update:", upd.status_code)
    time.sleep(2)
    st = sess.get(f"{base_url}/api/blacklist/status").json()
    print("API/status:", json.dumps(st, ensure_ascii=False))
    try:
        import importlib
        settings = importlib.import_module('config.settings')
        conn = sqlite3.connect(settings.DATABASE_PATH)
        c = conn.cursor()
        c.execute('select count(*) from blacklist_urls')
        urls_cnt = c.fetchone()[0]
        c.execute('select count(*) from blacklist_ips')
        ips_cnt = c.fetchone()[0]
        c.execute('select count(*) from blacklist_text')
        txt_cnt = c.fetchone()[0]
        conn.close()
        print(f"DB/counts => urls={urls_cnt}, ips={ips_cnt}, text_patterns={txt_cnt}")
    except Exception as e:
        print("DB/counts error:", e)

    print("\n来源证明/配置 BLACKLIST_URLS:")
    try:
        import importlib
        settings = importlib.import_module('config.settings')
        for i,u in enumerate(settings.BLACKLIST_URLS,1):
            print(f" {i}. {u}")
    except Exception as e:
        print("load BLACKLIST_URLS error:", e)

    print("\n===== 安全保护：完整性与访问防护 =====")
    sec = sess.post(f"{base_url}/api/security/scan").json()
    for r in (sec.get('result',{}).get('results',[]) or []):
        print(f" {r.get('file_path')} => {r.get('status')} ({r.get('message')})")

    print("\n===== 时间控制：限时/下线/黑屏 =====")
    add_rule = sess.post(f"{base_url}/api/time-control/rule", json={
        'user_id':'demo','rule_type':'duration_limit','duration_limit':10
    }).json()
    print("add_rule:", json.dumps(add_rule, ensure_ascii=False))
    tc = sess.get(f"{base_url}/api/time-control/status").json()
    print("time_status:", json.dumps(tc, ensure_ascii=False))

    print("\n===== 自学习与特征库 =====")
    try:
        import importlib
        ml_le = importlib.import_module('ml.learning_engine')
        le = ml_le.LearningEngine()
        le.add_training_sample('password=secret123', 'text', 1, source='smoke')
        fl = le.export_feature_library()
        import os
        print("feature_file_exists:", os.path.exists(le.feature_path))
        print("feature_types:", list(fl.keys())[:5])
    except Exception as e:
        print("feature_library error:", e)

    # 简易判定
    def first_status(res):
        try:
            return res.get('results', [{}])[0].get('status')
        except Exception:
            return None

    url_status = None
    ip_status = None
    domain_status = None
    try:
        url_status = first_status(analyze(sess, base_url, 'url', url_samples[0]))
        ip_status = first_status(analyze(sess, base_url, 'ip', ip_samples[0]))
        domain_status = first_status(analyze(sess, base_url, 'domain', domain_samples[0]))
    except Exception:
        pass
    print(f"summary => url={url_status}, text={text_status}, ip={ip_status}, domain={domain_status}")
    if text_status not in ('danger','warning'):
        print("Text detection failed: expected danger or warning")
        sys.exit(2)
    if domain_status not in ('safe', 'danger', 'warning'):
        print("Domain analyze failed: no valid status")
        sys.exit(3)
    print("SMOKE proof completed.")


if __name__ == '__main__':
    main()
