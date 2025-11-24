import requests
import json

BASE = 'http://127.0.0.1:8000'

def main():
    s = requests.Session()
    r = s.post(f'{BASE}/login', data={'username':'admin','password':'admin123'})
    print('LOGIN:', r.status_code)
    try:
        print('LOGIN JSON:', r.json())
    except Exception:
        print('LOGIN TEXT:', r.text[:200])
    print('COOKIES:', s.cookies.get_dict())
    # 若未登录成功，直接返回
    try:
        resp = r.json()
        if not resp.get('success'):
            print('Login failed, skip analyze.')
            return
    except Exception:
        print('No JSON login response, skip analyze.')
        return
    # 若重定向到首页或返回200都视为成功
    cases = [
        ('url','http://free-prize.click/win?uid=123'),
        ('text','免费领取大奖，点击链接领取奖励'),
        ('ip','8.8.8.8')
    ]
    for t, content in cases:
        r = s.post(f'{BASE}/api/analyze', json={'type': t, 'content': content})
        print('ANALYZE', t, r.status_code)
        try:
            print(json.dumps(r.json(), ensure_ascii=False))
        except Exception:
            print(r.text)

if __name__ == '__main__':
    main()
