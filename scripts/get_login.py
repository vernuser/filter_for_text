import requests

def main():
    BASE = 'http://127.0.0.1:8000'
    r = requests.get(f'{BASE}/login')
    print('GET /login:', r.status_code)
    print(r.text[:200])

if __name__ == '__main__':
    main()
