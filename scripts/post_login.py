import requests

def main():
    BASE = 'http://127.0.0.1:8000'
    r = requests.post(f'{BASE}/login', data={'username':'admin','password':'admin123'})
    print('STATUS:', r.status_code)
    print(r.text[:2000])

if __name__ == '__main__':
    main()
