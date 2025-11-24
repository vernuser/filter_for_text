from ui.auth_db import AuthDatabase

def main():
    print('start')
    db = AuthDatabase(db_path='data/auth_test_direct.db')
    print('validate:', db.validate_user('admin','admin123'))
    db.log_login_attempt('admin', True)
    print('logged')

if __name__ == '__main__':
    main()
