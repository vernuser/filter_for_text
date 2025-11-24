"""
用户认证数据库模块
"""
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class AuthDatabase:
    def __init__(self, db_path='data/auth.db'):
        self.db_path = db_path
        self.init_database()
    
    def _get_connection(self):
        """获取SQLite连接，增加超时并设置busy_timeout/WAL以减少锁表"""
        # 允许通过环境变量调整超时，避免请求阻塞过久
        timeout_sec = float(os.environ.get('FAIRY_DB_TIMEOUT_SEC', '3'))
        busy_ms = int(os.environ.get('FAIRY_DB_BUSY_MS', '3000'))
        conn = sqlite3.connect(self.db_path, timeout=timeout_sec)
        try:
            conn.execute(f'PRAGMA busy_timeout = {busy_ms}')
            conn.execute('PRAGMA journal_mode=WAL')
        except Exception:
            pass
        return conn
    
    def init_database(self):
        """初始化数据库"""
        # 确保数据目录存在
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        # 启用WAL模式以缓解并发写入锁
        try:
            cursor.execute('PRAGMA journal_mode=WAL;')
        except Exception:
            pass
        
        # 创建用户表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                is_locked BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # 创建登录日志表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT,
                success BOOLEAN NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            )
        ''')
        
        conn.commit()
        
        # 创建默认管理员账户
        self.create_default_users(cursor)
        
        conn.close()
    
    def create_default_users(self, cursor):
        """创建默认用户"""
        default_users = [
            ('admin', 'admin123', 'admin'),
            ('user', 'user123', 'user')
        ]
        
        for username, password, role in default_users:
            try:
                password_hash = generate_password_hash(password)
                cursor.execute('''
                    INSERT OR IGNORE INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                ''', (username, password_hash, role))
            except sqlite3.IntegrityError:
                pass  # 用户已存在
        
        cursor.connection.commit()
    
    def validate_user(self, username, password):
        """验证用户登录"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT password_hash, is_locked, login_attempts 
            FROM users WHERE username = ?
        ''', (username,))
        
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return False, "用户不存在"
        
        password_hash, is_locked, login_attempts = result
        
        if is_locked:
            conn.close()
            return False, "账户已被锁定"
        
        if login_attempts >= 10:
            # 锁定账户
            cursor.execute('''
                UPDATE users SET is_locked = TRUE WHERE username = ?
            ''', (username,))
            conn.commit()
            conn.close()
            return False, "登录尝试次数过多，账户已锁定"
        
        if check_password_hash(password_hash, password):
            # 登录成功，重置尝试次数
            cursor.execute('''
                UPDATE users SET 
                    login_attempts = 0,
                    last_login = CURRENT_TIMESTAMP
                WHERE username = ?
            ''', (username,))
            conn.commit()
            conn.close()
            return True, "登录成功"
        else:
            # 登录失败，增加尝试次数
            cursor.execute('''
                UPDATE users SET login_attempts = login_attempts + 1
                WHERE username = ?
            ''', (username,))
            conn.commit()
            conn.close()
            return False, f"密码错误，剩余尝试次数: {9 - login_attempts}"
    
    def log_login_attempt(self, username, success, ip_address=None, user_agent=None):
        """记录登录尝试"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO login_logs (username, ip_address, success, user_agent)
            VALUES (?, ?, ?, ?)
        ''', (username, ip_address, success, user_agent))
        
        conn.commit()
        conn.close()
    
    def get_user_info(self, username):
        """获取用户信息"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT username, role, created_at, last_login, login_attempts
            FROM users WHERE username = ?
        ''', (username,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'username': result[0],
                'role': result[1],
                'created_at': result[2],
                'last_login': result[3],
                'login_attempts': result[4]
            }
        return None

    def create_user(self, username: str, password: str, role: str = 'user'):
        """创建用户账号（用户名唯一）"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # 检查是否存在
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
        exists = cursor.fetchone()[0] > 0
        if exists:
            conn.close()
            return False

        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        ''', (username, password_hash, role))

        conn.commit()
        conn.close()
        return True
