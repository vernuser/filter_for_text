"""
用户认证数据库模块
"""
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from core.database import db_manager

class AuthDatabase:
    def __init__(self):
        self.init_database()
    
    def init_database(self):
        """初始化数据库"""
        try:
            db_manager.init_mysql_tables()
            
            # 创建默认管理员账户
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                self.create_default_users(cursor)
                conn.commit()
                
        except Exception as e:
            print(f"初始化认证数据库失败: {e}")
    
    def create_default_users(self, cursor):
        """创建默认用户"""
        default_users = [
            ('admin', 'admin123', 'admin'),
            ('user', 'user123', 'user')
        ]
        
        for username, password, role in default_users:
            try:
                # 检查是否存在
                cursor.execute('SELECT COUNT(*) FROM web_users WHERE username = %s', (username,))
                if cursor.fetchone()[0] > 0:
                    continue
                
                password_hash = generate_password_hash(password)
                cursor.execute('''
                    INSERT INTO web_users (username, password_hash, role)
                    VALUES (%s, %s, %s)
                ''', (username, password_hash, role))
            except Exception as e:
                print(f"创建默认用户失败: {e}")
    
    def validate_user(self, username, password):
        """验证用户登录"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT password_hash, is_locked, login_attempts 
                    FROM web_users WHERE username = %s
                ''', (username,))
                
                result = cursor.fetchone()
                
                if not result:
                    return False, "用户不存在"
                
                password_hash, is_locked, login_attempts = result
                
                if is_locked:
                    return False, "账户已被锁定"
                
                if login_attempts >= 10:
                    # 锁定账户
                    cursor.execute('''
                        UPDATE web_users SET is_locked = TRUE WHERE username = %s
                    ''', (username,))
                    conn.commit()
                    return False, "登录尝试次数过多，账户已锁定"
                
                if check_password_hash(password_hash, password):
                    # 登录成功，重置尝试次数
                    cursor.execute('''
                        UPDATE web_users SET 
                            login_attempts = 0,
                            last_login = CURRENT_TIMESTAMP
                        WHERE username = %s
                    ''', (username,))
                    conn.commit()
                    return True, "登录成功"
                else:
                    # 登录失败，增加尝试次数
                    cursor.execute('''
                        UPDATE web_users SET login_attempts = login_attempts + 1
                        WHERE username = %s
                    ''', (username,))
                    conn.commit()
                    return False, f"密码错误，剩余尝试次数: {9 - login_attempts}"
                    
        except Exception as e:
            print(f"验证用户失败: {e}")
            return False, "系统错误"
    
    def log_login_attempt(self, username, success, ip_address=None, user_agent=None):
        """记录登录尝试"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO login_logs (username, ip_address, success, user_agent)
                    VALUES (%s, %s, %s, %s)
                ''', (username, ip_address, int(success), user_agent))
                
                conn.commit()
        except Exception as e:
            print(f"记录登录日志失败: {e}")
    
    def get_user_info(self, username):
        """获取用户信息"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT username, role, created_at, last_login, login_attempts
                    FROM web_users WHERE username = %s
                ''', (username,))
                
                result = cursor.fetchone()
                
                if result:
                    return {
                        'username': result[0],
                        'role': result[1],
                        'created_at': result[2],
                        'last_login': result[3],
                        'login_attempts': result[4]
                    }
            return None
        except Exception as e:
            print(f"获取用户信息失败: {e}")
            return None

    def create_user(self, username: str, password: str, role: str = 'user'):
        """创建用户账号（用户名唯一）"""
        try:
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()

                # 检查是否存在
                cursor.execute('SELECT COUNT(*) FROM web_users WHERE username = %s', (username,))
                exists = cursor.fetchone()[0] > 0
                if exists:
                    return False

                password_hash = generate_password_hash(password)
                cursor.execute('''
                    INSERT INTO web_users (username, password_hash, role)
                    VALUES (%s, %s, %s)
                ''', (username, password_hash, role))

                conn.commit()
                return True
        except Exception as e:
            print(f"创建用户失败: {e}")
            return False
