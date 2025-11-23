#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
访问控制模块
提供用户认证、权限管理、会话管理等功能
"""

import os
import hashlib
import sqlite3
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from functools import wraps

class AccessControl:
    """访问控制类"""
    
    def __init__(self, db_path: str = "data/access_control.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # 会话管理
        self.active_sessions = {}
        self.session_timeout = 3600  # 1小时
        
        # 权限定义
        self.permissions = {
            'admin': [
                'system.manage', 'user.manage', 'filter.manage',
                'security.manage', 'ml.manage', 'config.manage',
                'log.view', 'report.generate'
            ],
            'operator': [
                'filter.view', 'filter.toggle', 'security.view',
                'ml.view', 'log.view'
            ],
            'viewer': [
                'dashboard.view', 'log.view'
            ]
        }
        
        # 初始化
        self.initialize_database()
        self.create_default_admin()
        
        self.logger.info("访问控制模块初始化完成")
    
    def initialize_database(self):
        """初始化访问控制数据库"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 创建用户表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'viewer',
                        email TEXT,
                        full_name TEXT,
                        created_at TEXT NOT NULL,
                        last_login TEXT,
                        is_active INTEGER DEFAULT 1,
                        failed_attempts INTEGER DEFAULT 0,
                        locked_until TEXT
                    )
                ''')
                
                # 创建会话表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL UNIQUE,
                        user_id INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        last_activity TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        is_active INTEGER DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # 创建访问日志表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS access_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        user_id INTEGER,
                        username TEXT,
                        action TEXT NOT NULL,
                        resource TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        success INTEGER NOT NULL,
                        details TEXT
                    )
                ''')
                
                # 创建权限表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_permissions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        permission TEXT NOT NULL,
                        granted_by INTEGER,
                        granted_at TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users (id),
                        FOREIGN KEY (granted_by) REFERENCES users (id)
                    )
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"初始化访问控制数据库失败: {e}")
            raise
    
    def create_default_admin(self):
        """创建默认管理员账户"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 检查是否已存在管理员
                cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
                admin_count = cursor.fetchone()[0]
                
                if admin_count == 0:
                    # 创建默认管理员
                    salt = secrets.token_hex(16)
                    password_hash = self.hash_password('admin123', salt)
                    
                    cursor.execute('''
                        INSERT INTO users 
                        (username, password_hash, salt, role, full_name, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', ('admin', password_hash, salt, 'admin', 
                          '系统管理员', datetime.now().isoformat()))
                    
                    conn.commit()
                    self.logger.info("默认管理员账户已创建 (用户名: admin, 密码: admin123)")
                    
        except Exception as e:
            self.logger.error(f"创建默认管理员失败: {e}")
    
    def hash_password(self, password: str, salt: str) -> str:
        """密码哈希"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    
    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """验证密码"""
        return self.hash_password(password, salt) == password_hash
    
    def authenticate(self, username: str, password: str, ip_address: str = None, 
                    user_agent: str = None) -> Optional[Dict]:
        """用户认证"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 获取用户信息
                cursor.execute('''
                    SELECT id, username, password_hash, salt, role, is_active, 
                           failed_attempts, locked_until
                    FROM users WHERE username = ?
                ''', (username,))
                
                user_data = cursor.fetchone()
                
                if not user_data:
                    self.log_access('login', username, ip_address, user_agent, False, '用户不存在')
                    return None
                
                user_id, username, password_hash, salt, role, is_active, failed_attempts, locked_until = user_data
                
                # 检查账户是否被锁定
                if locked_until:
                    lock_time = datetime.fromisoformat(locked_until)
                    if datetime.now() < lock_time:
                        self.log_access('login', username, ip_address, user_agent, False, '账户被锁定')
                        return None
                    else:
                        # 解锁账户
                        cursor.execute('''
                            UPDATE users SET failed_attempts = 0, locked_until = NULL 
                            WHERE id = ?
                        ''', (user_id,))
                        conn.commit()
                
                # 检查账户是否激活
                if not is_active:
                    self.log_access('login', username, ip_address, user_agent, False, '账户未激活')
                    return None
                
                # 验证密码
                if self.verify_password(password, password_hash, salt):
                    # 登录成功，重置失败次数
                    cursor.execute('''
                        UPDATE users SET failed_attempts = 0, last_login = ? 
                        WHERE id = ?
                    ''', (datetime.now().isoformat(), user_id))
                    
                    # 创建会话
                    session_id = self.create_session(user_id, ip_address, user_agent)
                    
                    conn.commit()
                    
                    user_info = {
                        'id': user_id,
                        'username': username,
                        'role': role,
                        'session_id': session_id,
                        'permissions': self.get_user_permissions(user_id)
                    }
                    
                    self.log_access('login', username, ip_address, user_agent, True, '登录成功')
                    self.logger.info(f"用户登录成功: {username}")
                    
                    return user_info
                else:
                    # 登录失败，增加失败次数
                    failed_attempts += 1
                    
                    # 检查是否需要锁定账户
                    if failed_attempts >= 5:
                        lock_until = datetime.now() + timedelta(minutes=30)
                        cursor.execute('''
                            UPDATE users SET failed_attempts = ?, locked_until = ? 
                            WHERE id = ?
                        ''', (failed_attempts, lock_until.isoformat(), user_id))
                        self.log_access('login', username, ip_address, user_agent, False, '密码错误，账户已锁定')
                    else:
                        cursor.execute('''
                            UPDATE users SET failed_attempts = ? WHERE id = ?
                        ''', (failed_attempts, user_id))
                        self.log_access('login', username, ip_address, user_agent, False, '密码错误')
                    
                    conn.commit()
                    return None
                    
        except Exception as e:
            self.logger.error(f"用户认证失败: {e}")
            return None
    
    def create_session(self, user_id: int, ip_address: str = None, 
                      user_agent: str = None) -> str:
        """创建会话"""
        try:
            session_id = secrets.token_urlsafe(32)
            now = datetime.now().isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO sessions 
                    (session_id, user_id, created_at, last_activity, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (session_id, user_id, now, now, ip_address, user_agent))
                conn.commit()
            
            # 添加到活动会话
            self.active_sessions[session_id] = {
                'user_id': user_id,
                'created_at': now,
                'last_activity': now,
                'ip_address': ip_address
            }
            
            return session_id
            
        except Exception as e:
            self.logger.error(f"创建会话失败: {e}")
            return None
    
    def validate_session(self, session_id: str) -> Optional[Dict]:
        """验证会话"""
        try:
            # 检查活动会话
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                last_activity = datetime.fromisoformat(session['last_activity'])
                
                # 检查会话是否超时
                if datetime.now() - last_activity > timedelta(seconds=self.session_timeout):
                    self.logout(session_id)
                    return None
                
                # 更新最后活动时间
                session['last_activity'] = datetime.now().isoformat()
                self.update_session_activity(session_id)
                
                return session
            
            # 从数据库检查会话
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user_id, created_at, last_activity, ip_address, is_active
                    FROM sessions WHERE session_id = ?
                ''', (session_id,))
                
                session_data = cursor.fetchone()
                
                if session_data and session_data[4]:  # is_active
                    user_id, created_at, last_activity, ip_address, is_active = session_data
                    
                    last_activity_time = datetime.fromisoformat(last_activity)
                    if datetime.now() - last_activity_time > timedelta(seconds=self.session_timeout):
                        self.logout(session_id)
                        return None
                    
                    # 恢复到活动会话
                    session = {
                        'user_id': user_id,
                        'created_at': created_at,
                        'last_activity': datetime.now().isoformat(),
                        'ip_address': ip_address
                    }
                    
                    self.active_sessions[session_id] = session
                    self.update_session_activity(session_id)
                    
                    return session
            
            return None
            
        except Exception as e:
            self.logger.error(f"验证会话失败: {e}")
            return None
    
    def update_session_activity(self, session_id: str):
        """更新会话活动时间"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE sessions SET last_activity = ? 
                    WHERE session_id = ?
                ''', (datetime.now().isoformat(), session_id))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"更新会话活动时间失败: {e}")
    
    def logout(self, session_id: str):
        """用户登出"""
        try:
            # 从活动会话中移除
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            
            # 更新数据库会话状态
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE sessions SET is_active = 0 
                    WHERE session_id = ?
                ''', (session_id,))
                conn.commit()
            
            self.logger.info(f"用户登出: {session_id}")
            
        except Exception as e:
            self.logger.error(f"用户登出失败: {e}")
    
    def get_user_permissions(self, user_id: int) -> List[str]:
        """获取用户权限"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 获取用户角色
                cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
                role_result = cursor.fetchone()
                
                if not role_result:
                    return []
                
                role = role_result[0]
                
                # 获取角色默认权限
                permissions = self.permissions.get(role, []).copy()
                
                # 获取用户特定权限
                cursor.execute('''
                    SELECT permission FROM user_permissions 
                    WHERE user_id = ?
                ''', (user_id,))
                
                for row in cursor.fetchall():
                    permission = row[0]
                    if permission not in permissions:
                        permissions.append(permission)
                
                return permissions
                
        except Exception as e:
            self.logger.error(f"获取用户权限失败: {e}")
            return []
    
    def has_permission(self, user_id: int, permission: str) -> bool:
        """检查用户权限"""
        user_permissions = self.get_user_permissions(user_id)
        return permission in user_permissions
    
    def require_permission(self, permission: str):
        """权限装饰器"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # 这里需要从请求中获取用户信息
                # 实际实现时需要与Web框架集成
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def user_exists(self, username: str) -> bool:
        """检查用户是否存在"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
                return cursor.fetchone()[0] > 0
        except Exception as e:
            self.logger.error(f"检查用户存在性失败: {e}")
            return False
    
    def create_user(self, username: str, password: str, role: str = 'viewer',
                   email: str = None, full_name: str = None) -> bool:
        """创建用户"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 检查用户名是否已存在
                cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
                if cursor.fetchone()[0] > 0:
                    return False
                
                # 创建用户
                salt = secrets.token_hex(16)
                password_hash = self.hash_password(password, salt)
                
                cursor.execute('''
                    INSERT INTO users 
                    (username, password_hash, salt, role, email, full_name, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (username, password_hash, salt, role, email, full_name,
                      datetime.now().isoformat()))
                
                conn.commit()
                self.logger.info(f"用户创建成功: {username}")
                return True
                
        except Exception as e:
            self.logger.error(f"创建用户失败: {e}")
            return False
    
    def update_user(self, user_id: int, **kwargs) -> bool:
        """更新用户信息"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 构建更新语句
                update_fields = []
                values = []
                
                for field, value in kwargs.items():
                    if field in ['username', 'role', 'email', 'full_name', 'is_active']:
                        update_fields.append(f"{field} = ?")
                        values.append(value)
                    elif field == 'password':
                        salt = secrets.token_hex(16)
                        password_hash = self.hash_password(value, salt)
                        update_fields.extend(['password_hash = ?', 'salt = ?'])
                        values.extend([password_hash, salt])
                
                if update_fields:
                    values.append(user_id)
                    cursor.execute(f'''
                        UPDATE users SET {', '.join(update_fields)} 
                        WHERE id = ?
                    ''', values)
                    conn.commit()
                    return True
                
                return False
                
        except Exception as e:
            self.logger.error(f"更新用户失败: {e}")
            return False
    
    def delete_user(self, user_id: int) -> bool:
        """删除用户"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 删除用户会话
                cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
                
                # 删除用户权限
                cursor.execute('DELETE FROM user_permissions WHERE user_id = ?', (user_id,))
                
                # 删除用户
                cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
                
                conn.commit()
                self.logger.info(f"用户删除成功: {user_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"删除用户失败: {e}")
            return False
    
    def get_users(self) -> List[Dict]:
        """获取用户列表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, role, email, full_name, 
                           created_at, last_login, is_active
                    FROM users ORDER BY created_at DESC
                ''')
                
                columns = ['id', 'username', 'role', 'email', 'full_name',
                          'created_at', 'last_login', 'is_active']
                users = []
                
                for row in cursor.fetchall():
                    user = dict(zip(columns, row))
                    users.append(user)
                
                return users
                
        except Exception as e:
            self.logger.error(f"获取用户列表失败: {e}")
            return []
    
    def get_active_sessions(self) -> List[Dict]:
        """获取活动会话列表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT s.session_id, s.user_id, u.username, s.created_at,
                           s.last_activity, s.ip_address, s.user_agent
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.is_active = 1
                    ORDER BY s.last_activity DESC
                ''')
                
                columns = ['session_id', 'user_id', 'username', 'created_at',
                          'last_activity', 'ip_address', 'user_agent']
                sessions = []
                
                for row in cursor.fetchall():
                    session = dict(zip(columns, row))
                    sessions.append(session)
                
                return sessions
                
        except Exception as e:
            self.logger.error(f"获取活动会话失败: {e}")
            return []
    
    def log_access(self, action: str, username: str = None, ip_address: str = None,
                  user_agent: str = None, success: bool = True, details: str = None):
        """记录访问日志"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 获取用户ID
                user_id = None
                if username:
                    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
                    result = cursor.fetchone()
                    if result:
                        user_id = result[0]
                
                cursor.execute('''
                    INSERT INTO access_logs 
                    (timestamp, user_id, username, action, ip_address, 
                     user_agent, success, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (datetime.now().isoformat(), user_id, username, action,
                      ip_address, user_agent, int(success), details))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"记录访问日志失败: {e}")
    
    def get_access_logs(self, limit: int = 100) -> List[Dict]:
        """获取访问日志"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM access_logs 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                columns = [description[0] for description in cursor.description]
                logs = []
                
                for row in cursor.fetchall():
                    log = dict(zip(columns, row))
                    logs.append(log)
                
                return logs
                
        except Exception as e:
            self.logger.error(f"获取访问日志失败: {e}")
            return []
    
    def cleanup_expired_sessions(self):
        """清理过期会话"""
        try:
            cutoff_time = datetime.now() - timedelta(seconds=self.session_timeout)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE sessions SET is_active = 0 
                    WHERE last_activity < ? AND is_active = 1
                ''', (cutoff_time.isoformat(),))
                conn.commit()
            
            # 清理活动会话缓存
            expired_sessions = []
            for session_id, session in self.active_sessions.items():
                last_activity = datetime.fromisoformat(session['last_activity'])
                if last_activity < cutoff_time:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del self.active_sessions[session_id]
            
            if expired_sessions:
                self.logger.info(f"清理了 {len(expired_sessions)} 个过期会话")
                
        except Exception as e:
            self.logger.error(f"清理过期会话失败: {e}")
    
    def get_status(self) -> Dict:
        """获取访问控制状态"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 用户统计
                cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
                active_users = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM users')
                total_users = cursor.fetchone()[0]
                
                # 会话统计
                cursor.execute('SELECT COUNT(*) FROM sessions WHERE is_active = 1')
                active_sessions = cursor.fetchone()[0]
                
                # 今日登录统计
                today = datetime.now().date().isoformat()
                cursor.execute('''
                    SELECT COUNT(*) FROM access_logs 
                    WHERE action = 'login' AND success = 1 AND date(timestamp) = ?
                ''', (today,))
                today_logins = cursor.fetchone()[0]
            
            return {
                'users': {
                    'active': active_users,
                    'total': total_users
                },
                'sessions': {
                    'active': active_sessions,
                    'in_memory': len(self.active_sessions)
                },
                'today_logins': today_logins
            }
            
        except Exception as e:
            self.logger.error(f"获取状态失败: {e}")
            return {
                'users': {'active': 0, 'total': 0},
                'sessions': {'active': 0, 'in_memory': 0},
                'today_logins': 0
            }
    
    def stop(self):
        """停止访问控制"""
        # 清理活动会话
        self.active_sessions.clear()
        self.logger.info("访问控制模块已停止")