"""
安全保护模块 - 防篡改、访问控制、完整性检查
"""
import os
import hashlib
import hmac
import json
import time
import sqlite3
import logging
import threading
import psutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config.settings import DATABASE_PATH

class SecurityProtection:
    """安全保护管理器"""
    
    def __init__(self, master_password: str = None):
        self.logger = logging.getLogger(__name__)
        self.db_path = DATABASE_PATH
        self.master_password = master_password or "default_security_key"
        self.encryption_key = self._derive_key(self.master_password)
        self.cipher_suite = Fernet(self.encryption_key)
        
        # 文件完整性监控
        self.integrity_monitor = None
        self.monitoring_active = False
        
        # 访问控制
        self.access_control = AccessControl()
        
        # 进程保护
        self.process_protection = ProcessProtection()
        
        self._init_security_database()
        self._setup_critical_files()
    
    def _derive_key(self, password: str) -> bytes:
        """从密码派生加密密钥"""
        password_bytes = password.encode()
        salt = b'security_filter_salt'  # 在生产环境中应使用随机盐
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def _init_security_database(self):
        """初始化安全数据库"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 文件完整性表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_integrity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                file_hash TEXT NOT NULL,
                last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_critical BOOLEAN DEFAULT FALSE,
                status TEXT DEFAULT 'valid'
            )
        ''')
        
        # 访问日志表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                result TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        # 安全事件表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity INTEGER DEFAULT 1,
                description TEXT,
                source TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                handled BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # 用户会话表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _setup_critical_files(self):
        """设置关键文件列表"""
        critical_files = [
            'config/settings.py',
            'core/filter_engine.py',
            'security/protection.py',
            'main.py'
        ]
        
        base_path = Path(__file__).parent.parent
        for file_path in critical_files:
            full_path = base_path / file_path
            if full_path.exists():
                self.add_file_to_integrity_check(str(full_path), is_critical=True)
    
    def add_file_to_integrity_check(self, file_path: str, is_critical: bool = False):
        """添加文件到完整性检查列表"""
        try:
            if not os.path.exists(file_path):
                self.logger.warning(f"文件不存在，无法添加到完整性检查: {file_path}")
                return False
            
            file_hash = self._calculate_file_hash(file_path)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO file_integrity (file_path, file_hash, is_critical)
                VALUES (?, ?, ?)
            ''', (file_path, file_hash, is_critical))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"文件已添加到完整性检查: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"添加文件到完整性检查失败: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """计算文件哈希值"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"计算文件哈希失败: {e}")
            return ""
    
    def check_file_integrity(self, file_path: str = None) -> Dict:
        """检查文件完整性"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if file_path:
                cursor.execute('SELECT * FROM file_integrity WHERE file_path = ?', (file_path,))
                files = cursor.fetchall()
            else:
                cursor.execute('SELECT * FROM file_integrity')
                files = cursor.fetchall()
            
            results = []
            
            for file_record in files:
                file_id, path, stored_hash, last_check, is_critical, status = file_record
                
                if not os.path.exists(path):
                    result = {
                        'file_path': path,
                        'status': 'missing',
                        'is_critical': bool(is_critical),
                        'message': '文件不存在'
                    }
                    self._log_security_event('file_missing', 3 if is_critical else 1, 
                                           f'关键文件丢失: {path}' if is_critical else f'文件丢失: {path}')
                else:
                    current_hash = self._calculate_file_hash(path)
                    
                    if current_hash == stored_hash:
                        result = {
                            'file_path': path,
                            'status': 'valid',
                            'is_critical': bool(is_critical),
                            'message': '文件完整性正常'
                        }
                        # 更新检查时间
                        cursor.execute('UPDATE file_integrity SET last_check = CURRENT_TIMESTAMP WHERE id = ?', (file_id,))
                    else:
                        result = {
                            'file_path': path,
                            'status': 'modified',
                            'is_critical': bool(is_critical),
                            'message': '文件已被修改',
                            'stored_hash': stored_hash,
                            'current_hash': current_hash
                        }
                        self._log_security_event('file_tampered', 4 if is_critical else 2,
                                               f'文件被篡改: {path}')
                
                results.append(result)
            
            conn.commit()
            conn.close()
            
            return {'status': 'success', 'results': results}
            
        except Exception as e:
            self.logger.error(f"检查文件完整性失败: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def start_integrity_monitoring(self, check_interval: int = 300):
        """启动文件完整性监控"""
        try:
            if self.monitoring_active:
                self.logger.warning("完整性监控已在运行")
                return
            
            self.monitoring_active = True
            
            # 启动定期检查线程
            def periodic_check():
                while self.monitoring_active:
                    self.logger.info("执行定期完整性检查")
                    result = self.check_file_integrity()
                    
                    # 检查是否有严重问题
                    if result.get('status') == 'success':
                        for file_result in result.get('results', []):
                            if file_result['status'] in ['missing', 'modified'] and file_result['is_critical']:
                                self._handle_critical_file_issue(file_result)
                    
                    time.sleep(check_interval)
            
            monitoring_thread = threading.Thread(target=periodic_check, daemon=True)
            monitoring_thread.start()
            
            self.logger.info(f"文件完整性监控已启动，检查间隔: {check_interval}秒")
            
        except Exception as e:
            self.logger.error(f"启动完整性监控失败: {e}")
    
    def stop_integrity_monitoring(self):
        """停止文件完整性监控"""
        self.monitoring_active = False
        self.logger.info("文件完整性监控已停止")
    
    def _handle_critical_file_issue(self, file_result: Dict):
        """处理关键文件问题"""
        file_path = file_result['file_path']
        status = file_result['status']
        
        self.logger.critical(f"关键文件问题: {file_path} - {status}")
        
        # 可以在这里添加更多处理逻辑，如：
        # 1. 发送警报
        # 2. 尝试从备份恢复
        # 3. 阻止系统运行
        # 4. 通知管理员
        
        if status == 'missing':
            self._log_security_event('critical_file_missing', 5, f'关键文件丢失: {file_path}')
        elif status == 'modified':
            self._log_security_event('critical_file_tampered', 5, f'关键文件被篡改: {file_path}')
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """加密敏感数据"""
        try:
            encrypted_data = self.cipher_suite.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            self.logger.error(f"数据加密失败: {e}")
            return ""
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """解密敏感数据"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            self.logger.error(f"数据解密失败: {e}")
            return ""
    
    def _log_security_event(self, event_type: str, severity: int, description: str, source: str = None):
        """记录安全事件"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_events (event_type, severity, description, source)
                VALUES (?, ?, ?, ?)
            ''', (event_type, severity, description, source or 'system'))
            
            conn.commit()
            conn.close()
            
            # 根据严重程度记录日志
            if severity >= 4:
                self.logger.critical(f"安全事件: {event_type} - {description}")
            elif severity >= 3:
                self.logger.error(f"安全事件: {event_type} - {description}")
            elif severity >= 2:
                self.logger.warning(f"安全事件: {event_type} - {description}")
            else:
                self.logger.info(f"安全事件: {event_type} - {description}")
                
        except Exception as e:
            self.logger.error(f"记录安全事件失败: {e}")
    
    def get_security_status(self) -> Dict:
        """获取安全状态"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 获取最近的安全事件
            cursor.execute('''
                SELECT event_type, severity, COUNT(*) 
                FROM security_events 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY event_type, severity
                ORDER BY severity DESC
            ''')
            recent_events = cursor.fetchall()
            
            # 获取文件完整性状态
            cursor.execute('''
                SELECT status, COUNT(*) 
                FROM file_integrity 
                GROUP BY status
            ''')
            integrity_status = dict(cursor.fetchall())
            
            # 获取活跃会话数
            cursor.execute('''
                SELECT COUNT(*) 
                FROM user_sessions 
                WHERE status = 'active' AND last_activity > datetime('now', '-1 hour')
            ''')
            active_sessions = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'monitoring_active': self.monitoring_active,
                'recent_events': recent_events,
                'file_integrity': integrity_status,
                'active_sessions': active_sessions,
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"获取安全状态失败: {e}")
            return {'status': 'error', 'message': str(e)}


class AccessControl:
    """访问控制管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_path = DATABASE_PATH
        self.active_sessions = {}
        self.failed_attempts = {}
        self.max_failed_attempts = 5
        self.lockout_duration = 300  # 5分钟
    
    def authenticate_user(self, user_id: str, password: str, ip_address: str = None) -> Dict:
        """用户认证"""
        try:
            # 检查是否被锁定
            if self._is_user_locked(user_id, ip_address):
                return {
                    'success': False,
                    'message': '账户已被锁定，请稍后再试',
                    'locked': True
                }
            
            # 这里应该实现真正的密码验证逻辑
            # 为演示目的，使用简单的验证
            if self._verify_password(user_id, password):
                session_id = self._create_session(user_id, ip_address)
                self._clear_failed_attempts(user_id, ip_address)
                
                self._log_access('login_success', user_id, ip_address, 'successful_login')
                
                return {
                    'success': True,
                    'session_id': session_id,
                    'message': '登录成功'
                }
            else:
                self._record_failed_attempt(user_id, ip_address)
                self._log_access('login_failed', user_id, ip_address, 'invalid_credentials')
                
                return {
                    'success': False,
                    'message': '用户名或密码错误'
                }
                
        except Exception as e:
            self.logger.error(f"用户认证失败: {e}")
            return {'success': False, 'message': '认证过程出错'}
    
    def _verify_password(self, user_id: str, password: str) -> bool:
        """验证密码（简化实现）"""
        # 在实际应用中，应该从数据库中获取哈希密码进行验证
        default_users = {
            'admin': 'admin123',
            'user': 'user123'
        }
        return default_users.get(user_id) == password
    
    def _is_user_locked(self, user_id: str, ip_address: str) -> bool:
        """检查用户是否被锁定"""
        key = f"{user_id}:{ip_address}"
        if key in self.failed_attempts:
            attempts, last_attempt = self.failed_attempts[key]
            if attempts >= self.max_failed_attempts:
                if time.time() - last_attempt < self.lockout_duration:
                    return True
                else:
                    # 锁定时间已过，清除记录
                    del self.failed_attempts[key]
        return False
    
    def _record_failed_attempt(self, user_id: str, ip_address: str):
        """记录失败尝试"""
        key = f"{user_id}:{ip_address}"
        current_time = time.time()
        
        if key in self.failed_attempts:
            attempts, _ = self.failed_attempts[key]
            self.failed_attempts[key] = (attempts + 1, current_time)
        else:
            self.failed_attempts[key] = (1, current_time)
    
    def _clear_failed_attempts(self, user_id: str, ip_address: str):
        """清除失败尝试记录"""
        key = f"{user_id}:{ip_address}"
        if key in self.failed_attempts:
            del self.failed_attempts[key]
    
    def _create_session(self, user_id: str, ip_address: str) -> str:
        """创建用户会话"""
        import uuid
        session_id = str(uuid.uuid4())
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO user_sessions (session_id, user_id, ip_address)
                VALUES (?, ?, ?)
            ''', (session_id, user_id, ip_address))
            
            conn.commit()
            conn.close()
            
            self.active_sessions[session_id] = {
                'user_id': user_id,
                'ip_address': ip_address,
                'login_time': time.time(),
                'last_activity': time.time()
            }
            
            return session_id
            
        except Exception as e:
            self.logger.error(f"创建会话失败: {e}")
            return ""
    
    def validate_session(self, session_id: str) -> Dict:
        """验证会话"""
        try:
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                
                # 检查会话是否过期（1小时）
                if time.time() - session['last_activity'] > 3600:
                    self._invalidate_session(session_id)
                    return {'valid': False, 'message': '会话已过期'}
                
                # 更新最后活动时间
                session['last_activity'] = time.time()
                self._update_session_activity(session_id)
                
                return {
                    'valid': True,
                    'user_id': session['user_id'],
                    'ip_address': session['ip_address']
                }
            else:
                return {'valid': False, 'message': '无效会话'}
                
        except Exception as e:
            self.logger.error(f"验证会话失败: {e}")
            return {'valid': False, 'message': '会话验证出错'}
    
    def _update_session_activity(self, session_id: str):
        """更新会话活动时间"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE user_sessions 
                SET last_activity = CURRENT_TIMESTAMP 
                WHERE session_id = ?
            ''', (session_id,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"更新会话活动时间失败: {e}")
    
    def _invalidate_session(self, session_id: str):
        """使会话无效"""
        try:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE user_sessions 
                SET status = 'expired' 
                WHERE session_id = ?
            ''', (session_id,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"使会话无效失败: {e}")
    
    def _log_access(self, action: str, user_id: str, ip_address: str, result: str, details: str = None):
        """记录访问日志"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO access_logs (user_id, action, result, ip_address, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, action, result, ip_address, details))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"记录访问日志失败: {e}")


class ProcessProtection:
    """进程保护管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.protected_processes = set()
        self.monitoring_active = False
        self.monitor_thread = None
    
    def add_protected_process(self, process_name: str):
        """添加受保护的进程"""
        self.protected_processes.add(process_name)
        self.logger.info(f"进程已添加到保护列表: {process_name}")
    
    def start_process_monitoring(self):
        """启动进程监控"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        self.monitor_thread.start()
        self.logger.info("进程监控已启动")
    
    def stop_process_monitoring(self):
        """停止进程监控"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("进程监控已停止")
    
    def _monitor_processes(self):
        """监控进程"""
        while self.monitoring_active:
            try:
                current_processes = {p.name() for p in psutil.process_iter(['name'])}
                
                for protected_process in self.protected_processes:
                    if protected_process not in current_processes:
                        self.logger.warning(f"受保护的进程已停止: {protected_process}")
                        # 可以在这里添加重启逻辑
                
                time.sleep(10)  # 每10秒检查一次
                
            except Exception as e:
                self.logger.error(f"进程监控错误: {e}")
                time.sleep(30)
    
    def get_system_info(self) -> Dict:
        """获取系统信息"""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'process_count': len(psutil.pids()),
                'boot_time': psutil.boot_time()
            }
        except Exception as e:
            self.logger.error(f"获取系统信息失败: {e}")
            return {}