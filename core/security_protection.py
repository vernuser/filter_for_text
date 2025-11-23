#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全防护模块
提供系统安全监控、威胁检测、文件完整性检查等功能
"""

import os
import sys
import time
import hashlib
import threading
import logging
import psutil
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

class SecurityProtection:
    """安全防护类"""
    
    def __init__(self, db_path: str = "data/security.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.monitor_thread = None
        
        # 安全配置
        self.config = {
            'scan_interval': 300,  # 扫描间隔（秒）
            'threat_threshold': 5,  # 威胁阈值
            'file_integrity_check': True,
            'real_time_protection': True,
            'quarantine_enabled': True
        }
        
        # 威胁数据库
        self.threats = {}
        self.quarantine_dir = "data/quarantine"
        
        # 文件完整性监控
        self.monitored_files = {}
        self.file_hashes = {}
        
        # 初始化
        self.initialize_database()
        self.load_threat_signatures()
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        self.logger.info("安全防护模块初始化完成")
    
    def initialize_database(self):
        """初始化安全数据库"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 创建威胁检测表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source TEXT NOT NULL,
                        description TEXT,
                        status TEXT DEFAULT 'active',
                        resolved_at TEXT
                    )
                ''')
                
                # 创建文件完整性表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_integrity (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL UNIQUE,
                        file_hash TEXT NOT NULL,
                        last_check TEXT NOT NULL,
                        status TEXT DEFAULT 'normal'
                    )
                ''')
                
                # 创建安全事件表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source TEXT NOT NULL,
                        details TEXT,
                        action_taken TEXT
                    )
                ''')
                
                # 创建隔离文件表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quarantine (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_path TEXT NOT NULL,
                        quarantine_path TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        quarantine_time TEXT NOT NULL,
                        file_hash TEXT NOT NULL
                    )
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"初始化安全数据库失败: {e}")
            raise
    
    def load_threat_signatures(self):
        """加载威胁特征库"""
        try:
            # 恶意文件哈希
            self.threats['file_hashes'] = {
                # 示例恶意文件哈希
                'd41d8cd98f00b204e9800998ecf8427e': 'empty_file',
                # 可以从威胁情报源加载更多哈希
            }
            
            # 恶意进程名
            self.threats['processes'] = [
                'malware.exe',
                'trojan.exe',
                'virus.exe',
                'keylogger.exe'
            ]
            
            # 可疑网络连接
            self.threats['network'] = [
                '192.168.1.100',  # 示例恶意IP
                'malicious-domain.com'
            ]
            
            # 文件扩展名黑名单
            self.threats['extensions'] = [
                '.scr', '.pif', '.bat', '.cmd', '.com',
                '.exe', '.vbs', '.js', '.jar'
            ]
            
            self.logger.info("威胁特征库加载完成")
            
        except Exception as e:
            self.logger.error(f"加载威胁特征库失败: {e}")
    
    def start_monitoring(self):
        """启动安全监控"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("安全监控已启动")
    
    def stop_monitoring(self):
        """停止安全监控"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("安全监控已停止")
    
    def _monitor_loop(self):
        """监控循环"""
        while self.monitoring:
            try:
                # 进程监控
                self.check_malicious_processes()
                
                # 网络连接监控
                self.check_network_connections()
                
                # 文件完整性检查
                if self.config['file_integrity_check']:
                    self.check_file_integrity()
                
                # 系统资源监控
                self.check_system_resources()
                
                time.sleep(self.config['scan_interval'])
                
            except Exception as e:
                self.logger.error(f"安全监控循环错误: {e}")
                time.sleep(60)  # 错误时等待1分钟
    
    def check_malicious_processes(self):
        """检查恶意进程"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    
                    # 检查进程名是否在黑名单中
                    if proc_name in self.threats['processes']:
                        self.handle_threat(
                            threat_type='malicious_process',
                            severity='high',
                            source=f"Process: {proc_name} (PID: {proc_info['pid']})",
                            description=f"检测到恶意进程: {proc_name}"
                        )
                        
                        # 尝试终止恶意进程
                        try:
                            proc.terminate()
                            self.logger.warning(f"已终止恶意进程: {proc_name}")
                        except Exception as e:
                            self.logger.error(f"终止进程失败: {e}")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"进程检查失败: {e}")
    
    def check_network_connections(self):
        """检查网络连接"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    
                    # 检查是否连接到恶意IP
                    if remote_ip in self.threats['network']:
                        self.handle_threat(
                            threat_type='malicious_connection',
                            severity='medium',
                            source=f"Network: {remote_ip}:{conn.raddr.port}",
                            description=f"检测到连接恶意IP: {remote_ip}"
                        )
                        
        except Exception as e:
            self.logger.error(f"网络连接检查失败: {e}")
    
    def check_file_integrity(self):
        """检查文件完整性"""
        try:
            for file_path in self.monitored_files:
                if os.path.exists(file_path):
                    current_hash = self.calculate_file_hash(file_path)
                    stored_hash = self.file_hashes.get(file_path)
                    
                    if stored_hash and current_hash != stored_hash:
                        self.handle_threat(
                            threat_type='file_integrity_violation',
                            severity='medium',
                            source=f"File: {file_path}",
                            description=f"文件完整性被破坏: {file_path}"
                        )
                    
                    # 更新哈希值
                    self.file_hashes[file_path] = current_hash
                    self.update_file_integrity_db(file_path, current_hash)
                    
        except Exception as e:
            self.logger.error(f"文件完整性检查失败: {e}")
    
    def check_system_resources(self):
        """检查系统资源"""
        try:
            # CPU使用率检查
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                self.handle_threat(
                    threat_type='high_cpu_usage',
                    severity='low',
                    source='System',
                    description=f"CPU使用率过高: {cpu_percent}%"
                )
            
            # 内存使用率检查
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                self.handle_threat(
                    threat_type='high_memory_usage',
                    severity='low',
                    source='System',
                    description=f"内存使用率过高: {memory.percent}%"
                )
            
            # 磁盘使用率检查
            disk = psutil.disk_usage('/')
            if disk.percent > 95:
                self.handle_threat(
                    threat_type='high_disk_usage',
                    severity='medium',
                    source='System',
                    description=f"磁盘使用率过高: {disk.percent}%"
                )
                
        except Exception as e:
            self.logger.error(f"系统资源检查失败: {e}")
    
    def scan_file(self, file_path: str) -> Dict:
        """扫描单个文件"""
        result = {
            'file_path': file_path,
            'is_threat': False,
            'threat_type': None,
            'severity': 'low',
            'details': []
        }
        
        try:
            if not os.path.exists(file_path):
                result['details'].append('文件不存在')
                return result
            
            # 计算文件哈希
            file_hash = self.calculate_file_hash(file_path)
            
            # 检查恶意文件哈希
            if file_hash in self.threats['file_hashes']:
                result['is_threat'] = True
                result['threat_type'] = 'malicious_hash'
                result['severity'] = 'high'
                result['details'].append(f'恶意文件哈希匹配: {file_hash}')
            
            # 检查文件扩展名
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in self.threats['extensions']:
                result['is_threat'] = True
                result['threat_type'] = 'suspicious_extension'
                result['severity'] = 'medium'
                result['details'].append(f'可疑文件扩展名: {file_ext}')
            
            # 检查文件大小（异常大小可能是威胁）
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                result['details'].append('空文件')
            elif file_size > 100 * 1024 * 1024:  # 100MB
                result['details'].append('文件过大')
            
            return result
            
        except Exception as e:
            result['details'].append(f'扫描错误: {str(e)}')
            return result
    
    def scan_directory(self, directory: str) -> List[Dict]:
        """扫描目录"""
        results = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path)
                    results.append(result)
                    
                    # 如果发现威胁，记录并处理
                    if result['is_threat']:
                        self.handle_threat(
                            threat_type=result['threat_type'],
                            severity=result['severity'],
                            source=file_path,
                            description='; '.join(result['details'])
                        )
            
            return results
            
        except Exception as e:
            self.logger.error(f"目录扫描失败: {e}")
            return results
    
    def quarantine_file(self, file_path: str, threat_type: str) -> bool:
        """隔离文件"""
        try:
            if not os.path.exists(file_path):
                return False
            
            # 生成隔离文件名
            file_hash = self.calculate_file_hash(file_path)
            quarantine_name = f"{file_hash}_{int(time.time())}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # 移动文件到隔离区
            os.rename(file_path, quarantine_path)
            
            # 记录隔离信息
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO quarantine 
                    (original_path, quarantine_path, threat_type, quarantine_time, file_hash)
                    VALUES (?, ?, ?, ?, ?)
                ''', (file_path, quarantine_path, threat_type, 
                      datetime.now().isoformat(), file_hash))
                conn.commit()
            
            self.logger.info(f"文件已隔离: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"文件隔离失败: {e}")
            return False
    
    def restore_file(self, quarantine_id: int) -> bool:
        """恢复隔离文件"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT original_path, quarantine_path 
                    FROM quarantine WHERE id = ?
                ''', (quarantine_id,))
                
                result = cursor.fetchone()
                if not result:
                    return False
                
                original_path, quarantine_path = result
                
                # 恢复文件
                if os.path.exists(quarantine_path):
                    os.makedirs(os.path.dirname(original_path), exist_ok=True)
                    os.rename(quarantine_path, original_path)
                    
                    # 删除隔离记录
                    cursor.execute('DELETE FROM quarantine WHERE id = ?', (quarantine_id,))
                    conn.commit()
                    
                    self.logger.info(f"文件已恢复: {quarantine_path} -> {original_path}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"文件恢复失败: {e}")
            return False
    
    def handle_threat(self, threat_type: str, severity: str, source: str, description: str):
        """处理威胁"""
        try:
            # 记录威胁
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO threats (timestamp, threat_type, severity, source, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (datetime.now().isoformat(), threat_type, severity, source, description))
                conn.commit()
            
            # 记录安全事件
            self.log_security_event(threat_type, severity, source, description, 'detected')
            
            # 根据威胁类型采取行动
            if threat_type == 'malicious_hash' and severity == 'high':
                if self.config['quarantine_enabled']:
                    self.quarantine_file(source, threat_type)
            
            self.logger.warning(f"威胁检测: {threat_type} - {description}")
            
        except Exception as e:
            self.logger.error(f"威胁处理失败: {e}")
    
    def log_security_event(self, event_type: str, severity: str, source: str, 
                          details: str, action_taken: str):
        """记录安全事件"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO security_events 
                    (timestamp, event_type, severity, source, details, action_taken)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (datetime.now().isoformat(), event_type, severity, 
                      source, details, action_taken))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"安全事件记录失败: {e}")
    
    def calculate_file_hash(self, file_path: str) -> str:
        """计算文件哈希"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.logger.error(f"计算文件哈希失败: {e}")
            return ""
    
    def add_monitored_file(self, file_path: str):
        """添加监控文件"""
        if os.path.exists(file_path):
            self.monitored_files[file_path] = True
            file_hash = self.calculate_file_hash(file_path)
            self.file_hashes[file_path] = file_hash
            self.update_file_integrity_db(file_path, file_hash)
            self.logger.info(f"添加文件监控: {file_path}")
    
    def remove_monitored_file(self, file_path: str):
        """移除监控文件"""
        if file_path in self.monitored_files:
            del self.monitored_files[file_path]
            if file_path in self.file_hashes:
                del self.file_hashes[file_path]
            self.logger.info(f"移除文件监控: {file_path}")
    
    def update_file_integrity_db(self, file_path: str, file_hash: str):
        """更新文件完整性数据库"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO file_integrity 
                    (file_path, file_hash, last_check)
                    VALUES (?, ?, ?)
                ''', (file_path, file_hash, datetime.now().isoformat()))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"更新文件完整性数据库失败: {e}")
    
    def get_threats(self, limit: int = 100) -> List[Dict]:
        """获取威胁列表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM threats 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                columns = [description[0] for description in cursor.description]
                threats = []
                
                for row in cursor.fetchall():
                    threat = dict(zip(columns, row))
                    threats.append(threat)
                
                return threats
                
        except Exception as e:
            self.logger.error(f"获取威胁列表失败: {e}")
            return []
    
    def get_security_events(self, limit: int = 100) -> List[Dict]:
        """获取安全事件列表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM security_events 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                columns = [description[0] for description in cursor.description]
                events = []
                
                for row in cursor.fetchall():
                    event = dict(zip(columns, row))
                    events.append(event)
                
                return events
                
        except Exception as e:
            self.logger.error(f"获取安全事件列表失败: {e}")
            return []
    
    def get_quarantine_files(self) -> List[Dict]:
        """获取隔离文件列表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM quarantine 
                    ORDER BY quarantine_time DESC
                ''')
                
                columns = [description[0] for description in cursor.description]
                files = []
                
                for row in cursor.fetchall():
                    file_info = dict(zip(columns, row))
                    files.append(file_info)
                
                return files
                
        except Exception as e:
            self.logger.error(f"获取隔离文件列表失败: {e}")
            return []
    
    def get_status(self) -> Dict:
        """获取安全防护状态"""
        try:
            # 获取威胁统计
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # 今日威胁数量
                today = datetime.now().date().isoformat()
                cursor.execute('''
                    SELECT COUNT(*) FROM threats 
                    WHERE date(timestamp) = ?
                ''', (today,))
                today_threats = cursor.fetchone()[0]
                
                # 总威胁数量
                cursor.execute('SELECT COUNT(*) FROM threats')
                total_threats = cursor.fetchone()[0]
                
                # 隔离文件数量
                cursor.execute('SELECT COUNT(*) FROM quarantine')
                quarantine_count = cursor.fetchone()[0]
            
            # 系统资源状态
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'monitoring': self.monitoring,
                'threats': {
                    'today': today_threats,
                    'total': total_threats
                },
                'quarantine_files': quarantine_count,
                'system_resources': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'disk_percent': disk.percent
                },
                'monitored_files': len(self.monitored_files)
            }
            
        except Exception as e:
            self.logger.error(f"获取状态失败: {e}")
            return {
                'monitoring': self.monitoring,
                'threats': {'today': 0, 'total': 0},
                'quarantine_files': 0,
                'system_resources': {'cpu_percent': 0, 'memory_percent': 0, 'disk_percent': 0},
                'monitored_files': 0
            }
    
    def stop(self):
        """停止安全防护"""
        self.stop_monitoring()
        self.logger.info("安全防护模块已停止")