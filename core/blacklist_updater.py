"""
黑名单自动下载和更新模块
"""
import requests
import re
import logging
import sqlite3
import schedule
import time
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from urllib.parse import urlparse
from config.settings import BLACKLIST_URLS, DATABASE_PATH, FILTER_CONFIG

class BlacklistUpdater:
    """黑名单自动更新器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_path = DATABASE_PATH
        self.update_interval = FILTER_CONFIG.get('auto_update_interval', 24)
        self.running = False
        self.update_thread = None
        
        # 设置定时更新
        schedule.every(self.update_interval).hours.do(self.update_all_blacklists)
    
    def start_auto_update(self):
        """启动自动更新服务"""
        if not self.running:
            self.running = True
            self.update_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.update_thread.start()
            self.logger.info("黑名单自动更新服务已启动")
    
    def stop_auto_update(self):
        """停止自动更新服务"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        self.logger.info("黑名单自动更新服务已停止")
    
    def _run_scheduler(self):
        """运行调度器"""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # 每分钟检查一次
    
    def update_all_blacklists(self):
        """更新所有黑名单"""
        self.logger.info("开始更新黑名单...")
        
        success_count = 0
        total_count = len(BLACKLIST_URLS)
        
        for url in BLACKLIST_URLS:
            try:
                if self.update_blacklist_from_url(url):
                    success_count += 1
            except Exception as e:
                self.logger.error(f"更新黑名单失败 {url}: {e}")
        
        self.logger.info(f"黑名单更新完成: {success_count}/{total_count} 成功")
        self._log_update_result(success_count, total_count)
    
    def update_blacklist_from_url(self, url: str) -> bool:
        """从指定URL更新黑名单"""
        try:
            self.logger.info(f"正在从 {url} 下载黑名单...")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # 根据URL类型解析内容
            if 'hosts' in url.lower():
                return self._parse_hosts_file(content, url)
            elif 'adservers' in url.lower() or 'filter' in url.lower():
                return self._parse_filter_list(content, url)
            else:
                return self._parse_generic_list(content, url)
                
        except requests.RequestException as e:
            self.logger.error(f"下载黑名单失败 {url}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"解析黑名单失败 {url}: {e}")
            return False
    
    def _parse_hosts_file(self, content: str, source_url: str) -> bool:
        """解析hosts文件格式的黑名单"""
        added_count = 0
        
        for line in content.split('\n'):
            line = line.strip()
            
            # 跳过注释和空行
            if not line or line.startswith('#'):
                continue
            
            # 解析hosts格式: IP domain
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                domain = parts[1]
                
                # 跳过本地地址
                if ip in ['127.0.0.1', '0.0.0.0'] and domain not in ['localhost']:
                    if self._add_domain_to_blacklist(domain, 'malware', 2, source_url):
                        added_count += 1
        
        self.logger.info(f"从hosts文件添加了 {added_count} 个域名")
        return added_count > 0
    
    def _parse_filter_list(self, content: str, source_url: str) -> bool:
        """解析过滤器列表格式的黑名单"""
        added_count = 0
        
        for line in content.split('\n'):
            line = line.strip()
            
            # 跳过注释和空行
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            
            # 解析AdBlock格式
            if line.startswith('||') and line.endswith('^'):
                domain = line[2:-1]
                if self._is_valid_domain(domain):
                    if self._add_domain_to_blacklist(domain, 'ads', 1, source_url):
                        added_count += 1
            
            # 解析简单域名格式
            elif self._is_valid_domain(line):
                if self._add_domain_to_blacklist(line, 'suspicious', 1, source_url):
                    added_count += 1
        
        self.logger.info(f"从过滤器列表添加了 {added_count} 个域名")
        return added_count > 0
    
    def _parse_generic_list(self, content: str, source_url: str) -> bool:
        """解析通用列表格式的黑名单"""
        added_count = 0
        
        for line in content.split('\n'):
            line = line.strip()
            
            # 跳过注释和空行
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # 尝试提取域名或IP
            if self._is_valid_domain(line):
                if self._add_domain_to_blacklist(line, 'generic', 1, source_url):
                    added_count += 1
            elif self._is_valid_ip(line):
                if self._add_ip_to_blacklist(line, 'generic', 1, source_url):
                    added_count += 1
            elif self._is_hash(line):
                if self._add_text_pattern_to_blacklist(line, 'hash', 1):
                    added_count += 1
        
        self.logger.info(f"从通用列表添加了 {added_count} 个条目")
        return added_count > 0
    
    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名格式"""
        if not domain or len(domain) > 255:
            return False
        
        # 基本域名格式检查
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        return bool(domain_pattern.match(domain))
    
    def _is_valid_ip(self, ip: str) -> bool:
        """验证IP地址格式"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_hash(self, s: str) -> bool:
        try:
            import re
            if re.fullmatch(r'[a-fA-F0-9]{32}', s):
                return True
            if re.fullmatch(r'[a-fA-F0-9]{40}', s):
                return True
            if re.fullmatch(r'[a-fA-F0-9]{64}', s):
                return True
            return False
        except Exception:
            return False
    
    def _add_domain_to_blacklist(self, domain: str, category: str, severity: int, source: str) -> bool:
        """添加域名到黑名单"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO blacklist_urls (url, domain, category, severity)
                VALUES (?, ?, ?, ?)
            ''', (domain, domain, category, severity))
            
            # 检查是否实际插入了新记录
            inserted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return inserted
            
        except Exception as e:
            self.logger.error(f"添加域名到黑名单失败 {domain}: {e}")
            return False
    
    def _add_ip_to_blacklist(self, ip: str, category: str, severity: int, source: str) -> bool:
        """添加IP到黑名单"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO blacklist_ips (ip_address, category, severity)
                VALUES (?, ?, ?)
            ''', (ip, category, severity))
            
            # 检查是否实际插入了新记录
            inserted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return inserted
            
        except Exception as e:
            self.logger.error(f"添加IP到黑名单失败 {ip}: {e}")
            return False
    
    def _log_update_result(self, success_count: int, total_count: int):
        """记录更新结果"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 创建更新日志表（如果不存在）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS update_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success_count INTEGER,
                    total_count INTEGER,
                    success_rate REAL
                )
            ''')
            
            success_rate = success_count / total_count if total_count > 0 else 0
            
            cursor.execute('''
                INSERT INTO update_logs (success_count, total_count, success_rate)
                VALUES (?, ?, ?)
            ''', (success_count, total_count, success_rate))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"记录更新日志失败: {e}")
    
    def get_update_status(self) -> Dict:
        """获取更新状态"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 获取最近的更新记录
            cursor.execute('''
                SELECT update_time, success_count, total_count, success_rate
                FROM update_logs
                ORDER BY update_time DESC
                LIMIT 1
            ''')
            
            last_update = cursor.fetchone()
            
            # 获取黑名单统计
            cursor.execute('SELECT COUNT(*) FROM blacklist_urls')
            url_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM blacklist_ips')
            ip_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM blacklist_text')
            text_count = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'last_update': last_update[0] if last_update else None,
                'last_success_rate': last_update[3] if last_update else 0,
                'auto_update_enabled': self.running,
                'update_interval_hours': self.update_interval,
                'blacklist_counts': {
                    'urls': url_count,
                    'ips': ip_count,
                    'text_patterns': text_count
                }
            }
            
        except Exception as e:
            self.logger.error(f"获取更新状态失败: {e}")
            return {}
    
    def manual_update(self) -> Dict:
        """手动触发更新"""
        self.logger.info("手动触发黑名单更新")
        
        start_time = datetime.now()
        self.update_all_blacklists()
        end_time = datetime.now()
        
        duration = (end_time - start_time).total_seconds()
        
        return {
            'status': 'completed',
            'duration_seconds': duration,
            'timestamp': end_time.isoformat()
        }
    
    def add_custom_blacklist_source(self, url: str, name: str = None) -> bool:
        """添加自定义黑名单源"""
        try:
            # 验证URL
            response = requests.head(url, timeout=10)
            response.raise_for_status()
            
            # 这里可以将自定义源保存到配置文件或数据库
            # 暂时添加到运行时列表
            if url not in BLACKLIST_URLS:
                BLACKLIST_URLS.append(url)
                self.logger.info(f"添加自定义黑名单源: {url}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"添加自定义黑名单源失败: {e}")
            return False

    def _add_text_pattern_to_blacklist(self, pattern: str, category: str, severity: int) -> bool:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO blacklist_text (pattern, category, severity)
                VALUES (?, ?, ?)
            ''', (pattern, category, severity))
            inserted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            return inserted
        except Exception as e:
            self.logger.error(f"添加文本特征到黑名单失败 {pattern}: {e}")
            return False
